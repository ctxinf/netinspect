// Package netns: DNS forwarder (runs inside the namespace in the agent).
package netns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"netinspect/internal/proxy"
	"netinspect/internal/store"
)

// ServeDNS runs a UDP/53 forwarder on listenAddr that logs every query
// (qname/qtype/answer, metadata only) and relays to upstreamAddr (host:port).
func ServeDNS(listenAddr, upstreamAddr string, st *store.Store, emit func(proxy.Event)) error {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("dns listen: %w", err)
	}
	defer pc.Close()
	var wg sync.WaitGroup
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, qname, qtype, answer, ms := forward(pkt, upstreamAddr)
			q := &store.DNSQuery{Source: addr.String(), Dest: upstreamAddr, QName: qname, QType: qtype, Answer: answer, Ms: ms}
			st.AddDNS(q)
			if emit != nil && q.ID != 0 {
				qc := *q
				emit(proxy.Event{Type: "dns", DNS: &qc})
			}
			if resp != nil {
				pc.WriteTo(resp, addr)
			}
		}()
	}
}

// forward relays one DNS query to upstreamAddr (host:port) over UDP (TCP
// fallback with SO_MARK on truncation) and extracts metadata.
func forward(query []byte, upstreamAddr string) (resp []byte, qname, qtype, answer string, ms float64) {
	t0 := time.Now()
	defer func() { ms = time.Since(t0).Seconds() * 1000 }()
	qname, qtype = parseQuery(query)

	uc, err := net.DialTimeout("udp", upstreamAddr, 5*time.Second)
	if err != nil {
		return nil, qname, qtype, "", ms
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Write(query); err != nil {
		return nil, qname, qtype, "", ms
	}
	buf := make([]byte, 4096)
	n, err := uc.Read(buf)
	if err != nil {
		return nil, qname, qtype, "", ms
	}
	resp = buf[:n]
	if truncated(resp) {
		if tcpResp := forwardTCP(query, upstreamAddr); tcpResp != nil {
			resp = tcpResp
		}
	}
	answer = extractAnswer(resp)
	return resp, qname, qtype, answer, ms
}

// forwardTCP retries a truncated query over TCP with SO_MARK=0x1 so the
// namespace's REDIRECT rule skips it.
func forwardTCP(query []byte, upstreamAddr string) []byte {
	d := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 1)
			})
			return err
		},
	}
	c, err := d.Dial("tcp", upstreamAddr)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	lb := []byte{byte(len(query) >> 8), byte(len(query))}
	if _, err := c.Write(append(lb, query...)); err != nil {
		return nil
	}
	hdr := make([]byte, 2)
	if _, err := readFull(c, hdr); err != nil {
		return nil
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n <= 0 || n > 65535 {
		return nil
	}
	out := make([]byte, n)
	if _, err := readFull(c, out); err != nil {
		return nil
	}
	return out
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func truncated(resp []byte) bool {
	return len(resp) >= 4 && resp[2]&0x02 != 0
}

var qtypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

// parseQuery extracts qname and qtype from a DNS query packet.
func parseQuery(pkt []byte) (string, string) {
	defer func() { _ = recover() }()
	if len(pkt) < 12 {
		return "", ""
	}
	off := 12
	var labels []string
	for {
		if off >= len(pkt) {
			return "", ""
		}
		l := int(pkt[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return "", "" // compression shouldn't appear in questions
		}
		if off+l > len(pkt) {
			return "", ""
		}
		labels = append(labels, string(pkt[off:off+l]))
		off += l
	}
	if off+4 > len(pkt) {
		return strings.Join(labels, "."), ""
	}
	qt := uint16(pkt[off])<<8 | uint16(pkt[off+1])
	name, ok := qtypeNames[qt]
	if !ok {
		name = fmt.Sprintf("TYPE%d", qt)
	}
	return strings.Join(labels, "."), name
}

// extractAnswer returns the first A/AAAA rdata as a string (best effort).
func extractAnswer(resp []byte) string {
	defer func() { _ = recover() }()
	if len(resp) < 12 {
		return ""
	}
	qd := int(resp[4])<<8 | int(resp[5])
	an := int(resp[6])<<8 | int(resp[7])
	off := 12
	for i := 0; i < qd; i++ {
		off = skipName(resp, off)
		off += 4 // qtype+qclass
	}
	for i := 0; i < an; i++ {
		off = skipName(resp, off)
		if off+10 > len(resp) {
			return ""
		}
		typ := uint16(resp[off])<<8 | uint16(resp[off+1])
		rdlen := int(resp[off+8])<<8 | int(resp[off+9])
		off += 10
		if off+rdlen > len(resp) {
			return ""
		}
		if typ == 1 && rdlen == 4 {
			return net.IP(resp[off : off+4]).String()
		}
		if typ == 28 && rdlen == 16 {
			return net.IP(resp[off : off+16]).String()
		}
		off += rdlen
	}
	return ""
}

func skipName(pkt []byte, off int) int {
	for {
		if off >= len(pkt) {
			return off
		}
		l := int(pkt[off])
		if l&0xC0 != 0 {
			return off + 2 // pointer
		}
		off++
		if l == 0 {
			return off
		}
		off += l
	}
}
