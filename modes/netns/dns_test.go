package netns

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"netinspect/internal/proxy"
	"netinspect/internal/store"
)

// fakeUpstream answers every query with one A record for 1.2.3.4.
func fakeUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			resp := buildResponse(q)
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func buildResponse(q []byte) []byte {
	// find end of question
	off := 12
	for {
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		off += l
	}
	qEnd := off + 4
	resp := make([]byte, 0, qEnd+16)
	hdr := make([]byte, 12)
	copy(hdr[0:2], q[0:2]) // ID
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	resp = append(resp, hdr...)
	resp = append(resp, q[12:qEnd]...)
	// answer: pointer to qname, A, IN, TTL 300, 1.2.3.4
	resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 1, 2, 3, 4)
	return resp
}

func dnsQuery(name string) []byte {
	var q []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	q = append(q, hdr...)
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01) // root label, QTYPE=A, QCLASS=IN
	return q
}

func TestServeDNS(t *testing.T) {
	if !udpAvailable() {
		t.Skip("UDP loopback not permitted in this sandbox")
	}
	upstream := fakeUpstream(t)
	host, port, _ := net.SplitHostPort(upstream)

	st := store.New(store.Session{ID: "test", Mode: "netns"})
	var emitted []proxy.Event
	emit := func(e proxy.Event) { emitted = append(emitted, e) }

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	// find a free port by listening then closing is racy; instead let ServeDNS pick :0
	// and discover via a second listener is impossible; use a fixed high port with retry
	listenAddr := "127.0.0.1:15353"
	serveErr := make(chan error, 1)
	go func() { serveErr <- ServeDNS(listenAddr, host+":"+port, st, emit) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-serveErr:
		t.Fatalf("ServeDNS exited: %v", err)
	default:
	}

	c, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(dnsQuery("example.com")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4096)
	n, err := c.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if n < 12 || resp[2]&0x80 == 0 {
		t.Fatalf("bad response (%d bytes)", n)
	}
	// the query must be recorded
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(st.ListDNS(10)) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	qs := st.ListDNS(10)
	if len(qs) != 1 {
		t.Fatalf("want 1 dns query recorded, got %d", len(qs))
	}
	if qs[0].QName != "example.com" || qs[0].QType != "A" || qs[0].Answer != "1.2.3.4" {
		t.Fatalf("bad dns record: %+v", qs[0])
	}
	if len(emitted) != 1 || emitted[0].Type != "dns" {
		t.Fatalf("want 1 dns event, got %+v", emitted)
	}
	t.Logf("DNS forwarder ok: %+v", qs[0])
}

func TestParseQuery(t *testing.T) {
	name, qt := parseQuery(dnsQuery("foo.example.org"))
	if name != "foo.example.org" || qt != "A" {
		t.Fatalf("got %q %q", name, qt)
	}
}
