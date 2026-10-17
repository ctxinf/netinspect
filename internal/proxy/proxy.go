// Package proxy is the unified local proxy core. All interception modes feed
// connections into this single core; it dials the real target directly,
// records connection-level metadata, and relays bytes. It never decrypts or
// inspects content: TLS is only classified from the ClientHello (SNI/ALPN).
// Phase 1 has no upstream proxy support (Upstream is a stub for later).
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"netinspect/internal/capture"
	"netinspect/internal/sidechan"
	"netinspect/internal/store"
)

// Upstream routes an outbound connection through an upstream proxy.
// Phase 1 does not implement any upstream; nil means direct dial.
type Upstream interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Name() string
}

// Event is pushed to the dashboard fan-out. Conn/DNS are copies.
type Event struct {
	Type string // "conn_new" | "conn_update" | "conn_closed" | "dns"
	Conn *store.Conn
	DNS  *store.DNSQuery
}

// Config configures the proxy core.
type Config struct {
	Mode         string // preload|ptrace|netns (observe never starts a proxy)
	Side         *sidechan.Server
	Store        *store.Store
	MarkOutbound bool // set SO_MARK=0x1 on outbound sockets (netns anti-loop)
	Upstream     Upstream
	Emit         func(Event)
}

// Server is the unified proxy core.
type Server struct {
	cfg  Config
	mu   sync.Mutex
	live map[net.Conn]struct{}
	wg   sync.WaitGroup
}

// New creates a proxy core.
func New(cfg Config) *Server {
	return &Server{cfg: cfg, live: make(map[net.Conn]struct{})}
}

func (s *Server) emitConn(typ string, c *store.Conn) {
	if s.cfg.Emit != nil && c != nil && c.ID != 0 {
		cp := *c
		s.cfg.Emit(Event{Type: typ, Conn: &cp})
	}
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.live[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.live, c)
	s.mu.Unlock()
}

// Close force-closes all live relayed connections.
func (s *Server) Close() {
	s.mu.Lock()
	for c := range s.live {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// ---- frontends ----

// ServeSOCKS5 serves a no-auth SOCKS5 CONNECT frontend (used by preload mode).
func (s *Server) ServeSOCKS5(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSOCKS5(c)
		}()
	}
}

// ServeTransparent serves connections redirected by iptables REDIRECT/DNAT
// (used by ptrace and netns modes), recovering the original destination via
// SO_ORIGINAL_DST.
func (s *Server) ServeTransparent(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ip, port, err := originalDst(c)
			if err != nil {
				// Not a NATed connection (ptrace mode rewrites the
				// sockaddr directly): the destination can only come
				// from the side-channel MAP.
				s.handleTransparent(c, "", 0)
				return
			}
			s.handleTransparent(c, ip.String(), port)
		}()
	}
}

// ---- SOCKS5 ----

func (s *Server) handleSOCKS5(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var host string
	var port int
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 6)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b[:4]).String()
		port = int(b[4])<<8 | int(b[5])
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b[:len(b)-2])
		port = int(b[len(b)-2])<<8 | int(b[len(b)-1])
	case 0x04: // IPv6
		b := make([]byte, 18)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b[:16]).String()
		port = int(b[16])<<8 | int(b[17])
	default:
		c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	c.SetDeadline(time.Time{})

	// resolve domain requests early to fail fast with a proper SOCKS reply
	dialIP := host
	if net.ParseIP(host) == nil {
		addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
		if err != nil || len(addrs) == 0 {
			c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			s.recordFailed(c, host, "", port, "dns_error", "resolve: "+errString(err))
			return
		}
		dialIP = addrs[0].IP.String()
	}
	rec, server := s.establish(c, host, dialIP, port, "socks5")
	if rec == nil {
		return
	}
	if server == nil {
		c.Write([]byte{0x05, socksRep(rec.Result), 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// success reply BEFORE relaying: the SOCKS client only proceeds after this
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		server.Close()
		return
	}
	s.relayAndFinish(c, server, rec)
}

// socksRep maps our dial result to a SOCKS5 reply code.
func socksRep(result string) byte {
	switch result {
	case "refused":
		return 0x05
	case "timeout", "unreachable", "dns_error":
		return 0x04
	default:
		return 0x01
	}
}

// ---- connection handling ----

func (s *Server) recordFailed(c net.Conn, origHost, origIP string, origPort int, result, errText string) *store.Conn {
	pid, comm, mode := 0, "", s.cfg.Mode
	if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok && s.cfg.Side != nil {
		if e, ok := s.cfg.Side.LookupRetry(addr.Port, 80*time.Millisecond); ok {
			pid, mode = e.PID, e.Mode
			comm = commOf(pid)
		}
	}
	rec := &store.Conn{
		PID: pid, Comm: comm, Mode: mode,
		OrigHost: origHost, OrigIP: origIP, OrigPort: origPort,
		Route: "DIRECT", Result: result, Error: errText,
	}
	if caddr := c.RemoteAddr(); caddr != nil {
		rec.Source = caddr.String()
	}
	s.cfg.Store.AddConnection(rec)
	s.cfg.Store.FinishConnection(rec.ID, 0, 0, result, errText)
	s.emitConn("conn_new", rec)
	s.emitConn("conn_closed", rec)
	return rec
}

// handleConn proxies one accepted client connection to (origHost,origPort).
// origHost is kept for display (may be a domain); dialIP is the literal IP
// to dial (already resolved when origHost was a domain).
// handleTransparent handles one connection from the transparent frontend
// (ptrace/netns): the original destination comes from SO_ORIGINAL_DST.
func (s *Server) handleTransparent(client net.Conn, origIP string, origPort int) {
	rec, server := s.establish(client, "", origIP, origPort, "transparent")
	if server == nil {
		client.Close()
		return
	}
	s.relayAndFinish(client, server, rec)
}

// establish attributes the client, records the connection, and dials the
// real target. On dial failure it finishes the record and returns nil server.
func (s *Server) establish(client net.Conn, origHost, dialIP string, origPort int, frontend string) (*store.Conn, net.Conn) {
	srcPort := 0
	if addr, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		srcPort = addr.Port
	}

	pid, comm, mode := 0, "", s.cfg.Mode
	if s.cfg.Side != nil {
		if e, ok := s.cfg.Side.LookupRetry(srcPort, 80*time.Millisecond); ok {
			pid, mode = e.PID, e.Mode
			comm = commOf(pid)
			if e.OrigHost != "" {
				// interceptor saw the pre-rewrite address
				origHost, dialIP, origPort = e.OrigHost, e.OrigHost, e.OrigPort
			}
			proxyDebugf("MAP hit srcport=%d -> %+v", srcPort, e)
		} else {
			proxyDebugf("MAP miss srcport=%d", srcPort)
		}
	}
	if pid == 0 {
		if p, cm := attrFromProc(srcPort); p != 0 {
			pid, comm = p, cm
		}
	}
	if origHost == "" {
		origHost = dialIP
	}
	if dialIP == "" || origPort == 0 {
		// no destination: neither SO_ORIGINAL_DST nor MAP knew it
		client.Close()
		return nil, nil
	}
	if net.ParseIP(dialIP) == nil {
		addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), dialIP)
		if err != nil || len(addrs) == 0 {
			rec := s.recordFailed(client, origHost, "", origPort, "dns_error", "resolve: "+errString(err))
			return rec, nil
		}
		dialIP = addrs[0].IP.String()
	}

	rec := &store.Conn{
		PID: pid, Comm: comm, Mode: mode,
		OrigHost: origHost, OrigIP: dialIP, OrigPort: origPort,
		Route: "DIRECT", Result: "open",
	}
	if addr := client.RemoteAddr(); addr != nil {
		rec.Source = addr.String()
	}
	s.cfg.Store.AddConnection(rec)
	s.emitConn("conn_new", rec)

	// dial (phase 1: always direct)
	t0 := time.Now()
	var server net.Conn
	var err error
	if s.cfg.Upstream != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		server, err = s.cfg.Upstream.DialContext(ctx, "tcp", net.JoinHostPort(dialIP, strconv.Itoa(origPort)))
		cancel()
	} else {
		d := &net.Dialer{Timeout: 15 * time.Second}
		if s.cfg.MarkOutbound {
			d.Control = markControl
		}
		server, err = d.Dial("tcp", net.JoinHostPort(dialIP, strconv.Itoa(origPort)))
	}
	rec.ConnectMs = time.Since(t0).Seconds() * 1000
	s.cfg.Store.SetConnectMs(rec.ID, rec.ConnectMs)
	if err != nil {
		result := "error"
		msg := err.Error()
		switch {
		case isTimeout(err):
			result = "timeout"
		case strings.Contains(msg, "connection refused"):
			result = "refused"
		case strings.Contains(msg, "no route") || strings.Contains(msg, "network is unreachable"):
			result = "unreachable"
		}
		s.cfg.Store.FinishConnection(rec.ID, 0, 0, result, msg)
		rec.Result, rec.Error = result, msg
		s.emitConn("conn_closed", rec)
		// note: caller closes client (SOCKS5 still needs it for the reply)
		return rec, nil
	}
	return rec, server
}

// relayAndFinish classifies the stream (metadata only), relays bytes with
// counting, and finishes the connection record.
func (s *Server) relayAndFinish(client, server net.Conn, rec *store.Conn) {
	// peek + classify (metadata only, never decrypt)
	client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	info, pc, _ := capture.Classify(client)
	client.SetReadDeadline(time.Time{})
	helloAt := time.Now()
	s.cfg.Store.UpdateConnMeta(rec.ID, info.Proto, info.SNI, strings.Join(info.ALPN, ","))
	rec.Proto, rec.SNI, rec.ALPN = info.Proto, info.SNI, strings.Join(info.ALPN, ",")
	s.emitConn("conn_update", rec)

	// relay with byte counting
	s.track(client)
	s.track(server)
	up, down, firstDown := s.relay(client, pc.R, server)
	s.untrack(client)
	s.untrack(server)
	client.Close()
	server.Close()

	if rec.Proto == "TLS" && !firstDown.IsZero() {
		rec.TLSMs = firstDown.Sub(helloAt).Seconds() * 1000
		s.cfg.Store.SetTLSMs(rec.ID, rec.TLSMs)
	}
	s.cfg.Store.FinishConnection(rec.ID, up, down, "ok", "")
	rec.BytesUp, rec.BytesDown, rec.Result = up, down, "ok"
	rec.EndedAt = time.Now().UnixMilli()
	s.emitConn("conn_closed", rec)
}

// countFirst records byte count and the time of the first write.
type countFirst struct {
	w     io.Writer
	n     int64
	first time.Time
	once  sync.Once
}

func (c *countFirst) Write(p []byte) (int, error) {
	c.once.Do(func() { c.first = time.Now() })
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

// relay copies both directions until both are done, returning byte counts
// and the time of the first server->client byte.
func (s *Server) relay(client net.Conn, clientR io.Reader, server net.Conn) (up, down int64, firstDown time.Time) {
	uw := &countFirst{w: server}
	dw := &countFirst{w: client}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(uw, clientR)
		closeWrite(server)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(dw, server)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	return uw.n, dw.n, dw.first
}

// ---- helpers ----

func markControl(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 1)
	})
	return err
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func commOf(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// originalDst recovers the pre-REDIRECT/DNAT destination via SO_ORIGINAL_DST.
func originalDst(c net.Conn) (net.IP, int, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCPConn")
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var ip net.IP
	var port int
	var gerr error
	err = rc.Control(func(fd uintptr) {
		var buf [28]byte
		n := uint32(len(buf))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
			fd, unix.SOL_IP, 80, /* SO_ORIGINAL_DST */
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		if errno != 0 {
			gerr = errno
			return
		}
		family := int(buf[0]) | int(buf[1])<<8
		port = int(buf[2])<<8 | int(buf[3])
		switch family {
		case unix.AF_INET:
			ip = net.IP(append([]byte(nil), buf[4:8]...))
		case unix.AF_INET6:
			ip = net.IP(append([]byte(nil), buf[8:24]...))
		default:
			gerr = fmt.Errorf("unknown family %d", family)
		}
		_ = n
	})
	if err != nil {
		return nil, 0, err
	}
	return ip, port, gerr
}

// attrFromProc maps a local TCP source port to (pid, comm) by scanning
// /proc/net/tcp* for the socket inode and then /proc/*/fd.
func attrFromProc(srcPort int) (int, string) {
	inode := findInodeByLocalPort(srcPort)
	if inode == "" {
		return 0, ""
	}
	want := "socket:[" + inode + "]"
	pids, _ := os.ReadDir("/proc")
	for _, p := range pids {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, f := range fds {
			target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, f.Name()))
			if err != nil {
				continue
			}
			if target == want {
				return pid, commOf(pid)
			}
		}
	}
	return 0, ""
}

func findInodeByLocalPort(port int) string {
	want := fmt.Sprintf(":%04X", port)
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			flds := strings.Fields(line)
			if len(flds) < 10 {
				continue
			}
			if strings.HasSuffix(flds[1], want) {
				return flds[9]
			}
		}
	}
	return ""
}
