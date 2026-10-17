package proxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netinspect/internal/store"
)

func TestUpstreamValidation(t *testing.T) {
	for _, raw := range []string{"ftp://host", "http://", "http://host:0", "socks5://host:65536", "http://host/path", "http://host?q=1", "http://host#fragment", "http://user:secret@host:bad", "socks5://user@host", "socks5://user:@host"} {
		_, err := NewUpstream(raw, false)
		if err == nil {
			t.Errorf("accepted %q", raw)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("credentials leaked")
		}
	}
	for _, raw := range []string{"http://host", "https://host", "socks5://host", "socks5h://host", "socks5://user:secret@[::1]:1080"} {
		u, err := NewUpstream(raw, true)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(u.Name(), "secret") || strings.Contains(u.Name(), "user") {
			t.Fatal("credentials leaked in route")
		}
		if u.(*upstreamProxy).dialer.Control == nil {
			t.Fatal("netns anti-loop mark missing")
		}
	}
	if u, err := NewUpstream("", false); err != nil || u != nil {
		t.Fatal("empty upstream must be direct")
	}
}

func connectServer(t *testing.T, secure bool, status int, auth bool) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "target.invalid:443" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Host)
			w.WriteHeader(400)
			return
		}
		if auth && r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")) {
			t.Error("missing auth")
			w.WriteHeader(407)
			return
		}
		if status >= 300 {
			w.WriteHeader(status)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(rw, "HTTP/1.1 %d Connected\r\n\r\nready", status)
		rw.Flush()
		io.Copy(conn, rw)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server
}

func TestHTTPUpstream(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			server := connectServer(t, secure, 201, true)
			raw := strings.Replace(server.URL, "://", "://user:secret@", 1)
			upstream, err := NewUpstream(raw, false)
			if err != nil {
				t.Fatal(err)
			}
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				upstream.(*upstreamProxy).tlsConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				upstream.(*upstreamProxy).tlsConfig.RootCAs = roots
			}
			conn, err := upstream.DialContext(context.Background(), "tcp", "target.invalid:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			ready := make([]byte, 5)
			if _, err := io.ReadFull(conn, ready); err != nil || string(ready) != "ready" {
				t.Fatalf("lost buffered bytes: %q %v", ready, err)
			}
			payload := strings.Repeat("payload", 20000) // cross the bounded response-reader limit
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != payload {
				t.Fatalf("tunnel data: %v", err)
			}
		})
	}
}

func TestHTTPUpstreamRejects(t *testing.T) {
	for _, status := range []int{302, 407, 503} {
		server := connectServer(t, false, status, false)
		u, _ := NewUpstream(server.URL, false)
		conn, err := u.DialContext(context.Background(), "tcp", "target.invalid:443")
		if err == nil || conn != nil {
			t.Fatal("accepted failed CONNECT")
		}
	}
	server := connectServer(t, true, 200, false)
	u, _ := NewUpstream(server.URL, false)
	if c, err := u.DialContext(context.Background(), "tcp", "target.invalid:443"); err == nil {
		c.Close()
		t.Fatal("accepted untrusted TLS proxy")
	}
}

func socksServer(t *testing.T, target string, auth, reject bool) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 3)
		if _, err = io.ReadFull(conn, header); err != nil {
			t.Error(err)
			return
		}
		method := byte(0)
		if auth {
			method = 2
		}
		if string(header) != string([]byte{5, 1, method}) {
			t.Errorf("bad greeting %v", header)
			return
		}
		conn.Write([]byte{5, method})
		if auth {
			prefix := make([]byte, 2)
			io.ReadFull(conn, prefix)
			username := make([]byte, int(prefix[1]))
			io.ReadFull(conn, username)
			io.ReadFull(conn, prefix[:1])
			password := make([]byte, int(prefix[0]))
			io.ReadFull(conn, password)
			if string(username) != "user" || string(password) != "secret" {
				t.Error("invalid credentials")
				return
			}
			conn.Write([]byte{1, 0})
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			t.Error(err)
			return
		}
		var host string
		switch request[3] {
		case 1:
			b := make([]byte, 4)
			io.ReadFull(conn, b)
			host = net.IP(b).String()
		case 4:
			b := make([]byte, 16)
			io.ReadFull(conn, b)
			host = net.IP(b).String()
		case 3:
			b := make([]byte, 1)
			io.ReadFull(conn, b)
			name := make([]byte, int(b[0]))
			io.ReadFull(conn, name)
			host = string(name)
		default:
			t.Errorf("unexpected address type %d", request[3])
			return
		}
		port := make([]byte, 2)
		io.ReadFull(conn, port)
		if net.JoinHostPort(host, fmt.Sprint(int(port[0])<<8|int(port[1]))) != target {
			t.Errorf("wrong target: %s", host)
			return
		}
		code := byte(0)
		if reject {
			code = 5
		}
		conn.Write([]byte{5, code, 0, 3, 1, 'x', 0, 1}) // domain-form bound address
		if !reject {
			io.Copy(conn, conn)
		}
	}()
	return ln
}

func TestSOCKSUpstream(t *testing.T) {
	for _, target := range []string{"127.0.0.1:443", "[::1]:443", "target.invalid:443"} {
		for _, auth := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", target, auth), func(t *testing.T) {
				ln := socksServer(t, target, auth, false)
				credentials := ""
				if auth {
					credentials = "user:secret@"
				}
				u, err := NewUpstream("socks5h://"+credentials+ln.Addr().String(), false)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := u.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				io.WriteString(conn, "hello")
				b := make([]byte, 5)
				if _, err := io.ReadFull(conn, b); err != nil || string(b) != "hello" {
					t.Fatalf("echo: %q %v", b, err)
				}
			})
		}
	}
	ln := socksServer(t, "127.0.0.1:443", false, true)
	u, _ := NewUpstream("socks5://"+ln.Addr().String(), false)
	if conn, err := u.DialContext(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		conn.Close()
		t.Fatal("accepted SOCKS rejection")
	}
}

func TestUpstreamCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		io.Copy(io.Discard, c)
	}()
	u, _ := NewUpstream("http://"+ln.Addr().String(), false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := u.DialContext(ctx, "tcp", "target.invalid:443"); result <- err }()
	<-accepted
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("accepted canceled handshake")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not cancel")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("leaked connection")
	}
}

func TestUpstreamCoreRemoteDNSAndRoute(t *testing.T) {
	server := connectServer(t, false, 200, true)
	u, _ := NewUpstream(strings.Replace(server.URL, "://", "://user:secret@", 1), false)
	st := store.New(store.Session{})
	px := New(Config{Mode: "preload", Store: st, Upstream: u})
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	rec, conn := px.establish(client, "target.invalid", "target.invalid", 443, "socks5")
	if conn == nil {
		t.Fatalf("upstream dial failed: %+v", rec)
	}
	defer conn.Close()
	if rec.OrigIP != "" || rec.OrigHost != "target.invalid" || rec.Route != u.Name() || strings.Contains(rec.Route, "secret") {
		t.Fatalf("bad route metadata: %+v", rec)
	}
	// Verify the upstream tunnel survives the handshake context's cancellation.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 5)
	if _, err := io.ReadFull(bufio.NewReader(conn), b); err != nil {
		t.Fatal(err)
	}
}
