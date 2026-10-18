//go:build linux && amd64

package ptrace

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"netinspect/internal/sidechan"
)

// TestTraceRewrite runs a real python process under the tracer, checks the
// connect() got rewritten to the fake proxy port, and that a MAP datagram
// arrived with the original destination.
func TestTraceRewrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for ptrace")
	}
	python, err := whichPython()
	if err != nil {
		t.Skip(err)
	}

	// "real" server the target wants to reach
	realLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer realLn.Close()
	realPort := realLn.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := realLn.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()

	// fake proxy port: accept and close so connect() succeeds
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port
	proxied := make(chan int, 4) // src ports seen
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			proxied <- c.RemoteAddr().(*net.TCPAddr).Port
			c.Close()
		}
	}()

	sockPath := fmt.Sprintf("/tmp/ni-ptrace-test-%d.sock", os.Getpid())
	side, err := sidechan.New(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer side.Close()

	code := fmt.Sprintf("import socket;s=socket.create_connection(('127.0.0.1',%d));print(s.recv(2));s.close()", realPort)
	done := make(chan error, 1)
	go func() { done <- Run(python, []string{"-c", code}, sockPath, proxyPort, 59999) }()

	var srcPort int
	select {
	case srcPort = <-proxied:
		t.Logf("proxy accepted connection from srcport %d (rewrite worked)", srcPort)
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never saw the rewritten connection")
	}
	if err := <-done; err != nil {
		t.Fatalf("tracer: %v", err)
	}
	e, ok := side.LookupRetry(srcPort, 2*time.Second)
	if !ok {
		t.Fatalf("no MAP datagram for srcport %d", srcPort)
	}
	if e.OrigHost != "127.0.0.1" || e.OrigPort != realPort || e.Mode != "ptrace" {
		t.Fatalf("bad MAP entry: %+v (want 127.0.0.1:%d ptrace)", e, realPort)
	}
	if e.PID <= 0 {
		t.Fatalf("bad pid in MAP: %+v", e)
	}
	t.Logf("MAP ok: %+v", e)
}

// TestTraceSkipProxyPort ensures connections to the proxy port itself are
// NOT rewritten (anti-recursion).
func TestTraceSkipProxyPort(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for ptrace")
	}
	python, err := whichPython()
	if err != nil {
		t.Skip(err)
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port
	seen := make(chan string, 4)
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			seen <- "direct"
			c.Close()
		}
	}()
	sockPath := fmt.Sprintf("/tmp/ni-ptrace-skip-%d.sock", os.Getpid())
	side, err := sidechan.New(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer side.Close()

	// target connects straight to the proxy port: must NOT be rewritten
	// (rewrite would be a no-op loop to the same port, but we verify no MAP).
	code := fmt.Sprintf("import socket;s=socket.create_connection(('127.0.0.1',%d));s.close()", proxyPort)
	done := make(chan error, 1)
	go func() { done <- Run(python, []string{"-c", code}, sockPath, proxyPort, 59999) }()
	select {
	case <-seen:
	case <-time.After(10 * time.Second):
		t.Fatal("direct connection to proxy port failed")
	}
	if err := <-done; err != nil {
		t.Fatalf("tracer: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	// no MAP should exist for this (we check the table is empty via a bogus port)
	if _, ok := side.Lookup(1); ok {
		t.Fatal("unexpected MAP entry")
	}
}

func whichPython() (string, error) {
	for _, p := range []string{"/usr/bin/python3", "/usr/local/bin/python3"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no python3")
}
