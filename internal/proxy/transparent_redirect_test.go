package proxy

// Verifies the transparent-proxy path used by netns mode:
// iptables REDIRECT -> ServeTransparent -> SO_ORIGINAL_DST recovery ->
// direct dial (with SO_MARK bypass so the proxy's own outbound connection
// is not re-redirected).
//
// Requires root + iptables. Skipped otherwise.

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"netinspect/internal/store"
)

func ipt(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %v (%s)", args, err, out)
	}
	return nil
}

func iptMust(t *testing.T, args ...string) {
	t.Helper()
	if err := ipt(args...); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestTransparentRedirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for iptables REDIRECT")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("no iptables")
	}

	const backendPort = 18081

	// 1. real backend server on 127.0.0.1:18081
	backend, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Read(buf) // read the request, ignore content
				fmt.Fprint(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
		}
	}()

	// 2. transparent proxy with marked outbound dials
	st := store.New(store.Session{ID: "test", StartedAt: 1, Mode: "netns"})
	px := New(Config{Mode: "netns", Store: st, MarkOutbound: true})
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer pln.Close()
	proxyPort := pln.Addr().(*net.TCPAddr).Port
	go px.ServeTransparent(pln)
	defer px.Close()

	// 3. REDIRECT 127.0.0.1:18081 -> proxy; marked packets bypass.
	// If the kernel lacks the nat/mark/REDIRECT extensions (common in
	// restricted sandboxes), skip instead of failing.
	if err := ipt("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport",
		fmt.Sprint(backendPort), "-j", "REDIRECT", "--to-ports", fmt.Sprint(proxyPort)); err != nil {
		t.Skipf("iptables REDIRECT unavailable, skipping: %v", err)
	}
	defer ipt("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport",
		fmt.Sprint(backendPort), "-j", "REDIRECT", "--to-ports", fmt.Sprint(proxyPort))
	iptMust(t, "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "0x1", "-j", "ACCEPT")
	defer ipt("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "0x1", "-j", "ACCEPT")

	// 4. client connects to 127.0.0.1:18081 -> should be transparently proxied
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort), 5*time.Second)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := io.ReadAll(c)
	c.Close()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := string(resp); len(got) < 12 || got[:12] != "HTTP/1.0 200" {
		t.Fatalf("unexpected response: %q", got)
	}

	// 5. the proxy must have recorded the ORIGINAL destination
	deadline := time.Now().Add(5 * time.Second)
	for {
		conns := st.ListConnections("", 10)
		done := false
		for _, cn := range conns {
			if cn.OrigIP == "127.0.0.1" && cn.OrigPort == backendPort && cn.Result == "ok" {
				done = true
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recorded connection for 127.0.0.1:%d, got %+v", backendPort, conns)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
