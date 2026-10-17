package session

import (
	"net"
	"netinspect/internal/dashboard"
	"netinspect/internal/store"
	"strconv"
	"testing"
)

func TestDashboardPortIncrementAndEphemeral(t *testing.T) {
	// Keep eight consecutive ports busy, beyond the old six-port limit.
	var busy []net.Listener
	var base int
	for tries := 0; tries < 100; tries++ {
		first, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		base = first.Addr().(*net.TCPAddr).Port
		busy = []net.Listener{first}
		if base > 65525 {
			first.Close()
			continue
		}
		for p := base + 1; p < base+8; p++ {
			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
			if err != nil {
				break
			}
			busy = append(busy, ln)
		}
		if len(busy) == 8 {
			break
		}
		for _, ln := range busy {
			ln.Close()
		}
		busy = nil
	}
	if len(busy) != 8 {
		t.Fatal("could not reserve consecutive ports")
	}
	defer func() {
		for _, ln := range busy {
			ln.Close()
		}
	}()
	cfg := Config{Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(base)), runtime: &runtimeState{done: make(chan struct{})}}
	ln, url, err := startDashboard(cfg, store.New(store.Session{}), dashboard.NewHub())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ln.Addr().(*net.TCPAddr).Port < base+8 {
		t.Fatalf("did not increment: %s", url)
	}
	cfg.Listen = "127.0.0.1:0"
	ephemeral, url, err := startDashboard(cfg, store.New(store.Session{}), dashboard.NewHub())
	if err != nil {
		t.Fatal(err)
	}
	defer ephemeral.Close()
	if dashboardPort(url[len("http://"):]) != ephemeral.Addr().(*net.TCPAddr).Port {
		t.Fatalf("wrong ephemeral URL: %s", url)
	}
}
