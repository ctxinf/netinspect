// Package netns: __agent entrypoint (runs inside the namespace).
package netns

import (
	"fmt"
	"net"
	"time"

	"netinspect/internal/dashboard"
	"netinspect/internal/proxy"
	"netinspect/internal/store"
)

// RunAgent starts the proxy core (transparent frontend), the dashboard and
// the DNS forwarder inside the network namespace. It runs until killed.
func RunAgent(sid, command string, proxyPort, dashPort int, nsIP, upstreamDNS, token string) error {
	st := store.New(store.Session{
		ID:        sid,
		StartedAt: time.Now().UnixMilli(),
		Command:   command,
		Mode:      "netns",
	})
	hub := dashboard.NewHub()
	px := proxy.New(proxy.Config{
		Mode:         "netns",
		Store:        st,
		MarkOutbound: true, // outbound sockets skip our own REDIRECT rule
		Emit:         hub.Publish,
	})

	// transparent proxy on loopback (REDIRECT target), both families
	ln4, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		return fmt.Errorf("agent proxy listen: %w", err)
	}
	ln6, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", proxyPort))
	if err != nil {
		ln4.Close()
		return fmt.Errorf("agent proxy listen6: %w", err)
	}
	go px.ServeTransparent(ln4)
	go px.ServeTransparent(ln6)

	// dashboard on loopback and on the ns IP (reachable from host)
	dash := dashboard.New(st, hub)
	dash.ConfigureControl(token, nil, func() { px.Close(); st.EndSession() })
	dashURL := fmt.Sprintf("http://%s:%d", nsIP, dashPort)
	st.SetDashboardURL(dashURL)
	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", dashPort), fmt.Sprintf("%s:%d", nsIP, dashPort)} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("agent dashboard listen %s: %w", addr, err)
		}
		go dash.Serve(ln)
	}

	// DNS forwarder with query logging
	go func() {
		_ = ServeDNS(net.JoinHostPort(nsIP, "53"), net.JoinHostPort(upstreamDNS, "53"), st, hub.Publish)
	}()

	select {} // run until killed by the launcher
}
