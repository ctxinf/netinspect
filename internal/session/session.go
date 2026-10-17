// Package session orchestrates one netinspect run: it starts the side
// channel, proxy core and dashboard, prepares the chosen interception mode,
// launches the target, prints the honest banner, and cleans up afterwards.
// Everything is in-memory; records vanish when the process exits.
package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"netinspect/internal/cliui"
	"netinspect/internal/dashboard"
	"netinspect/internal/observe"
	"netinspect/internal/proxy"
	"netinspect/internal/sidechan"
	"netinspect/internal/store"
	"netinspect/internal/version"
	"netinspect/modes/netns"
	"netinspect/modes/preload"
	modesptrace "netinspect/modes/ptrace"
)

// Config configures one run.
type Config struct {
	UpstreamProxy string
	upstream      proxy.Upstream
	Mode          string   // preload|ptrace|netns|observe
	Listen        string   // dashboard listen addr, e.g. 127.0.0.1:17890
	Command       []string // target command
	ExePath       string   // this binary (for __agent re-exec)
	TargetUser    string
	OpenBrowser   bool
	KeepAlive     time.Duration
	MemoryMB      int64
	identity      *targetIdentity
	runtime       *runtimeState
}

var validModes = map[string]bool{
	"preload": true, "ptrace": true, "netns": true, "observe": true,
}

func newSID() string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// Run executes one session.
func Run(cfg Config) error {
	if err := checkNesting(); err != nil {
		return err
	}
	previous, hadPrevious := os.LookupEnv(activeSessionEnv)
	if err := os.Setenv(activeSessionEnv, strconv.Itoa(os.Getpid())); err != nil {
		return err
	}
	defer func() {
		if hadPrevious {
			_ = os.Setenv(activeSessionEnv, previous)
		} else {
			_ = os.Unsetenv(activeSessionEnv)
		}
	}()
	if !validModes[cfg.Mode] {
		return fmt.Errorf("invalid --mode %q: must be one of preload|ptrace|netns|observe", cfg.Mode)
	}
	if cfg.KeepAlive < 0 {
		return fmt.Errorf("keep-alive cannot be negative")
	}
	if len(cfg.Command) == 0 {
		return fmt.Errorf("no command given")
	}
	if cfg.Mode == "observe" && cfg.UpstreamProxy != "" {
		return fmt.Errorf("--upstream-proxy is not supported in observe mode")
	}
	upstream, err := proxy.NewUpstream(cfg.UpstreamProxy, cfg.Mode == "netns")
	if err != nil {
		return err
	}
	cfg.upstream = upstream
	if cfg.Mode == "netns" && os.Geteuid() != 0 {
		return fmt.Errorf("netns requires root to create a network namespace; launch with sudo (the target defaults to the original sudo user)")
	}

	if cfg.Mode != "netns" && cfg.TargetUser != "" {
		return fmt.Errorf("--user is only supported in netns mode")
	}
	if cfg.Mode == "netns" {
		identity, err := resolveTargetIdentity(cfg.TargetUser)
		if err != nil {
			return err
		}
		cfg.identity = identity
	}
	if cfg.Mode == "ptrace" {
		warnPtraceStartup(cfg.Command)
	}
	warnCompatibility(cfg)
	warnDesktopHandoff(cfg.Command)
	sid := newSID()
	cfg.runtime = &runtimeState{done: make(chan struct{}), token: newSID() + newSID() + newSID() + newSID()}
	upstreamName := ""
	if upstream != nil {
		upstreamName = upstream.Name()
	}
	st := store.NewWithLimit(store.Session{
		ID:            sid,
		StartedAt:     time.Now().UnixMilli(),
		Command:       strings.Join(cfg.Command, " "),
		Mode:          cfg.Mode,
		UpstreamProxy: upstreamName,
	}, cfg.MemoryMB<<20)
	hub := dashboard.NewHub()

	dashLn, dashURL, err := startDashboard(cfg, st, hub)
	if err != nil {
		return err
	}
	defer dashLn.Close()
	cfg.runtime.url = dashURL
	cfg.Listen = strings.TrimPrefix(dashURL, "http://")
	printBanner()
	var runErr error
	switch cfg.Mode {
	case "preload":
		runErr = runPreload(cfg, sid, st, hub)
	case "ptrace":
		runErr = runPtrace(cfg, sid, st, hub)
	case "netns":
		return runNetns(cfg, sid, st, hub, dashboardPort(cfg.Listen))
	case "observe":
		runErr = runObserve(cfg, sid, st, hub)
	}
	// Setup failures should return immediately; only completed targets retain the dashboard.
	if st.Session().EndedAt != 0 {
		warnNoRecords(cfg, st.Stats(), st.Session().StartedAt, runErr)
		retain(cfg, runErr)
	}
	return runErr
}

type runtimeState struct {
	done  chan struct{}
	once  sync.Once
	token string
	url   string
	dash  *dashboard.Server
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func retain(cfg Config, runErr error) {
	result := "success"
	if runErr != nil {
		result = runErr.Error()
	}
	mark := "✓"
	if runErr != nil {
		mark = "!"
	}
	cliui.Printf("\n%s Target exited · %s\n", mark, result)
	if cfg.KeepAlive == 0 {
		return
	}
	cliui.Printf("Dashboard stays available for %s, until %s; use Shut down in the dashboard.\nOr run %s stop --url %s --token %s\nOr press Ctrl+C to stop\n", cfg.KeepAlive, time.Now().Add(cfg.KeepAlive).Format("15:04:05"), shellQuote(cfg.ExePath), shellQuote(cfg.runtime.url), cfg.runtime.token)
	timer := time.NewTimer(cfg.KeepAlive)
	defer timer.Stop()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	select {
	case <-timer.C:
	case <-cfg.runtime.done:
	case <-sig:
	}
	cliui.Printf("· Dashboard stopped; in-memory records released\n")
}

func dashboardPort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 17890
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 17890
	}
	return n
}

func printBanner() {
	cliui.Printf("──────────────── netinspect %s ────────────────\n", version.Current().Version)
}

func printPanel(cfg Config) {
	if cfg.upstream != nil {
		cliui.Printf("· Upstream: %s (TCP only; DNS/UDP are not tunneled)\n", cfg.upstream.Name())
	}
	cliui.Printf("· Dashboard: %s\n", cfg.runtime.url)
	if cfg.OpenBrowser {
		openBrowser(cfg.runtime.url, cfg.identity)
	}
}

// startDashboard binds atomically, incrementing only on address conflicts.
func startDashboard(cfg Config, st *store.Store, hub *dashboard.Hub) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, "", fmt.Errorf("bad --listen %q", cfg.Listen)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, "", fmt.Errorf("invalid dashboard port %q", portStr)
	}
	var ln net.Listener
	for p := port; p <= 65535; p++ {
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EADDRINUSE) || port == 0 {
			return nil, "", fmt.Errorf("dashboard listen: %w", err)
		}
	}
	if ln == nil {
		return nil, "", fmt.Errorf("no available dashboard port: %w", err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	displayHost := host
	if host == "" || host == "0.0.0.0" {
		displayHost = "127.0.0.1"
	}
	if host == "::" {
		displayHost = "::1"
	}
	url := "http://" + net.JoinHostPort(displayHost, strconv.Itoa(actualPort))
	st.SetDashboardURL(url)
	dash := dashboard.New(st, hub)
	cfg.runtime.dash = dash
	dash.ConfigureControl(cfg.runtime.token, func() { cfg.runtime.once.Do(func() { close(cfg.runtime.done) }) }, nil)
	go dash.Serve(ln)
	return ln, url, nil
}

func runtimeDir(sid string) string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("netinspect-%d", os.Geteuid()))
	}
	return filepath.Join(base, "ni-"+sid)
}

// ---- preload ----

func runPreload(cfg Config, sid string, st *store.Store, hub *dashboard.Hub) error {
	rdir := runtimeDir(sid)
	soPath, err := preload.Extract(rdir)
	if err != nil {
		return err
	}
	defer os.RemoveAll(rdir)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port
	defer proxyLn.Close()

	side, err := sidechan.New(filepath.Join(rdir, "side.sock"))
	if err != nil {
		return err
	}
	defer side.Close()

	px := proxy.New(proxy.Config{Mode: "preload", Side: side, Store: st, Upstream: cfg.upstream, Emit: hub.Publish})
	go px.ServeSOCKS5(proxyLn)

	dashPort := dashboardPort(cfg.Listen)

	cliui.Printf("· TCP: proxy endpoint 127.0.0.1:%d\n", proxyPort)

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+soPath,
		"NETINSPECT_SOCK_PATH="+side.Path(),
		"NETINSPECT_SOCKS_PORT="+strconv.Itoa(proxyPort),
		"NETINSPECT_DASH_PORT="+strconv.Itoa(dashPort),
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	printPanel(cfg)
	endOutput := cliui.TargetOutput()
	defer endOutput()
	if err := cmd.Start(); err != nil {
		return err
	}
	expectedNS, _ := os.Readlink("/proc/self/ns/net")
	stopMonitor := monitorTarget(cfg, cmd.Process.Pid, expectedNS)
	defer stopMonitor()
	runErr := waitTarget(cmd)
	stopMonitor()
	proxyLn.Close()
	px.Close()
	st.EndSession()
	return runErr
}

// ---- ptrace ----

func runPtrace(cfg Config, sid string, st *store.Store, hub *dashboard.Hub) error {
	rdir := runtimeDir(sid)
	if err := os.MkdirAll(rdir, 0755); err != nil {
		return err
	}
	defer os.RemoveAll(rdir)

	// bind the same port on 127.0.0.1 and ::1 for the transparent frontend
	var proxyLn4, proxyLn6 net.Listener
	var proxyPort int
	for tries := 0; tries < 20; tries++ {
		tmp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		p := tmp.Addr().(*net.TCPAddr).Port
		tmp.Close()
		l4, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		l6, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", p))
		if err != nil {
			l4.Close()
			continue
		}
		proxyLn4, proxyLn6, proxyPort = l4, l6, p
		break
	}
	if proxyLn4 == nil {
		return fmt.Errorf("could not bind transparent proxy port")
	}
	defer proxyLn4.Close()
	defer proxyLn6.Close()

	side, err := sidechan.New(filepath.Join(rdir, "side.sock"))
	if err != nil {
		return err
	}
	defer side.Close()

	px := proxy.New(proxy.Config{Mode: "ptrace", Side: side, Store: st, Upstream: cfg.upstream, Emit: hub.Publish})
	go px.ServeTransparent(proxyLn4)
	go px.ServeTransparent(proxyLn6)

	dashPort := dashboardPort(cfg.Listen)

	cliui.Printf("· TCP: transparent proxy endpoint 127.0.0.1:[::1]:%d (ptrace rewrites connect)\n", proxyPort)

	printPanel(cfg)
	endOutput := cliui.TargetOutput()
	defer endOutput()
	traceErr := modesptrace.Run(cfg.Command[0], cfg.Command[1:], side.Path(), proxyPort, dashPort)
	proxyLn4.Close()
	proxyLn6.Close()
	px.Close()
	if traceErr != nil {
		var exit *modesptrace.ExitError
		if !errors.As(traceErr, &exit) {
			return traceErr
		}
	}
	st.EndSession()
	return traceErr
}

// ---- netns ----

func runNetns(cfg Config, sid string, st *store.Store, hub *dashboard.Hub, dashPort int) error {
	// pick a free proxy port (agent binds it inside the fresh ns)
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	proxyPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	n, err := netns.Setup(sid, proxyPort, dashPort)
	if err != nil {
		return err
	}
	defer n.Cleanup()

	cliui.Printf("· netns: %s subnet=%s proxy=127.0.0.1:%d (inside namespace)\n", n.Name, n.Subnet, proxyPort)
	cliui.Printf("· DNS: forwarder %s:53 -> upstream %s\n", n.NSIP, n.UpstreamDNS)

	agent := n.Exec(cfg.ExePath, "__agent",
		"--sid", sid,
		"--command", strings.Join(cfg.Command, " "),
		"--proxy-port", strconv.Itoa(proxyPort),
		"--dash-port", strconv.Itoa(dashPort),
		"--ns-ip", n.NSIP,
		"--upstream-dns", n.UpstreamDNS,
		"--control-token", cfg.runtime.token,
		"--memory-mb", strconv.FormatInt(cfg.MemoryMB, 10),
	)
	// Pass even an empty value so inherited helper state cannot select an upstream.
	agent.Env = append(os.Environ(), "NETINSPECT_UPSTREAM_PROXY="+cfg.UpstreamProxy)
	agent.Stdout, agent.Stderr = os.Stdout, os.Stderr
	if err := agent.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	defer func() {
		agent.Process.Kill()
		agent.Wait()
	}()

	// wait for the agent's dashboard to answer from the host side
	dashURL := fmt.Sprintf("http://%s:%d", n.NSIP, dashPort)
	if err := waitTCP(n.NSIP, dashPort, 15*time.Second); err != nil {
		return fmt.Errorf("agent did not come up: %w", err)
	}

	remote, _ := url.Parse(dashURL)
	forward := httputil.NewSingleHostReverseProxy(remote)
	forward.Transport = &http.Transport{Proxy: nil}
	cfg.runtime.dash.SetDataHandler(forward)

	targetArgs := cfg.identity.wrap(cfg.Command)
	target := n.Exec(targetArgs[0], targetArgs[1:]...)
	target.Env = cfg.identity.environment()
	target.Stdin, target.Stdout, target.Stderr = os.Stdin, os.Stdout, os.Stderr
	printPanel(cfg)
	endOutput := cliui.TargetOutput()
	defer endOutput()
	if err := target.Start(); err != nil {
		return err
	}
	expectedNS, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", agent.Process.Pid))
	stopMonitor := monitorTarget(cfg, target.Process.Pid, expectedNS)
	defer stopMonitor()
	runErr := waitTarget(target)
	stopMonitor()
	endOutput()
	req, _ := http.NewRequest(http.MethodPost, dashURL+"/api/end", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.runtime.token)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	res, err := client.Do(req)
	if err == nil {
		res.Body.Close()
	} else {
		cliui.Printf("! Cannot update netns session state: %v\n", err)
	}
	// The host store has no connection data in netns mode; use agent statistics.
	if response, err := client.Get(dashURL + "/api/session"); err == nil {
		var snapshot struct {
			Stats store.Stats `json:"stats"`
		}
		if response.StatusCode == http.StatusOK && json.NewDecoder(response.Body).Decode(&snapshot) == nil {
			warnNoRecords(cfg, snapshot.Stats, st.Session().StartedAt, runErr)
		}
		response.Body.Close()
	}
	st.EndSession()
	retain(cfg, runErr)
	return runErr
}

func waitTCP(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s:%d", host, port)
}

// ---- observe ----

func runObserve(cfg Config, sid string, st *store.Store, hub *dashboard.Hub) error {
	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	printPanel(cfg)
	endOutput := cliui.TargetOutput()
	defer endOutput()
	if err := cmd.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observeWarnings sync.Map
	go observe.PollWithDiagnostics(ctx, cmd.Process.Pid, st, func(message string) {
		if _, loaded := observeWarnings.LoadOrStore(message, true); !loaded {
			cliui.Printf("! WARN [observe]: %s\n", message)
		}
	})
	expectedNS, _ := os.Readlink("/proc/self/ns/net")
	stopMonitor := monitorTarget(cfg, cmd.Process.Pid, expectedNS)
	defer stopMonitor()
	runErr := waitTarget(cmd)
	stopMonitor()
	cancel()
	// let the poller record final state
	time.Sleep(400 * time.Millisecond)
	st.EndSession()
	return runErr
}

// Forward termination to the target while keeping the dashboard available for review.
func waitTarget(cmd *exec.Cmd) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	return cmd.Wait()
}

// Opening a browser is best effort and never delays the wrapped program.
func openBrowser(panelURL string, identity *targetIdentity) {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return
	}
	path, err := exec.LookPath("xdg-open")
	if err != nil {
		return
	}
	args := identity.wrap([]string{path, panelURL})
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = identity.environment()
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}
