// Package session orchestrates one netinspect run: it starts the side
// channel, proxy core and dashboard, prepares the chosen interception mode,
// launches the target, prints the honest banner, and cleans up afterwards.
// Everything is in-memory; records vanish when the process exits.
package session

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netinspect/internal/dashboard"
	"netinspect/internal/observe"
	"netinspect/internal/proxy"
	"netinspect/internal/sidechan"
	"netinspect/internal/store"
	"netinspect/modes/netns"
	"netinspect/modes/preload"
	modesptrace "netinspect/modes/ptrace"
)

// Config configures one run.
type Config struct {
	Mode    string   // preload|ptrace|netns|observe (required, no default)
	Listen  string   // dashboard listen addr, e.g. 127.0.0.1:17890
	Command []string // target command
	ExePath string   // this binary (for __agent re-exec)
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
	if !validModes[cfg.Mode] {
		return fmt.Errorf("invalid --mode %q: must be one of preload|ptrace|netns|observe", cfg.Mode)
	}
	if len(cfg.Command) == 0 {
		return fmt.Errorf("no command given")
	}
	if cfg.Mode == "netns" && os.Geteuid() != 0 {
		return fmt.Errorf("netns mode requires root")
	}

	sid := newSID()
	st := store.New(store.Session{
		ID:        sid,
		StartedAt: time.Now().UnixMilli(),
		Command:   strings.Join(cfg.Command, " "),
		Mode:      cfg.Mode,
	})
	hub := dashboard.NewHub()

	dashPort := dashboardPort(cfg.Listen)
	printBanner(sid, cfg)

	switch cfg.Mode {
	case "preload":
		return runPreload(cfg, sid, st, hub)
	case "ptrace":
		return runPtrace(cfg, sid, st, hub)
	case "netns":
		return runNetns(cfg, sid, st, hub, dashPort)
	case "observe":
		return runObserve(cfg, sid, st, hub)
	}
	return nil
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

func printBanner(sid string, cfg Config) {
	fmt.Printf("[netinspect] session %s mode=%s target=%s\n", sid, cfg.Mode, strings.Join(cfg.Command, " "))
	switch cfg.Mode {
	case "preload":
		fmt.Printf("[netinspect] TCP: 经本地代理 (SOCKS5, LD_PRELOAD 拦截 connect)\n")
		fmt.Printf("[netinspect] DNS: 不可见 (本模式不拦截 DNS，应用直连解析)\n")
	case "ptrace":
		fmt.Printf("[netinspect] TCP: 经本地代理 (ptrace 改写 connect → 透明代理)\n")
		fmt.Printf("[netinspect] DNS: 不可见 (本模式不拦截 DNS，应用直连解析)\n")
	case "netns":
		fmt.Printf("[netinspect] TCP: 经本地代理 (netns + iptables REDIRECT)\n")
		fmt.Printf("[netinspect] DNS: 经 netinspect 转发器记录 (UDP/53)\n")
	case "observe":
		fmt.Printf("[netinspect] TCP: 仅观察 (/proc 轮询连接元数据，不拦截流量)\n")
		fmt.Printf("[netinspect] DNS: 不可见 (observe 不拦截)\n")
	}
	fmt.Printf("[netinspect] UDP: 不覆盖\n")
	fmt.Printf("[netinspect] TLS: 仅记录 SNI/ALPN 与握手耗时，不解密不看内容\n")
}

// startDashboard binds the dashboard, trying listen then listen+1..+5.
func startDashboard(cfg Config, st *store.Store, hub *dashboard.Hub) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, "", fmt.Errorf("bad --listen %q", cfg.Listen)
	}
	port, _ := strconv.Atoi(portStr)
	var ln net.Listener
	var finalPort int
	for p := port; p < port+6; p++ {
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			finalPort = p
			break
		}
	}
	if ln == nil {
		return nil, "", fmt.Errorf("dashboard listen: %v", err)
	}
	url := fmt.Sprintf("http://%s:%d", host, finalPort)
	st.SetDashboardURL(url)
	dash := dashboard.New(st, hub)
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

	px := proxy.New(proxy.Config{Mode: "preload", Side: side, Store: st, Emit: hub.Publish})
	go px.ServeSOCKS5(proxyLn)

	dashLn, dashURL, err := startDashboard(cfg, st, hub)
	if err != nil {
		return err
	}
	defer dashLn.Close()
	dashPort := dashboardPort(dashURL)

	fmt.Printf("[netinspect] TCP: 代理入口 127.0.0.1:%d\n", proxyPort)
	fmt.Printf("[netinspect] dashboard: %s\n", dashURL)

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+soPath,
		"NETINSPECT_SOCK_PATH="+side.Path(),
		"NETINSPECT_SOCKS_PORT="+strconv.Itoa(proxyPort),
		"NETINSPECT_DASH_PORT="+strconv.Itoa(dashPort),
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := cmd.Run()
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

	px := proxy.New(proxy.Config{Mode: "ptrace", Side: side, Store: st, Emit: hub.Publish})
	go px.ServeTransparent(proxyLn4)
	go px.ServeTransparent(proxyLn6)

	dashLn, dashURL, err := startDashboard(cfg, st, hub)
	if err != nil {
		return err
	}
	defer dashLn.Close()
	dashPort := dashboardPort(dashURL)

	fmt.Printf("[netinspect] TCP: 透明代理入口 127.0.0.1:[::1]:%d (ptrace 改写 connect)\n", proxyPort)
	fmt.Printf("[netinspect] dashboard: %s\n", dashURL)

	traceErr := modesptrace.Run(cfg.Command[0], cfg.Command[1:], side.Path(), proxyPort, dashPort)
	px.Close()
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

	fmt.Printf("[netinspect] netns: %s subnet=%s proxy=127.0.0.1:%d (ns内)\n", n.Name, n.Subnet, proxyPort)
	fmt.Printf("[netinspect] DNS: 转发器 %s:53 -> 上游 %s\n", n.NSIP, n.UpstreamDNS)

	agent := n.Exec(cfg.ExePath, "__agent",
		"--sid", sid,
		"--command", strings.Join(cfg.Command, " "),
		"--proxy-port", strconv.Itoa(proxyPort),
		"--dash-port", strconv.Itoa(dashPort),
		"--ns-ip", n.NSIP,
		"--upstream-dns", n.UpstreamDNS,
	)
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
	fmt.Printf("[netinspect] dashboard: %s\n", dashURL)

	target := n.Exec(cfg.Command[0], cfg.Command[1:]...)
	target.Stdin, target.Stdout, target.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := target.Run()
	st.EndSession()
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
	dashLn, dashURL, err := startDashboard(cfg, st, hub)
	if err != nil {
		return err
	}
	defer dashLn.Close()
	fmt.Printf("[netinspect] dashboard: %s\n", dashURL)

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go observe.Poll(ctx, cmd.Process.Pid, st)
	runErr := cmd.Wait()
	cancel()
	// let the poller record final state
	time.Sleep(400 * time.Millisecond)
	st.EndSession()
	return runErr
}
