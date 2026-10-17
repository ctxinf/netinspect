// Package netns implements the netns interception mode: the target runs in
// an isolated network namespace whose TCP output is REDIRECTed into the
// proxy core (running inside the namespace via the __agent subprocess) and
// whose DNS goes through our logging forwarder. All original code; it shells
// out to ip/iptables/sysctl.
package netns

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// NetNS describes a prepared network namespace.
type NetNS struct {
	Name       string // ni-<sid>
	VethH      string
	VethN      string
	Subnet     string // 10.200.X.0/24
	HostIP     string // 10.200.X.1
	NSIP       string // 10.200.X.2
	ProxyPort  int
	DashPort   int
	UpstreamDNS string // host DNS server reachable from inside the ns

	cleanups []func()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *NetNS) fail(err error) (*NetNS, error) {
	n.Cleanup()
	return nil, err
}

// Setup creates ni-<sid> with a veth pair, NAT, and TCP REDIRECT to proxyPort.
func Setup(sid string, proxyPort, dashPort int) (*NetNS, error) {
	n := &NetNS{Name: "ni-" + sid, ProxyPort: proxyPort, DashPort: dashPort}
	x, err := freeOctet()
	if err != nil {
		return n.fail(err)
	}
	n.Subnet = fmt.Sprintf("10.200.%d.0/24", x)
	n.HostIP = fmt.Sprintf("10.200.%d.1", x)
	n.NSIP = fmt.Sprintf("10.200.%d.2", x)
	n.VethH = "vh-" + sid
	n.VethN = "vn-" + sid
	inNS := func(args ...string) error {
		return run("ip", append([]string{"netns", "exec", n.Name}, args...)...)
	}

	steps := []func() error{
		func() error { return run("ip", "netns", "add", n.Name) },
		func() error { return run("ip", "link", "add", n.VethH, "type", "veth", "peer", "name", n.VethN) },
		func() error { return run("ip", "link", "set", n.VethN, "netns", n.Name) },
		func() error { return run("ip", "addr", "add", n.HostIP+"/24", "dev", n.VethH) },
		func() error { return run("ip", "link", "set", n.VethH, "up") },
		func() error { return inNS("ip", "link", "set", "lo", "up") },
		func() error { return inNS("ip", "addr", "add", n.NSIP+"/24", "dev", n.VethN) },
		func() error { return inNS("ip", "link", "set", n.VethN, "up") },
		func() error { return inNS("ip", "route", "add", "default", "via", n.HostIP) },
		func() error { return inNS("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp", "-m", "mark", "--mark", "0x1", "-j", "ACCEPT") },
		func() error { return inNS("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprint(proxyPort)) },
		func() error { return run("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", n.Subnet, "-j", "MASQUERADE") },
		func() error { return run("iptables", "-A", "FORWARD", "-s", n.Subnet, "-j", "ACCEPT") },
		func() error { return run("iptables", "-A", "FORWARD", "-d", n.Subnet, "-j", "ACCEPT") },
	}
	// register cleanups in reverse before running (best effort rollback)
	n.cleanups = []func(){
		func() { run("iptables", "-D", "FORWARD", "-d", n.Subnet, "-j", "ACCEPT") },
		func() { run("iptables", "-D", "FORWARD", "-s", n.Subnet, "-j", "ACCEPT") },
		func() { run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", n.Subnet, "-j", "MASQUERADE") },
		func() { run("ip", "link", "del", n.VethH) },
		func() { run("ip", "netns", "del", n.Name) },
		func() { os.RemoveAll("/etc/netns/" + n.Name) },
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return n.fail(fmt.Errorf("netns setup: %w", err))
		}
	}
	// ip_forward (warn only)
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		fmt.Fprintf(os.Stderr, "[netinspect] warning: %v\n", err)
	}
	// resolv.conf for the namespace -> our DNS forwarder
	n.UpstreamDNS = pickUpstreamDNS()
	if err := os.MkdirAll("/etc/netns/"+n.Name, 0755); err != nil {
		return n.fail(err)
	}
	if err := os.WriteFile("/etc/netns/"+n.Name+"/resolv.conf",
		[]byte("nameserver "+n.NSIP+"\n"), 0644); err != nil {
		return n.fail(err)
	}
	return n, nil
}

// Exec runs a command inside the namespace.
func (n *NetNS) Exec(name string, args ...string) *exec.Cmd {
	return exec.Command("ip", append([]string{"netns", "exec", n.Name, name}, args...)...)
}

// Cleanup removes the namespace, veth, iptables rules and resolv.conf.
func (n *NetNS) Cleanup() {
	for _, c := range n.cleanups {
		func() {
			defer func() { _ = recover() }()
			c()
		}()
	}
	n.cleanups = nil
}

func freeOctet() (int, error) {
	out, _ := exec.Command("ip", "addr", "show").Output()
	s := string(out)
	for x := 100; x <= 254; x++ {
		if !strings.Contains(s, fmt.Sprintf("10.200.%d.", x)) {
			return x, nil
		}
	}
	return 0, fmt.Errorf("no free 10.200.X.0/24 subnet")
}

// pickUpstreamDNS returns the host's first non-loopback nameserver, or a
// public fallback when the host uses a loopback stub (unreachable from ns).
func pickUpstreamDNS() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "8.8.8.8"
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "nameserver" {
			ip := f[1]
			if ip == "127.0.0.53" || ip == "127.0.0.1" || ip == "::1" {
				continue
			}
			return ip
		}
	}
	return "8.8.8.8"
}
