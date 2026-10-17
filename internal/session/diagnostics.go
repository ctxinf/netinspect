package session

import (
	"context"
	"debug/elf"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"netinspect/internal/cliui"
	"netinspect/internal/store"
)

func compatibilityWarnings(mode string, command []string) []string {
	if len(command) == 0 {
		return nil
	}
	var out []string
	base := filepath.Base(command[0])
	if base == "flatpak" || base == "snap" {
		switch mode {
		case "preload":
			out = append(out, base+" uses a separate sandbox; Flatpak clears LD_PRELOAD by default, and host injection libraries/side channels may be inaccessible. Capture is not guaranteed; try netns and verify.")
		case "ptrace":
			out = append(out, base+" sandbox, privilege changes or external launch services may restrict ptrace. Tracing a launcher does not confirm tracing the application. Try netns or observe and verify.")
		case "netns":
			out = append(out, base+" may launch applications through host services; applications in another network namespace bypass this netns capture.")
		case "observe":
			out = append(out, base+" may use external services or switch namespaces; the observed process tree and TCP tables may not cover the application.")
		}
	}
	if mode == "preload" {
		if inherited := os.Getenv("LD_PRELOAD"); inherited != "" {
			out = append(out, "existing LD_PRELOAD detected (possibly proxychains); preload mode replaces it and may change wrapper behavior. Try netns or observe.")
		}
		switch base {
		case "proxychains", "proxychains4":
			out = append(out, "proxychains sets its own LD_PRELOAD and may replace netinspect injection; network access may work without capture. Try netns or observe.")
		case "sudo", "su", "doas":
			out = append(out, base+" may remove LD_PRELOAD during privilege/environment changes, preventing capture of subsequent programs; consider netns.")
		}
		path, err := exec.LookPath(command[0])
		if err == nil {
			out = append(out, executableWarnings(path)...)
		}
	}
	if mode == "netns" {
		loopback := false
		for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NETINSPECT_HTTP_PROXY", "NETINSPECT_SOCKS5_PROXY"} {
			value := os.Getenv(key)
			if value == "" {
				continue
			}
			if !strings.Contains(value, "://") {
				value = "http://" + value
			}
			u, err := url.Parse(value)
			if err == nil && (strings.EqualFold(u.Hostname(), "localhost") || net.ParseIP(u.Hostname()).IsLoopback()) {
				loopback = true
				break
			}
		}
		if loopback {
			out = append(out, "proxy environment points to localhost/loopback; namespace loopback is separate from the host. Configure a reachable proxy address or bridge; proxy settings are not rewritten automatically.")
		}
	}
	if mode == "observe" {
		if _, err := os.ReadFile("/proc/net/tcp"); err != nil {
			out = append(out, fmt.Sprintf("observe cannot read /proc/net/tcp: %v; TCP enumeration is unavailable.", err))
		}
	}
	return out
}

func executableWarnings(path string) []string {
	var warnings []string
	if info, err := os.Stat(path); err == nil && info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		warnings = append(warnings, "target has setuid/setgid bits; the dynamic loader may ignore LD_PRELOAD. Capture is not guaranteed.")
	}
	f, err := elf.Open(path)
	if err != nil {
		return warnings
	} // Scripts and non-ELF launchers are not classified as static.
	defer f.Close()
	dynamic := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
			break
		}
	}
	if !dynamic {
		warnings = append(warnings, "target ELF has no dynamic interpreter (static linking or custom loading); normal LD_PRELOAD injection is unavailable. Try netns, ptrace or observe.")
	}
	return warnings
}

func warnCompatibility(cfg Config) {
	for _, message := range compatibilityWarnings(cfg.Mode, cfg.Command) {
		cliui.Printf("! WARN [%s]: %s\n", cfg.Mode, message)
	}
}

// Only evidence from a still-running target is reported; read races and exited
// targets are ignored. This is diagnostic only and never changes target execution.
func monitorTarget(cfg Config, pid int, expectedNS string) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		warned := map[string]bool{}
		warn := func(key, message string) {
			if !warned[key] {
				warned[key] = true
				cliui.Printf("! WARN [%s]: %s\n", cfg.Mode, message)
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			proc := "/proc/" + strconv.Itoa(pid)
			if _, err := os.Stat(proc); err != nil {
				continue
			}
			switch cfg.Mode {
			case "preload":
				data, err := os.ReadFile(proc + "/maps")
				if os.IsPermission(err) {
					warn("maps", "cannot read target memory maps; injection cannot be confirmed, possibly due to privilege changes or /proc access restrictions.")
				} else if err == nil && len(data) > 0 && !strings.Contains(string(data), "libnetinspect.so") {
					warn("injection", "target PID has not loaded libnetinspect.so: LD_PRELOAD may have been cleared, the executable replaced or a sandbox entered. Capture is unconfirmed.")
				}
			}
			if expectedNS != "" {
				actual, err := os.Readlink(proc + "/ns/net")
				if err == nil && actual != expectedNS {
					warn("namespace", "target entered another network namespace; current TCP tables/redirection rules may not cover its traffic.")
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }
}

func warnNoRecords(cfg Config, stats store.Stats, started int64, runErr error) {
	if stats.Conns+stats.DNS != 0 {
		return
	}
	if runErr == nil && time.Since(time.UnixMilli(started)) < 2*time.Second {
		return
	}
	reason := map[string]string{
		"preload": "There may be no supported TCP connections, injection may not be inherited, or traffic may use existing instances/external services.",
		"ptrace":  "There may be no supported TCP connect calls, or tracing permissions, sandboxes or wrappers may limit capture.",
		"netns":   "There may be no supported TCP/DNS traffic, or the network process may be outside this namespace.",
		"observe": "There may be no TCP connections, connections shorter than the 200ms polling window, or process/permission/namespace limits.",
	}[cfg.Mode]
	cliui.Printf("! WARN [%s]: No records captured; this does not prove the target had no network traffic or capture failed. %s\n", cfg.Mode, reason)
}
