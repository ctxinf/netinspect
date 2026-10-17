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
			out = append(out, base+" 使用独立沙箱；Flatpak 默认清除 LD_PRELOAD，宿主机注入库和侧信道也可能不可见。当前 preload 不能保证采集沙箱内应用；可尝试 netns，仍需验证。")
		case "ptrace":
			out = append(out, base+" 的沙箱、权限切换或独立启动服务可能限制 ptrace；启动器被跟踪不代表沙箱内应用已被跟踪。可尝试 netns 或 observe，仍需验证。")
		case "netns":
			out = append(out, base+" 可能通过宿主机服务启动应用；若应用在其他网络命名空间中运行，会绕过本次 netns 采集。")
		case "observe":
			out = append(out, base+" 可能通过独立服务启动应用或切换命名空间，observe 的目标进程树和 TCP 表可能无法覆盖应用。")
		}
	}
	if mode == "preload" {
		if inherited := os.Getenv("LD_PRELOAD"); inherited != "" {
			out = append(out, "检测到已有 LD_PRELOAD（可能含 proxychains 等注入库）；当前 preload 会覆盖该设置，目标原有套壳行为可能改变。可尝试 netns 或 observe。")
		}
		switch base {
		case "proxychains", "proxychains4":
			out = append(out, "proxychains 会设置自己的 LD_PRELOAD，可能覆盖 netinspect 注入；即使目标正常联网也可能无法采集。可尝试 netns 或 observe。")
		case "sudo", "su", "doas":
			out = append(out, base+" 的提权/环境清理可能移除 LD_PRELOAD，后续程序可能无法采集；可考虑使用 netns。")
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
			out = append(out, "代理环境变量指向 localhost/回环地址；netns 内的回环地址不属于宿主机，宿主机代理通常不可达。需配置可达的代理地址或桥接；这里不会自动改写代理配置。")
		}
	}
	if mode == "observe" {
		if _, err := os.ReadFile("/proc/net/tcp"); err != nil {
			out = append(out, fmt.Sprintf("observe 无法读取 /proc/net/tcp：%v；不能正常枚举 TCP 连接。", err))
		}
	}
	return out
}

func executableWarnings(path string) []string {
	var warnings []string
	if info, err := os.Stat(path); err == nil && info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		warnings = append(warnings, "目标可执行文件具有 setuid/setgid 位，动态加载器可能忽略 LD_PRELOAD；preload 不能保证生效。")
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
		warnings = append(warnings, "目标 ELF 没有动态解释器（静态链接或自定义加载方式），LD_PRELOAD 无法按常规方式注入；建议使用 netns、ptrace 或 observe。")
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
					warn("maps", "没有权限读取目标内存映射，无法确认注入库是否加载；可能发生权限切换或受 /proc 访问策略限制。")
				} else if err == nil && len(data) > 0 && !strings.Contains(string(data), "libnetinspect.so") {
					warn("injection", "当前目标 PID 未加载 libnetinspect.so：可能清除了 LD_PRELOAD、切换了可执行文件或进入沙箱；该进程的 preload 采集未确认生效。")
				}
			}
			if expectedNS != "" {
				actual, err := os.Readlink(proc + "/ns/net")
				if err == nil && actual != expectedNS {
					warn("namespace", "目标进入了不同的网络命名空间，当前 TCP 视图/重定向规则可能无法覆盖它的流量。")
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
		"preload": "可能没有发起受支持的 TCP 连接，或子进程没有继承注入、通过已有实例/外部服务联网。",
		"ptrace":  "可能没有受支持的 TCP connect，或跟踪权限、沙箱、套壳限制了采集。",
		"netns":   "可能没有受支持的 TCP/DNS 流量，或实际联网进程位于本命名空间之外。",
		"observe": "可能没有 TCP 连接，连接短于 200ms 轮询窗口，或进程归属/权限/命名空间不在观察范围。",
	}[cfg.Mode]
	cliui.Printf("! WARN [%s]: 本次未采集到记录；这不能证明目标没有联网或采集一定失效。%s\n", cfg.Mode, reason)
}
