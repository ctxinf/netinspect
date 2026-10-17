// netinspect: per-process network connection inspector for Linux.
// Phase 1: connection-level metadata only. No MITM, no content capture,
// in-memory storage (records vanish when the process exits).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"netinspect/internal/session"
	"netinspect/modes/netns"
)

const usage = `netinspect - Linux 进程级网络连接监控 (Phase 1: 纯连接级元数据)

用法:
  netinspect -- <command> [args...]                                  最简: 默认 observe 模式
  netinspect run --mode <preload|ptrace|netns|observe> [--listen 127.0.0.1:17890] -- <command> [args...]

模式 (run 必须手动指定; 裸 -- 形式默认 observe):
  preload  LD_PRELOAD 拦截 connect, 走 SOCKS5 本地代理 (动态链接程序)
  ptrace   ptrace 改写 connect syscall (静态链接/Go 程序也可用, 仅 x86_64)
  netns    目标跑进独立 netns, iptables REDIRECT + DNS 转发记录 (需 root)
  observe  不拦截, 仅 /proc 轮询观察 TCP 连接元数据 (默认, 零侵入)

说明:
  - 只记录连接元数据: 五元组/进程/耗时/流量/结果/SNI/ALPN/DNS 查询, 不解密不看内容
  - 纯内存存储, 进程退出记录即丢弃
  - dashboard 在目标运行期间实时展示: http://<listen>
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// shorthand: netinspect -- <command>  (default mode: observe, zero intrusion)
	// flags are also accepted: netinspect --mode ptrace -- <command>
	a1 := os.Args[1]
	if a1 == "--" || (strings.HasPrefix(a1, "-") && a1 != "-h" && a1 != "--help") {
		args := os.Args[2:]
		if a1 != "--" {
			args = os.Args[1:]
		}
		if err := runCmd(args, "observe"); err != nil {
			fmt.Fprintf(os.Stderr, "[netinspect] error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	switch os.Args[1] {
	case "run":
		if err := runCmd(os.Args[2:], ""); err != nil {
			fmt.Fprintf(os.Stderr, "[netinspect] error: %v\n", err)
			os.Exit(1)
		}
	case "__agent":
		if err := agentCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[netinspect] agent error: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runCmd(args []string, defaultMode string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	mode := fs.String("mode", defaultMode, "interception mode: preload|ptrace|netns|observe")
	listen := fs.String("listen", "127.0.0.1:17890", "dashboard listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode == "" {
		return fmt.Errorf("--mode is required (preload|ptrace|netns|observe)")
	}
	cmd := fs.Args()
	if len(cmd) == 0 {
		return fmt.Errorf("no command given; usage: netinspect run --mode %s -- <command> [args...]", *mode)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return session.Run(session.Config{
		Mode:    strings.ToLower(*mode),
		Listen:  *listen,
		Command: cmd,
		ExePath: exe,
	})
}

func agentCmd(args []string) error {
	fs := flag.NewFlagSet("__agent", flag.ContinueOnError)
	sid := fs.String("sid", "", "")
	command := fs.String("command", "", "")
	proxyPort := fs.Int("proxy-port", 0, "")
	dashPort := fs.Int("dash-port", 0, "")
	nsIP := fs.String("ns-ip", "", "")
	upstreamDNS := fs.String("upstream-dns", "8.8.8.8", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sid == "" || *proxyPort == 0 || *dashPort == 0 || *nsIP == "" {
		return fmt.Errorf("__agent: missing required flags")
	}
	return netns.RunAgent(*sid, *command, *proxyPort, *dashPort, *nsIP, *upstreamDNS)
}
