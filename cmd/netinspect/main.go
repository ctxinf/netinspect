package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"netinspect/internal/session"
	"netinspect/modes/netns"
)

const usage = `netinspect · Linux 进程网络监控

用法
  netinspect
  netinspect 命令 [参数...]                    全默认快捷形式
  netinspect [选项] -- 命令 [参数...]
  netinspect run [选项] -- 命令 [参数...]
  netinspect stop --url URL --token TOKEN

默认启动交互 Shell，使用 preload 模式。只有无子命令、无选项的快捷形式可省略 --。
使用 run 或选项并指定目标命令时，必须通过 -- 分隔。目标参数原样传递。

选项
  --mode MODE       preload（默认）| ptrace | netns | observe
  --listen ADDRESS  面板地址（默认 127.0.0.1:17890），占用时端口递增
  --port PORT       覆盖面板端口
  --keep-alive TIME 命令结束后面板保留时间（默认 30m，0 表示立即关闭）
  --config FILE     显式指定 JSON 配置文件
  -h, --help        显示帮助

示例
  netinspect
  netinspect curl -I https://example.com
  netinspect --mode observe --keep-alive 10m -- python app.py
  netinspect run -- ./my-command --help

配置
  $XDG_CONFIG_HOME/netinspect/config.json（默认 ~/.config/netinspect/config.json）
  当前目录 .netinspect.json；--config 替代自动发现。命令行优先。
  {"mode":"preload","listen":"127.0.0.1:17890","keep_alive":"30m"}

仅记录连接元数据，不解密内容。数据保留至面板关闭。
`

func main() {
	args := os.Args[1:]
	var err error
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			fmt.Print(usage)
			return
		case "__agent":
			err = agentCmd(args[1:])
		case "stop":
			err = stopCmd(args[1:])
		default:
			err = runCmd(args, "preload")
		}
	} else {
		err = runCmd(args, "preload")
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  ✕ netinspect: %v\n", err)
		var e *exec.ExitError
		if errors.As(err, &e) {
			code := e.ExitCode()
			if ws, ok := e.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
			os.Exit(code)
		}
		if e, ok := err.(interface{ ExitCode() int }); ok {
			os.Exit(e.ExitCode())
		}
		os.Exit(1)
	}
}

func runCmd(args []string, defaultMode string) error {
	cfg, err := parseRun(args, defaultMode)
	if err != nil {
		return err
	}
	return session.Run(cfg)
}

func agentCmd(args []string) error {
	fs := flag.NewFlagSet("__agent", flag.ContinueOnError)
	sid := fs.String("sid", "", "")
	command := fs.String("command", "", "")
	proxyPort := fs.Int("proxy-port", 0, "")
	dashPort := fs.Int("dash-port", 0, "")
	nsIP := fs.String("ns-ip", "", "")
	token := fs.String("control-token", "", "")
	upstreamDNS := fs.String("upstream-dns", "8.8.8.8", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sid == "" || *proxyPort == 0 || *dashPort == 0 || *nsIP == "" {
		return fmt.Errorf("__agent: missing required flags")
	}
	return netns.RunAgent(*sid, *command, *proxyPort, *dashPort, *nsIP, *upstreamDNS, *token)
}
