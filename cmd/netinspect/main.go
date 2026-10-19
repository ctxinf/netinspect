package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"netinspect/internal/cliui"
	"netinspect/internal/session"
	"netinspect/internal/version"
	"netinspect/modes/netns"
)

func main() {
	args := os.Args[1:]
	var err error
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Println("netinspect " + version.Current().Version)
			return
		case "help":
			err = helpCmd(args[1:])
		case "-h", "--help":
			printHelp()
			return
		case "__agent":
			err = agentCmd(args[1:])
		case "skills":
			err = skillsCmd(args[1:])
		case "init-config":
			err = initConfigCmd(args[1:])
		case "stop":
			err = stopCmd(args[1:])
		default:
			err = runCmd(args, "preload")
		}
	} else {
		printHelp()
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		cliui.Errorf("\n✕ netinspect: %v\n", err)
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
	if cfg.Mode == "netns" && os.Geteuid() != 0 {
		if err := session.CheckNesting(); err != nil {
			return err
		}
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("netns requires sudo: %w", err)
		}
		// Reuse the absolute executable path: sudo's secure_path excludes user installations.
		elevated := []string{"--", cfg.ExePath}
		for _, path := range cfg.ConfigPaths {
			elevated = append(elevated, "--config", path)
		}
		elevated = append(elevated, "--mode", cfg.Mode, "--listen", cfg.Listen,
			"--memory-mb", strconv.FormatInt(cfg.MemoryMB, 10), "--keep-alive", cfg.KeepAlive.String(),
			"--open-browser="+strconv.FormatBool(cfg.OpenBrowser), "--upstream-proxy", cfg.UpstreamProxy)
		if cfg.TargetUser != "" {
			elevated = append(elevated, "--user", cfg.TargetUser)
		}
		elevated = append(elevated, "--")
		target := append([]string(nil), cfg.Command...)
		if len(target) > 0 {
			if resolved, err := exec.LookPath(target[0]); err == nil {
				target[0] = resolved
			}
		}
		elevated = append(elevated, target...)
		cliui.Printf("· netns requires administrator privileges; requesting sudo authentication\n")
		// Replace this process so the elevated instance has no netinspect launcher
		// ancestor. Real outer sessions are checked above, before sudo filters env.
		return syscall.Exec(sudo, append([]string{sudo}, elevated...), os.Environ())
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
	memoryMB := fs.Int64("memory-mb", 128, "")
	upstreamDNS := fs.String("upstream-dns", "8.8.8.8", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sid == "" || *proxyPort == 0 || *dashPort == 0 || *nsIP == "" {
		return fmt.Errorf("__agent: missing required flags")
	}
	return netns.RunAgent(*sid, *command, *proxyPort, *dashPort, *nsIP, *upstreamDNS, *token, *memoryMB<<20)
}
