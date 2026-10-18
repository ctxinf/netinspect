package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"netinspect/internal/version"
)

const usage = `Monitor a Linux process and its network connections.

Usage:
  netinspect <COMMAND> [ARGS...]
  netinspect [OPTIONS] -- <COMMAND> [ARGS...]
  netinspect run [OPTIONS] -- <COMMAND> [ARGS...]
  netinspect stop --url <URL> --token <TOKEN>

Commands:
  run                 Run and monitor a command (default)
  stop                Shut down a running dashboard
  skills              Read bundled agent guidance (list, get core [--full])
  init-config         Create default user configuration
  version             Print version information
  help                Print this help

Options:
      --mode <MODE>            Capture mode: preload, ptrace, netns, observe [default: preload]
      --user <USER>            Target username or UID for netns [default: original sudo user]
      --listen <ADDRESS>       Dashboard address [default: 127.0.0.1:17890]
      --port <PORT>            Override the dashboard port; busy ports increment automatically
      --keep-alive <TIME>      Keep dashboard after target exits; 0 disables [default: 30m]
      --open-browser           Open dashboard automatically [default: true; use =false to disable]
      --memory-mb <MB>         Record storage budget in MiB [default: 128]
      --upstream-proxy <URL>   TCP via http(s):// or socks5(h)://; optional user:password
      --config <FILE>          Load only this JSON configuration file
      --version                Print version information
  -h, --help                   Print help

Shell alias:
  alias ni=netinspect
  Add this line to ~/.bashrc or ~/.zshrc, then use: ni curl -I https://example.com
`

func printHelpText(text string) {
	_, noColor := os.LookupEnv("NO_COLOR")
	_, terminalErr := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	if !noColor && os.Getenv("TERM") != "dumb" && terminalErr == nil {
		for _, heading := range []string{"Usage:", "Commands:", "Options:", "Shell alias:"} {
			text = strings.ReplaceAll(text, heading, "\x1b[1;32m"+heading+"\x1b[0m")
		}
	}
	fmt.Print(text)
}

func printHelp() {
	fmt.Printf("netinspect %s\n\n", version.Current().Version)
	printHelpText(usage)
	if path, err := userConfigPath(); err == nil {
		fmt.Printf("\nUser config: %s [%s]\n", path, configStatus(path))
	}
	if path, err := filepath.Abs(".netinspect.json"); err == nil {
		fmt.Printf("Local config: %s [%s]\n", path, configStatus(path))
	}
}

func userConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netinspect", "config.json"), nil
}

func configStatus(path string) string {
	_, err := os.Stat(path)
	if err == nil {
		return "exists"
	}
	if os.IsNotExist(err) {
		return "missing"
	}
	return "unavailable: " + err.Error()
}

func initConfigCmd(args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		printHelpText("Create the default user configuration. Existing files are never overwritten.\n\nUsage:\n  netinspect init-config\n\nOptions:\n  -h, --help  Print help\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: netinspect init-config")
	}
	path, err := userConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create config %s: %w", path, err)
	}
	_, writeErr := f.WriteString(`{
  "mode": "preload",
  "listen": "127.0.0.1:17890",
  "keep_alive": "30m",
  "open_browser": true,
  "memory_mb": 128,
  "upstream_proxy": null
}
`)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Printf("Created configuration: %s\n", path)
	return nil
}

func printStopHelp() {
	printHelpText(`Shut down a dashboard after its target command has exited.

Usage:
  netinspect stop --url <URL> --token <TOKEN>

Options:
      --url <URL>              Dashboard URL printed by the session
      --token <TOKEN>          Session control token printed after the target exits
  -h, --help           Print help
`)
}

func helpCmd(args []string) error {
	if len(args) == 0 {
		printHelp()
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: netinspect help [COMMAND]")
	}
	switch args[0] {
	case "run":
		printHelp()
	case "stop":
		printStopHelp()
	case "skills":
		return skillsCmd(nil)
	case "init-config":
		return initConfigCmd([]string{"--help"})
	case "version":
		printHelpText("Print version information.\n\nUsage:\n  netinspect version\n")
	case "help":
		printHelpText("Usage:\n  netinspect help [COMMAND]\n")
	default:
		return fmt.Errorf("unknown help command %q", args[0])
	}
	return nil
}
