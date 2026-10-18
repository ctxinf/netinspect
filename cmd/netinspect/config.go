package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netinspect/internal/proxy"
	"netinspect/internal/session"
)

const modeHelp = "--mode MODE  preload (default)| ptrace | netns | observe"

type fileConfig struct {
	UpstreamProxy *string `json:"upstream_proxy"`
	TargetUser    *string `json:"user"`
	OpenBrowser   *bool   `json:"open_browser"`
	Mode          *string `json:"mode"`
	Listen        *string `json:"listen"`
	Port          *int    `json:"port"`
	KeepAlive     *string `json:"keep_alive"`
	MemoryMB      *int64  `json:"memory_mb"`
}

func parseRun(args []string, defaultMode string) (session.Config, error) {
	cfg := session.Config{Mode: defaultMode, Listen: "127.0.0.1:17890", KeepAlive: 30 * time.Minute, MemoryMB: 128, OpenBrowser: true}
	// Only the bare command shortcut may omit the separator.
	requireSeparator := false
	if len(args) > 0 && args[0] == "run" {
		requireSeparator = true
		args = args[1:]
	}
	// Inspect only the option prefix; target arguments must remain untouched.
	explicit := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			if requireSeparator {
				return cfg, fmt.Errorf("with run or netinspect options, add -- before the target command (example: netinspect --mode observe -- %s)", a)
			}
			break
		}
		requireSeparator = true
		if a == "--help" || a == "-h" {
			printHelp()
			return cfg, flag.ErrHelp
		}
		key, value, equal := strings.Cut(a, "=")
		switch key {
		case "--open-browser":
			// Boolean flags use --open-browser or --open-browser=false.

		case "--config", "--mode", "--listen", "--port", "--keep-alive", "--memory-mb", "--user", "--upstream-proxy":
			if !equal {
				i++
				if i >= len(args) {
					if key == "--mode" {
						return cfg, fmt.Errorf("--mode requires a value\n%s", modeHelp)
					}
					return cfg, fmt.Errorf("%s requires a value", key)
				}
				value = args[i]
			}
			if key == "--mode" && (value == "" || strings.HasPrefix(value, "--")) {
				return cfg, fmt.Errorf("--mode requires a value\n%s", modeHelp)
			}
			if key == "--config" {
				explicit = value
				if value == "" {
					return cfg, fmt.Errorf("--config cannot be empty")
				}
			}
		default:
			return cfg, fmt.Errorf("unknown option %s; see netinspect --help", key)
		}
	}
	paths := []string{}
	if explicit != "" {
		paths = append(paths, explicit)
	} else {
		dir, err := os.UserConfigDir()
		if err == nil {
			paths = append(paths, filepath.Join(dir, "netinspect", "config.json"))
		}
		paths = append(paths, ".netinspect.json")
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if os.IsNotExist(err) && explicit == "" {
			continue
		}
		if err != nil {
			return cfg, err
		}
		var fc fileConfig
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		err = dec.Decode(&fc)
		if err == nil {
			var extra any
			if dec.Decode(&extra) != io.EOF {
				err = fmt.Errorf("configuration must contain exactly one JSON object")
			}
		}
		f.Close()
		if err != nil {
			return cfg, fmt.Errorf("config %s: %w", path, err)
		}
		if fc.UpstreamProxy != nil {
			cfg.UpstreamProxy = *fc.UpstreamProxy
		}
		if fc.TargetUser != nil {
			cfg.TargetUser = *fc.TargetUser
		}
		if fc.OpenBrowser != nil {
			cfg.OpenBrowser = *fc.OpenBrowser
		}
		if fc.MemoryMB != nil {
			cfg.MemoryMB = *fc.MemoryMB
		}
		if fc.Mode != nil {
			cfg.Mode = *fc.Mode
		}
		if fc.Listen != nil {
			cfg.Listen = *fc.Listen
		}
		if fc.Port != nil {
			cfg.Listen, err = withPort(cfg.Listen, *fc.Port)
			if err != nil {
				return cfg, err
			}
		}
		if fc.KeepAlive != nil {
			cfg.KeepAlive, err = time.ParseDuration(*fc.KeepAlive)
			if err != nil {
				return cfg, fmt.Errorf("config %s: %w", path, err)
			}
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return cfg, fmt.Errorf("config %s: %w", path, err)
		}
		cfg.ConfigPaths = append(cfg.ConfigPaths, absPath)
	}
	fs := flag.NewFlagSet("netinspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { printHelp() }
	fs.StringVar(&cfg.UpstreamProxy, "upstream-proxy", cfg.UpstreamProxy, "")
	fs.StringVar(&cfg.TargetUser, "user", cfg.TargetUser, "")
	fs.BoolVar(&cfg.OpenBrowser, "open-browser", cfg.OpenBrowser, "")
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "")
	fs.Int64Var(&cfg.MemoryMB, "memory-mb", cfg.MemoryMB, "")
	fs.DurationVar(&cfg.KeepAlive, "keep-alive", cfg.KeepAlive, "")
	var configPath string
	fs.StringVar(&configPath, "config", explicit, "")
	port := fs.Int("port", -1, "")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	var err error
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			cfg.Listen, err = withPort(cfg.Listen, *port)
		}
	})
	if err != nil {
		return cfg, err
	}
	if cfg.MemoryMB < 1 || cfg.MemoryMB > 1048576 {
		return cfg, fmt.Errorf("memory-mb must be between 1 and 1048576")
	}
	if cfg.KeepAlive < 0 {
		return cfg, fmt.Errorf("keep-alive cannot be negative")
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	switch cfg.Mode {
	case "preload", "ptrace", "netns", "observe":
	default:
		return cfg, fmt.Errorf("invalid mode %q\n%s", cfg.Mode, modeHelp)
	}
	if cfg.TargetUser != "" && cfg.Mode != "netns" {
		return cfg, fmt.Errorf("--user is only supported in netns mode")
	}
	if cfg.Mode == "observe" && cfg.UpstreamProxy != "" {
		return cfg, fmt.Errorf("--upstream-proxy is not supported in observe mode")
	}
	if _, err := proxy.NewUpstream(cfg.UpstreamProxy, false); err != nil {
		return cfg, err
	}
	host, p, err := net.SplitHostPort(cfg.Listen)
	_ = host
	if err != nil {
		return cfg, fmt.Errorf("invalid listen address %q", cfg.Listen)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return cfg, fmt.Errorf("invalid port %q", p)
	}
	cfg.Command = fs.Args()
	if len(cfg.Command) == 0 {
		printHelp()
		return cfg, flag.ErrHelp
	}
	cfg.ExePath, err = os.Executable()
	return cfg, err
}

func withPort(listen string, port int) (string, error) {
	if port < 0 || port > 65535 {
		return "", fmt.Errorf("port must be between 0 and 65535")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func stopCmd(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = printStopHelp
	url := fs.String("url", "", "Dashboard URL")
	token := fs.String("token", "", "Session control token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *token == "" || fs.NArg() != 0 {
		return fmt.Errorf("Usage: netinspect stop --url URL --token TOKEN")
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*url, "/")+"/api/shutdown", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("shutdown failed: %s", res.Status)
	}
	fmt.Println("✓ Dashboard stopped")
	return nil
}
