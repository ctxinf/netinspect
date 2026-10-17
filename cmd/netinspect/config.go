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

	"netinspect/internal/session"
)

type fileConfig struct {
	Mode      *string `json:"mode"`
	Listen    *string `json:"listen"`
	Port      *int    `json:"port"`
	KeepAlive *string `json:"keep_alive"`
}

func parseRun(args []string, defaultMode string) (session.Config, error) {
	cfg := session.Config{Mode: defaultMode, Listen: "127.0.0.1:17890", KeepAlive: 30 * time.Minute}
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
				return cfg, fmt.Errorf("使用 run 或 netinspect 选项时，目标命令前必须添加 --（例如 netinspect --mode observe -- %s）", a)
			}
			break
		}
		requireSeparator = true
		if a == "--help" || a == "-h" {
			fmt.Print(usage)
			return cfg, flag.ErrHelp
		}
		key, value, equal := strings.Cut(a, "=")
		switch key {
		case "--config", "--mode", "--listen", "--port", "--keep-alive":
			if !equal {
				i++
				if i >= len(args) {
					return cfg, fmt.Errorf("%s 需要一个值", key)
				}
				value = args[i]
			}
			if key == "--config" {
				explicit = value
				if value == "" {
					return cfg, fmt.Errorf("--config 不能为空")
				}
			}
		default:
			return cfg, fmt.Errorf("未知选项 %s；查看 netinspect --help", key)
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
				err = fmt.Errorf("配置必须只有一个 JSON 对象")
			}
		}
		f.Close()
		if err != nil {
			return cfg, fmt.Errorf("配置 %s: %w", path, err)
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
				return cfg, fmt.Errorf("配置 %s: %w", path, err)
			}
		}
	}
	fs := flag.NewFlagSet("netinspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { fmt.Print(usage) }
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "")
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
	if cfg.KeepAlive < 0 {
		return cfg, fmt.Errorf("keep-alive 不能为负数")
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	switch cfg.Mode {
	case "preload", "ptrace", "netns", "observe":
	default:
		return cfg, fmt.Errorf("无效 mode %q", cfg.Mode)
	}
	host, p, err := net.SplitHostPort(cfg.Listen)
	_ = host
	if err != nil {
		return cfg, fmt.Errorf("无效 listen %q", cfg.Listen)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return cfg, fmt.Errorf("无效端口 %q", p)
	}
	cfg.Command = fs.Args()
	if len(cfg.Command) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cfg.Command = []string{shell}
	}
	cfg.ExePath, err = os.Executable()
	return cfg, err
}

func withPort(listen string, port int) (string, error) {
	if port < 0 || port > 65535 {
		return "", fmt.Errorf("端口必须在 0–65535 之间")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func stopCmd(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	url := fs.String("url", "", "面板 URL")
	token := fs.String("token", "", "实例控制令牌")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *token == "" || fs.NArg() != 0 {
		return fmt.Errorf("用法: netinspect stop --url URL --token TOKEN")
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
		return fmt.Errorf("关闭失败: %s", res.Status)
	}
	fmt.Println("  ✓ 面板已关闭")
	return nil
}
