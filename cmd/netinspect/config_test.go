package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func cleanConfig(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	t.Setenv("SHELL", "/bin/sh")
}
func TestCommandParsing(t *testing.T) {
	cleanConfig(t)
	for _, tt := range []struct {
		args, want []string
		mode       string
	}{
		{nil, []string{"/bin/sh"}, "preload"},
		{[]string{"run"}, []string{"/bin/sh"}, "preload"},
		{[]string{"run", "--", "curl", "--help"}, []string{"curl", "--help"}, "preload"},
		{[]string{"--mode", "observe"}, []string{"/bin/sh"}, "observe"},
		{[]string{"curl", "--help", "--mode", "observe"}, []string{"curl", "--help", "--mode", "observe"}, "preload"},
		{[]string{"--mode", "observe", "--", "sh", "-c", "exit 7"}, []string{"sh", "-c", "exit 7"}, "observe"},
		{[]string{"--", "--strange-command", "-h"}, []string{"--strange-command", "-h"}, "preload"},
	} {
		cfg, err := parseRun(tt.args, "preload")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Mode != tt.mode || !reflect.DeepEqual(cfg.Command, tt.want) || cfg.KeepAlive != 30*time.Minute {
			t.Fatalf("args=%q cfg=%+v", tt.args, cfg)
		}
	}
}
func TestConfigPrecedence(t *testing.T) {
	cleanConfig(t)
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "netinspect")
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"mode":"observe","port":19000,"keep_alive":"1m"}`), 0600)
	os.WriteFile(".netinspect.json", []byte(`{"port":19001,"keep_alive":"2m"}`), 0600)
	cfg, err := parseRun([]string{"--port", "19002", "--", "true"}, "preload")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" || cfg.Listen != "127.0.0.1:19002" || cfg.KeepAlive != 2*time.Minute {
		t.Fatalf("%+v", cfg)
	}
	os.WriteFile("explicit.json", []byte(`{"mode":"ptrace"}`), 0600)
	cfg, err = parseRun([]string{"--config=explicit.json", "--", "true"}, "preload")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "ptrace" || cfg.Listen != "127.0.0.1:17890" {
		t.Fatalf("%+v", cfg)
	}
}
func TestInvalidOptions(t *testing.T) {
	cleanConfig(t)
	for _, args := range [][]string{{"--config", "missing"}, {"--keep-alive", "-1m"}, {"--port", "65536"}, {"--mode", "bad"}, {"--listen", "bad"}, {"--wat"}} {
		if _, err := parseRun(args, "preload"); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	os.WriteFile("bad.json", []byte(`{"keep_alve":"1m"}`), 0600)
	if _, err := parseRun([]string{"--config", "bad.json"}, "preload"); err == nil {
		t.Fatal("accepted unknown config key")
	}
}

func TestMissingCommandSeparator(t *testing.T) {
	cleanConfig(t)
	for _, args := range [][]string{
		{"run", "curl"},
		{"run", "--mode", "observe", "curl"},
		{"--mode", "observe", "curl", "--"},
		{"--keep-alive=0", "true"},
		{"--listen", "127.0.0.1:17890", "curl"},
		{"--port", "19000", "curl"},
		{"--config", "settings.json", "curl"},
	} {
		if _, err := parseRun(args, "preload"); err == nil || !strings.Contains(err.Error(), "必须添加 --") {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
}
