package main

import (
	"errors"
	"flag"
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
		{[]string{"run", "--", "curl", "--help"}, []string{"curl", "--help"}, "preload"},
		{[]string{"--mode", "observe", "--", "true"}, []string{"true"}, "observe"},
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
		if _, err := parseRun(args, "preload"); err == nil || !strings.Contains(err.Error(), "add -- before the target command") {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
}

func TestMemoryBudgetConfig(t *testing.T) {
	cleanConfig(t)
	cfg, err := parseRun([]string{"--", "true"}, "preload")
	if err != nil || cfg.MemoryMB != 128 {
		t.Fatalf("default budget: %+v %v", cfg, err)
	}
	os.WriteFile(".netinspect.json", []byte(`{"memory_mb":32}`), 0600)
	cfg, err = parseRun([]string{"--", "true"}, "preload")
	if err != nil || cfg.MemoryMB != 32 {
		t.Fatalf("file budget: %+v %v", cfg, err)
	}
	cfg, err = parseRun([]string{"--memory-mb", "64", "--", "true"}, "preload")
	if err != nil || cfg.MemoryMB != 64 {
		t.Fatalf("CLI budget: %+v %v", cfg, err)
	}
	for _, v := range []string{"0", "-1", "1048577", "garbage"} {
		if _, err = parseRun([]string{"--memory-mb", v, "--", "true"}, "preload"); err == nil {
			t.Fatalf("accepted memory budget %s", v)
		}
	}
}

func TestOpenBrowserConfiguration(t *testing.T) {
	cleanConfig(t)
	cfg, err := parseRun([]string{"--", "true"}, "preload")
	if err != nil || !cfg.OpenBrowser {
		t.Fatalf("browser should default on: %+v %v", cfg, err)
	}
	if err := os.WriteFile(".netinspect.json", []byte(`{"open_browser":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = parseRun([]string{"--", "true"}, "preload")
	if err != nil || cfg.OpenBrowser {
		t.Fatal("file setting ignored")
	}
	cfg, err = parseRun([]string{"--open-browser", "--", "true"}, "preload")
	if err != nil || !cfg.OpenBrowser {
		t.Fatal("CLI override ignored")
	}
	cfg, err = parseRun([]string{"--open-browser=false", "--", "true"}, "preload")
	if err != nil || cfg.OpenBrowser {
		t.Fatal("CLI disable ignored")
	}
}

func TestMissingCommandShowsHelpAndModeErrors(t *testing.T) {
	cleanConfig(t)
	for _, args := range [][]string{nil, {"run"}, {"--mode", "observe"}} {
		if _, err := parseRun(args, "preload"); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("args=%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"--mode"}, {"--mode="}, {"--mode", "--"}, {"--mode", "rplace"}} {
		_, err := parseRun(args, "preload")
		if err == nil || !strings.Contains(err.Error(), modeHelp) {
			t.Fatalf("missing mode help: %v", err)
		}
	}
}

func TestNetnsTargetUserOption(t *testing.T) {
	cleanConfig(t)
	cfg, err := parseRun([]string{"--mode", "netns", "--user", "1000", "--", "id"}, "preload")
	if err != nil || cfg.TargetUser != "1000" {
		t.Fatalf("user option: %+v %v", cfg, err)
	}
	if _, err := parseRun([]string{"--user", "1000", "--", "id"}, "preload"); err == nil {
		t.Fatal("user option accepted outside netns")
	}
	if err := os.WriteFile(".netinspect.json", []byte(`{"mode":"netns","user":"root"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = parseRun([]string{"--", "id"}, "preload")
	if err != nil || cfg.TargetUser != "root" {
		t.Fatalf("file user: %+v %v", cfg, err)
	}
}

func TestInitConfig(t *testing.T) {
	cleanConfig(t)
	if err := initConfigCmd(nil); err != nil {
		t.Fatal(err)
	}
	path, err := userConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initConfigCmd(nil); err == nil {
		t.Fatal("overwrote existing config")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config changed")
	}
	cfg, err := parseRun([]string{"true"}, "preload")
	if err != nil || cfg.Mode != "preload" || cfg.MemoryMB != 128 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if configStatus(path) != "exists" || configStatus(path+".missing") != "missing" {
		t.Fatal("incorrect status")
	}
}

func TestUpstreamConfig(t *testing.T) {
	cleanConfig(t)
	if err := os.WriteFile(".netinspect.json", []byte(`{"upstream_proxy":"http://127.0.0.1:3128"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseRun([]string{"true"}, "preload")
	if err != nil || cfg.UpstreamProxy != "http://127.0.0.1:3128" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = parseRun([]string{"--upstream-proxy", "socks5h://127.0.0.1:1080", "--", "true"}, "preload")
	if err != nil || cfg.UpstreamProxy != "socks5h://127.0.0.1:1080" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, args := range [][]string{{"--mode", "observe", "--", "true"}, {"--upstream-proxy", "ftp://host", "--", "true"}} {
		if _, err := parseRun(args, "preload"); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
