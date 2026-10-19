package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNetnsRequestsSudoWithAbsolutePaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged invocation")
	}
	if os.Getenv("NETINSPECT_TEST_SUDO_CHILD") == "1" {
		err := runCmd([]string{"--mode", "netns", "--open-browser=false", "--memory-mb", "64", "--", "user-target", "argument with spaces"}, "preload")
		t.Fatalf("sudo exec returned: %v", err)
	}
	dir := t.TempDir()
	capture := filepath.Join(dir, "arguments")
	t.Setenv("NETINSPECT_TEST_ARGS", capture)
	t.Setenv("NETINSPECT_TEST_PID", filepath.Join(dir, "sudo-pid"))
	sudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$NETINSPECT_TEST_PID\"\nprintf '%s\\n' \"$@\" > \"$NETINSPECT_TEST_ARGS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "user-target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	// Use a distinct executable inode so the test runner is not an outer session.
	original, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(dir, "netinspect-test")
	if err := os.WriteFile(childPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(childPath, "-test.run=^TestNetnsRequestsSudoWithAbsolutePaths$")
	child.Env = append(os.Environ(), "NETINSPECT_TEST_SUDO_CHILD=1")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("sudo handoff: %v: %s", err, output)
	}
	pid, err := os.ReadFile(filepath.Join(dir, "sudo-pid"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pid)) != strconv.Itoa(child.Process.Pid) {
		t.Fatal("sudo must replace the launcher process, not run as its child")
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(args) < 4 || args[0] != "--" || args[1] != childPath || args[len(args)-2] != target || args[len(args)-1] != "argument with spaces" {
		t.Fatalf("sudo arguments did not preserve executable paths or target arguments: %q", args)
	}
	if !strings.Contains(string(data), "--memory-mb\n64\n") {
		t.Fatal("effective configuration lost")
	}
}
