package session

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearProxyEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"LD_PRELOAD", "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NETINSPECT_HTTP_PROXY", "NETINSPECT_SOCKS5_PROXY"} {
		t.Setenv(key, "")
	}
}

func TestSandboxModeDiagnostics(t *testing.T) {
	clearProxyEnvironment(t)
	for _, mode := range []string{"preload", "ptrace", "netns", "observe"} {
		warnings := strings.Join(compatibilityWarnings(mode, []string{"/usr/bin/flatpak", "run", "example.App"}), " ")
		if !strings.Contains(warnings, "sandbox") && !strings.Contains(warnings, "namespace") {
			t.Fatalf("missing %s warning: %s", mode, warnings)
		}
	}
	if warnings := compatibilityWarnings("preload", []string{"/bin/true"}); len(warnings) != 0 {
		t.Fatalf("normal dynamic binary misclassified: %v", warnings)
	}
}

func TestProxyEnvironmentDiagnosticsDoNotExposeCredentials(t *testing.T) {
	clearProxyEnvironment(t)
	t.Setenv("https_proxy", "http://secret-user:secret-password@127.0.0.1:7890")
	warnings := strings.Join(compatibilityWarnings("netns", []string{"/bin/true"}), " ")
	if !strings.Contains(warnings, "loopback") || strings.Contains(warnings, "secret") {
		t.Fatalf("bad warning: %s", warnings)
	}
	t.Setenv("https_proxy", "http://192.0.2.1:7890")
	if warnings := compatibilityWarnings("netns", []string{"/bin/true"}); len(warnings) != 0 {
		t.Fatalf("non-loopback proxy misclassified: %v", warnings)
	}
	t.Setenv("LD_PRELOAD", "/private/secret-injection.so")
	warnings = strings.Join(compatibilityWarnings("preload", []string{"/bin/true"}), " ")
	if !strings.Contains(warnings, "LD_PRELOAD") || strings.Contains(warnings, "secret-injection") {
		t.Fatalf("bad inherited preload warning: %s", warnings)
	}
}

func TestStaticAndPrivilegedExecutableDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "static-elf")
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(header[16:], 2)
	binary.LittleEndian.PutUint16(header[18:], 62)
	binary.LittleEndian.PutUint32(header[20:], 1)
	binary.LittleEndian.PutUint16(header[52:], 64)
	binary.LittleEndian.PutUint16(header[54:], 56)
	binary.LittleEndian.PutUint16(header[58:], 64)
	if err := os.WriteFile(path, header, 0755); err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(executableWarnings(path), " ")
	if !strings.Contains(warnings, "static linking") {
		t.Fatalf("missing static warning: %s", warnings)
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if warnings := executableWarnings(script); len(warnings) != 0 {
		t.Fatalf("script misclassified as static: %v", warnings)
	}
	if err := os.Chmod(script, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	warnings = strings.Join(executableWarnings(script), " ")
	if !strings.Contains(warnings, "setuid") {
		t.Fatalf("missing setuid warning: %s", warnings)
	}
}
