package session

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"netinspect/internal/cliui"
)

func tracerPID(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(value))
			return n
		}
	}
	return 0
}

func ptraceWrapper(command []string) bool {
	if len(command) == 0 {
		return false
	}
	switch filepath.Base(command[0]) {
	case "graftcp", "graftcp-local", "strace", "ltrace", "gdb", "rr":
		return true
	}
	return false
}

func warnPtraceStartup(command []string) {
	if ptraceWrapper(command) {
		cliui.Printf("! WARN: ptrace mode detected tracer wrapper %s; a thread cannot have two ptrace tracers. Try netns or observe.\n", filepath.Base(command[0]))
	}
	status, _ := os.ReadFile("/proc/self/status")
	if pid := tracerPID(string(status)); pid > 0 {
		cliui.Printf("! WARN: netinspect is already traced by PID %d; ptrace mode may conflict. Try netns or observe.\n", pid)
	}
}

func warnDesktopHandoff(command []string) {
	if len(command) == 0 || filepath.Base(command[0]) != "gnome-software" {
		return
	}
	cliui.Printf("! WARN: GNOME Software is a D-Bus single-instance application; the launcher may hand off to an existing instance and exit. To capture a new instance, first run gnome-software --quit yourself. Traffic from system services such as PackageKit is outside the target process tree.\n")
}
