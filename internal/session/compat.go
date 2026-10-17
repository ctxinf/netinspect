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
		cliui.Printf("! WARN: ptrace 模式检测到跟踪器套壳 %s，同一线程不能同时被两个 ptrace 跟踪器控制；建议使用 netns 或 observe。\n", filepath.Base(command[0]))
	}
	status, _ := os.ReadFile("/proc/self/status")
	if pid := tracerPID(string(status)); pid > 0 {
		cliui.Printf("! WARN: netinspect 已被 PID %d 跟踪，ptrace 模式可能冲突；建议使用 netns 或 observe。\n", pid)
	}
}

func warnDesktopHandoff(command []string) {
	if len(command) == 0 || filepath.Base(command[0]) != "gnome-software" {
		return
	}
	cliui.Printf("! WARN: GNOME Software 是 D-Bus 单实例应用，启动命令可能转交已有实例后退出；如需捕获新实例，请先自行运行 gnome-software --quit。PackageKit 等系统服务的流量不属于该目标进程树。\n")
}
