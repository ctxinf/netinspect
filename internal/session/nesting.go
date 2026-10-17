package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const activeSessionEnv = "NETINSPECT_ACTIVE_SESSION"

// Refuse nested capture even through shell wrappers, aliases, or renamed binaries.
// The environment marker covers descendants; /proc also covers wrappers that clear it.
func checkNesting() error {
	if os.Getenv(activeSessionEnv) != "" || os.Getenv("NETINSPECT_SOCK_PATH") != "" {
		return fmt.Errorf("nested netinspect sessions are not supported; run the command outside the active session")
	}
	self, _ := os.Stat("/proc/self/exe")
	for pid, depth := os.Getppid(), 0; pid > 1 && depth < 256; depth++ {
		root := filepath.Join("/proc", strconv.Itoa(pid))
		ancestor, err := os.Stat(filepath.Join(root, "exe"))
		if err == nil && self != nil && os.SameFile(self, ancestor) {
			return fmt.Errorf("nested netinspect session detected (ancestor PID %d)", pid)
		}
		status, err := os.ReadFile(filepath.Join(root, "status"))
		if err != nil {
			break
		}
		parent := 0
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
				break
			}
		}
		if parent == pid {
			break
		}
		pid = parent
	}
	return nil
}
