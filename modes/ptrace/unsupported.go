//go:build linux && !amd64

package ptrace

import "fmt"

func Run(cmd string, args []string, sockPath string, proxyPort, dashPort int) error {
	return fmt.Errorf("ptrace mode only supports x86_64")
}

type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }
func (e *ExitError) ExitCode() int { return e.Code }
