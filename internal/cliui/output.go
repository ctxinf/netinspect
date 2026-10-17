// Package cliui formats netinspect diagnostics without touching target output.
package cliui

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func colorEnabled() bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return false
	}
	_, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS)
	return err == nil
}
func write(color, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if colorEnabled() {
		message = "\x1b[" + color + "m" + message + "\x1b[0m"
	}
	fmt.Fprint(os.Stderr, message)
}
func Printf(format string, args ...any) { write("36", format, args...) }
func Errorf(format string, args ...any) { write("31", format, args...) }

// TargetOutput brackets the target's inherited stdout/stderr. The returned
// closer is idempotent, including when process startup fails.
func TargetOutput() func() {
	Printf("\n──────────────── Target output ────────────────\n")
	ended := false
	return func() {
		if !ended {
			ended = true
			Printf("\n──────────────── End of target output ────────────────\n")
		}
	}
}
