// Package ptrace implements the ptrace interception mode: it traces the
// target process tree and rewrites connect() syscalls for TCP sockets to
// redirect them into the proxy core's transparent frontend. Original
// destinations are reported over the side-channel so the proxy can attribute
// and dial them. x86_64 Linux only. All original code.
package ptrace

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"netinspect/internal/cliui"
	"netinspect/internal/sidechan"
)

const (
	sysConnect = 42 // __NR_connect on x86_64
)

// pendingConnect remembers a rewritten connect until syscall exit.
type pendingConnect struct {
	fd   int
	ip   string
	port int
}

type tracee struct {
	inSyscall bool
	pending   pendingConnect
}

// Run traces cmd (with args) and all its descendants, rewriting TCP
// connect() calls to 127.0.0.1:proxyPort (::1 for AF_INET6). It returns when
// the whole traced tree has exited.
func Run(cmd string, args []string, sockPath string, proxyPort, dashPort int) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("ptrace mode only supports x86_64")
	}
	runtime.LockOSThread()

	argv := append([]string{cmd}, args...)
	attr := &syscall.ProcAttr{
		Dir:   "",
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	}
	if !strings.Contains(cmd, "/") {
		if p, err := exec.LookPath(cmd); err == nil {
			cmd = p
			argv[0] = p
		}
	}
	pid, err := syscall.ForkExec(cmd, argv, attr)
	if err != nil {
		return fmt.Errorf("ptrace target startup failed: %w; check existing tracers, seccomp/Yama or sandbox restrictions; try netns/observe", err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig, ok := sig.(syscall.Signal); ok {
					_ = syscall.Kill(pid, sig)
				}
			case <-done:
				return
			}
		}
	}()
	var exitErr error
	warnedNested := false
	warnedCapture := false
	options := unix.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEEXEC

	states := map[int]*tracee{pid: {}}

	for len(states) > 0 {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(-1, &ws, unix.WALL, nil)
		if err != nil {
			if err == unix.ECHILD {
				return exitErr
			}
			continue
		}
		st, ok := states[wpid]
		if !ok {
			// unknown tid (e.g. brand-new thread not yet registered); register
			st = &tracee{}
			states[wpid] = st
			_ = unix.PtraceSetOptions(wpid, options)
		}

		switch {
		case ws.Exited() || ws.Signaled():
			if wpid == pid {
				code := ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
				if code != 0 {
					exitErr = &ExitError{Code: code}
				}
			}
			delete(states, wpid)
			continue
		case ws.Stopped():
			sig := ws.StopSignal()
			event := (uint32(ws) >> 16) & 0xff

			switch {
			case sig == unix.SIGTRAP|0x80:
				// syscall stop
				if st.inSyscall {
					st.inSyscall = false
					handleExit(wpid, st, sockPath)
				} else {
					st.inSyscall = true
					handleEnter(wpid, st, proxyPort, dashPort, &warnedNested, &warnedCapture)
				}
				_ = unix.PtraceSyscall(wpid, 0)
			case sig == unix.SIGTRAP:
				switch event {
				case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_CLONE:
					msg, err := unix.PtraceGetEventMsg(wpid)
					if err == nil {
						newpid := int(msg)
						states[newpid] = &tracee{}
						_ = unix.PtraceSetOptions(newpid, options)
						_ = unix.PtraceSyscall(newpid, 0)
					}
					_ = unix.PtraceSyscall(wpid, 0)
				case unix.PTRACE_EVENT_EXEC:
					_ = unix.PtraceSetOptions(wpid, options)
					_ = unix.PtraceSyscall(wpid, 0)
				default:
					// initial stop or plain SIGTRAP: install options
					_ = unix.PtraceSetOptions(wpid, options)
					_ = unix.PtraceSyscall(wpid, 0)
				}
			default:
				// forward real signals
				_ = unix.PtraceSyscall(wpid, int(sig))
			}
		}
	}
	return exitErr
}

// ExitError preserves the traced root process exit code.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }
func (e *ExitError) ExitCode() int { return e.Code }

// handleEnter inspects a connect() syscall entry and rewrites the destination
// to the proxy when appropriate.
func handleEnter(pid int, st *tracee, proxyPort, dashPort int, warnedNested, warnedCapture *bool) {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		debugf("enter pid=%d: getregs: %v", pid, err)
		return
	}
	if regs.Orig_rax == unix.SYS_PTRACE && !*warnedNested &&
		(regs.Rdi == unix.PTRACE_TRACEME || regs.Rdi == unix.PTRACE_ATTACH || regs.Rdi == unix.PTRACE_SEIZE) {
		*warnedNested = true
		cliui.Printf("! WARN: PID %d attempted nested ptrace tracing (possibly graftcp/strace/debugger), which conflicts with ptrace mode; try netns or observe.\n", pid)
	}
	if regs.Orig_rax != sysConnect {
		return
	}
	debugf("enter pid=%d fd=%d connect()", pid, int(regs.Rdi))
	fd := int(regs.Rdi)
	sa, err := readRemote(pid, uintptr(regs.Rsi), 28)
	if err != nil || len(sa) < 2 {
		return
	}
	family := int(sa[0]) | int(sa[1])<<8
	var ip net.IP
	var port int
	switch family {
	case unix.AF_INET:
		if len(sa) < 8 {
			return
		}
		port = int(sa[2])<<8 | int(sa[3])
		ip = net.IP(append([]byte(nil), sa[4:8]...))
	case unix.AF_INET6:
		if len(sa) < 24 {
			return
		}
		port = int(sa[2])<<8 | int(sa[3])
		ip = net.IP(append([]byte(nil), sa[8:24]...))
	default:
		return // unix sockets etc.
	}
	// only TCP sockets: check SO_TYPE via pidfd_getfd
	isTCP, inspectErr := sockIsTCP(pid, fd)
	if inspectErr != nil && !*warnedCapture {
		*warnedCapture = true
		cliui.Printf("! WARN [ptrace]: cannot inspect target socket: %v; connection skipped, possibly due to kernel version, seccomp, Yama or permissions. Try netns or observe.\n", inspectErr)
	}
	if !isTCP {
		debugf("enter pid=%d fd=%d: not a TCP socket, skip", pid, fd)
		return
	}
	// anti-recursion: never redirect the proxy/dashboard themselves
	if ip.IsLoopback() && (port == proxyPort || port == dashPort) {
		debugf("enter pid=%d: skip loopback self %s:%d", pid, ip, port)
		return
	}
	debugf("enter pid=%d: rewrite %s:%d -> proxy", pid, ip, port)

	// rewrite destination, preserving address family
	var newSA []byte
	if family == unix.AF_INET6 {
		newSA = make([]byte, 28)
		newSA[0], newSA[1] = 10, 0
		copy(newSA[8:24], net.ParseIP("::1").To16())
	} else {
		newSA = make([]byte, 16)
		newSA[0], newSA[1] = 2, 0
		copy(newSA[4:8], net.ParseIP("127.0.0.1").To4())
	}
	newSA[2] = byte(proxyPort >> 8)
	newSA[3] = byte(proxyPort)
	if err := writeRemote(pid, uintptr(regs.Rsi), newSA); err != nil {
		if !*warnedCapture {
			*warnedCapture = true
			cliui.Printf("! WARN [ptrace]: cannot rewrite target connect address: %v; this connection cannot be redirected for capture.\n", err)
		}
		return
	}
	st.pending = pendingConnect{fd: fd, ip: ip.String(), port: port}
}

// handleExit checks the connect() result and reports the original destination
// over the side-channel so the proxy can attribute the connection.
func handleExit(pid int, st *tracee, sockPath string) {
	p := st.pending
	st.pending = pendingConnect{}
	if p.fd == 0 || p.ip == "" {
		return
	}
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		debugf("exit pid=%d: getregs: %v", pid, err)
		return
	}
	retval := int64(regs.Rax)
	debugf("exit pid=%d fd=%d retval=%d", pid, p.fd, retval)
	if retval != 0 && retval != -int64(unix.EINPROGRESS) {
		return // connect failed; nothing to attribute
	}
	srcPort := localPortOf(pid, p.fd)
	debugf("exit pid=%d fd=%d -> srcport=%d", pid, p.fd, srcPort)
	if srcPort == 0 {
		return
	}
	err := sidechan.Send(sockPath, sidechan.Entry{
		SrcPort: srcPort, PID: pid, OrigHost: p.ip, OrigPort: p.port, Mode: "ptrace",
	})
	debugf("exit pid=%d: MAP sent (err=%v)", pid, err)
}

// sockIsTCP reports whether /proc/pid/fd/fd is a SOCK_STREAM socket, using
// pidfd_getfd to duplicate the tracee's fd into our process and query
// SO_TYPE. (An unconnected socket does not appear in /proc/net/tcp, so the
// inode-table lookup only works after connect.)
func sockIsTCP(pid, fd int) (bool, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false, fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd)
	ourFd, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return false, fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(ourFd)
	typ, err := unix.GetsockoptInt(ourFd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return false, fmt.Errorf("getsockopt(SO_TYPE): %w", err)
	}
	return typ == unix.SOCK_STREAM, nil
}

// localPortOf finds the local TCP port of the socket behind /proc/pid/fd/fd.
func localPortOf(pid, fd int) int {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil || !strings.HasPrefix(target, "socket:[") {
		return 0
	}
	inode := target[len("socket:[") : len(target)-1]
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			flds := strings.Fields(line)
			if len(flds) < 10 || flds[9] != inode {
				continue
			}
			parts := strings.Split(flds[1], ":")
			if len(parts) != 2 {
				continue
			}
			p, err := strconv.ParseInt(parts[1], 16, 32)
			if err == nil && p != 0 {
				return int(p)
			}
		}
	}
	return 0
}

// readRemote reads len bytes from the tracee's address space.
func readRemote(pid int, addr uintptr, n int) ([]byte, error) {
	buf := make([]byte, n)
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(n)}}
	remote := []unix.RemoteIovec{{Base: addr, Len: n}}
	done, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	return buf[:done], nil
}

// writeRemote writes buf into the tracee's address space.
func writeRemote(pid int, addr uintptr, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(len(buf))}}
	remote := []unix.RemoteIovec{{Base: addr, Len: len(buf)}}
	_, err := unix.ProcessVMWritev(pid, local, remote, 0)
	return err
}

func whichDebug() bool { return os.Getenv("NETINSPECT_PTRACE_DEBUG") != "" }

func debugf(format string, args ...any) {
	if whichDebug() {
		fmt.Fprintf(os.Stderr, "[ptrace-debug] "+format+"\n", args...)
	}
}
