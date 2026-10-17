package session

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// targetIdentity is resolved before namespace setup; only the target is dropped.
type targetIdentity struct {
	user    *user.User
	gid     string
	setpriv string
}

func resolveTargetIdentity(explicit string) (*targetIdentity, error) {
	selector := explicit
	if selector == "" {
		selector = os.Getenv("SUDO_UID")
		if selector != "" {
			if _, err := strconv.ParseUint(selector, 10, 32); err != nil {
				return nil, fmt.Errorf("invalid SUDO_UID %q", selector)
			}
		}
	}
	if selector == "" {
		return nil, nil
	} // A genuine root invocation stays root.
	var u *user.User
	var err error
	if _, e := strconv.ParseUint(selector, 10, 32); e == nil {
		u, err = user.LookupId(selector)
	} else {
		u, err = user.Lookup(selector)
	}
	if err != nil {
		return nil, fmt.Errorf("netns target user %q: %w", selector, err)
	}
	gid := u.Gid
	if explicit == "" && os.Getenv("SUDO_GID") != "" {
		gid = os.Getenv("SUDO_GID")
	}
	if _, err := strconv.ParseUint(gid, 10, 32); err != nil {
		return nil, fmt.Errorf("invalid target GID %q", gid)
	}
	path, err := exec.LookPath("setpriv")
	if err != nil {
		return nil, fmt.Errorf("netns target privilege drop requires setpriv (util-linux): %w", err)
	}
	return &targetIdentity{user: u, gid: gid, setpriv: path}, nil
}

func (id *targetIdentity) wrap(command []string) []string {
	if id == nil {
		return command
	}
	return append([]string{id.setpriv, "--reuid=" + id.user.Uid, "--regid=" + id.gid, "--init-groups", "--inh-caps=-all", "--ambient-caps=-all", "--"}, command...)
}

func (id *targetIdentity) environment() []string {
	if id == nil {
		return os.Environ()
	}
	values := map[string]string{"HOME": id.user.HomeDir, "USER": id.user.Username, "LOGNAME": id.user.Username}
	// sudo's secure_path often omits the invoking user's executable directory.
	values["PATH"] = filepath.Join(id.user.HomeDir, ".local/bin") + ":" + os.Getenv("PATH")
	runtimeDir := "/run/user/" + id.user.Uid
	if info, err := os.Stat(runtimeDir); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && strconv.FormatUint(uint64(stat.Uid), 10) == id.user.Uid {
			values["XDG_RUNTIME_DIR"] = runtimeDir
			if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
				if _, err := os.Stat(filepath.Join(runtimeDir, "bus")); err == nil {
					values["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + filepath.Join(runtimeDir, "bus")
				}
			}
		}
	}
	out := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := values[key]; replaced || strings.HasPrefix(key, "SUDO_") || key == "XDG_RUNTIME_DIR" {
			continue
		}
		// Avoid resolving application caches/settings in root's home after sudo -E.
		if (key == "XDG_CONFIG_HOME" || key == "XDG_CACHE_HOME" || key == "XDG_DATA_HOME") && strings.HasPrefix(strings.SplitN(entry, "=", 2)[1], "/root/") {
			continue
		}
		out = append(out, entry)
	}
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}
