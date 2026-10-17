package session

import (
	"os/user"
	"reflect"
	"strings"
	"testing"
)

func TestSudoTargetIdentity(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_UID", current.Uid)
	t.Setenv("SUDO_GID", current.Gid)
	t.Setenv("HOME", "/root")
	t.Setenv("XDG_CACHE_HOME", "/root/.cache")
	id, err := resolveTargetIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if id.user.Uid != current.Uid || id.gid != current.Gid {
		t.Fatalf("wrong identity: %+v", id)
	}
	args := id.wrap([]string{"program", "one arg", "--flag"})
	if !reflect.DeepEqual(args[len(args)-3:], []string{"program", "one arg", "--flag"}) {
		t.Fatal("target arguments changed")
	}
	if !strings.Contains(strings.Join(args, " "), "--init-groups") {
		t.Fatal("supplementary groups missing")
	}
	env := map[string]string{}
	for _, value := range id.environment() {
		k, v, _ := strings.Cut(value, "=")
		env[k] = v
	}
	if env["HOME"] != current.HomeDir || env["USER"] != current.Username || env["LOGNAME"] != current.Username {
		t.Fatal("user environment not restored")
	}
	if _, ok := env["SUDO_UID"]; ok {
		t.Fatal("sudo identity leaked into target")
	}
	if current.Uid != "0" && env["XDG_CACHE_HOME"] != "" {
		t.Fatal("root cache leaked into target")
	}
	explicit, err := resolveTargetIdentity(current.Username)
	if err != nil || explicit.user.Uid != current.Uid {
		t.Fatalf("explicit user failed: %v", err)
	}
}

func TestRootIdentityAndInvalidUser(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	id, err := resolveTargetIdentity("")
	if err != nil || id != nil {
		t.Fatal("root fallback changed")
	}
	if !reflect.DeepEqual(id.wrap([]string{"id"}), []string{"id"}) {
		t.Fatal("nil identity wrap")
	}
	if _, err := resolveTargetIdentity("netinspect-user-does-not-exist-735924"); err == nil {
		t.Fatal("accepted unknown user")
	}
	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "invalid")
	if _, err := resolveTargetIdentity(""); err == nil {
		t.Fatal("accepted invalid sudo gid")
	}
}

func TestPtraceConflictDetection(t *testing.T) {
	if tracerPID("Name:\ttest\nTracerPid:\t123\n") != 123 || tracerPID("TracerPid:\t0\n") != 0 {
		t.Fatal("bad tracer PID")
	}
	if !ptraceWrapper([]string{"/usr/bin/graftcp", "curl"}) || ptraceWrapper([]string{"curl", "graftcp"}) {
		t.Fatal("bad wrapper detection")
	}
}
