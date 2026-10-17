package session

import "testing"

func TestNestingMarkers(t *testing.T) {
	t.Setenv(activeSessionEnv, "")
	t.Setenv("NETINSPECT_SOCK_PATH", "")
	if err := checkNesting(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(activeSessionEnv, "1234")
	if err := checkNesting(); err == nil {
		t.Fatal("accepted active session")
	}
	t.Setenv(activeSessionEnv, "")
	t.Setenv("NETINSPECT_SOCK_PATH", "/tmp/side.sock")
	if err := checkNesting(); err == nil {
		t.Fatal("accepted inherited preload session")
	}
}
