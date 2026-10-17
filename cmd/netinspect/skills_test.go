package main

import "testing"

func TestSkillsCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"list"}, {"get", "core"}, {"get", "core", "--full"}, {"--help"}} {
		if err := skillsCmd(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"get"}, {"get", "missing"}, {"list", "extra"}, {"get", "core", "--bad"}} {
		if err := skillsCmd(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
