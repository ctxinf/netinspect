package main

import (
	"embed"
	"fmt"
)

//go:embed skilldata/*.md
var skillsFS embed.FS

func skillsCmd(args []string) error {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")) {
		fmt.Println("Usage: netinspect skills <COMMAND>\n\nCommands:\n  list              List bundled agent skills\n  get core [--full]  Print the agent workflow, optionally with API reference")
		return nil
	}
	if len(args) == 1 && args[0] == "list" {
		fmt.Println("core  Capture workflow, mode selection, diagnostics and dashboard API")
		return nil
	}
	if (len(args) == 2 || len(args) == 3 && args[2] == "--full") && args[0] == "get" && args[1] == "core" {
		data, err := skillsFS.ReadFile("skilldata/core.md")
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		if len(args) == 3 {
			data, err = skillsFS.ReadFile("skilldata/reference.md")
			if err != nil {
				return err
			}
			fmt.Print(string(data))
		}
		return nil
	}
	return fmt.Errorf("unknown skills command or skill; use netinspect skills --help")
}
