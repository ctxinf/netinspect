// Package version shares release and build identity between the CLI and UI.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Tag and Build can be supplied at release build time with -ldflags -X.
// Tag must identify the release (for example v0.1.0), never a commit hash.
var Tag string
var Build string

type Info struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

var pseudoVersion = regexp.MustCompile(`[-.][0-9]{14}-[0-9a-f]+(\+.*)?$`)

func releaseTag(value string) string {
	if pseudoVersion.MatchString(value) {
		return ""
	}
	return value
}

func Current() Info {
	info := Info{Version: releaseTag(Tag), Build: Build}
	if b, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" && strings.HasPrefix(b.Main.Version, "v") {
			info.Version = releaseTag(b.Main.Version)
		}
		if info.Build == "" {
			dirty := false
			for _, s := range b.Settings {
				if s.Key == "vcs.revision" {
					info.Build = s.Value
					if len(info.Build) > 12 {
						info.Build = info.Build[:12]
					}
				}
				if s.Key == "vcs.modified" {
					dirty = s.Value == "true"
				}
			}
			if dirty && info.Build != "" {
				info.Build += "-dirty"
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Build == "" {
		info.Build = "local"
	}
	return info
}
