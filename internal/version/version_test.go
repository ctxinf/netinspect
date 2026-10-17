package version

import "testing"

func TestReleaseIdentitySeparateFromBuild(t *testing.T) {
	oldTag, oldBuild := Tag, Build
	t.Cleanup(func() { Tag, Build = oldTag, oldBuild })
	Tag, Build = "v1.2.3", "abcdef012345-dirty"
	info := Current()
	if info.Version != "v1.2.3" || info.Build != "abcdef012345-dirty" {
		t.Fatalf("mixed release and build identity: %+v", info)
	}
	Tag, Build = "", ""
	if info = Current(); info.Version != "dev" || info.Build == "" {
		t.Fatalf("missing development defaults: %+v", info)
	}
}

func TestPseudoVersionIsNotAReleaseTag(t *testing.T) {
	for _, v := range []string{"v0.0.0-20261017130746-a8798ba58443+dirty", "v1.2.4-0.20261017130746-a8798ba58443"} {
		if releaseTag(v) != "" {
			t.Fatalf("build identity presented as release tag: %s", v)
		}
	}
	if releaseTag("v1.2.3-rc.1") != "v1.2.3-rc.1" {
		t.Fatal("discarded a release tag")
	}
}
