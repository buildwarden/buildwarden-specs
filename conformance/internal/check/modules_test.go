package check

import (
	"testing"
	"testing/fstest"
)

// modules is a repository of the harness and two specifications whose
// go.mod files and go.work pass the module checks.
func modules() fstest.MapFS {
	fsys := fstest.MapFS{
		"go.work": {Data: []byte("go 1.26.3\n\nuse (\n\t./conformance\n\t./relay-claim\n\t./collector-inputs\n)\n\n" +
			"replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0 => ./conformance\n")},
		"conformance/go.mod":       {Data: []byte("module github.com/buildwarden/buildwarden-specs/conformance\n\ngo 1.26.3\n\nrequire github.com/BurntSushi/toml v1.6.0\n")},
		"conformance/CHANGELOG.md": {Data: []byte("# Changelog\n\n## v0.2.0\n\n## v0.1.0\n")},
	}
	for _, dir := range []string{"relay-claim", "collector-inputs"} {
		fsys[dir+"/go.mod"] = &fstest.MapFile{Data: []byte("module github.com/buildwarden/buildwarden-specs/" + dir +
			"\n\ngo 1.26.3\n\nrequire github.com/buildwarden/buildwarden-specs/conformance v0.2.0\n")}
		fsys[dir+"/CHANGELOG.md"] = &fstest.MapFile{Data: []byte("# Changelog\n\n## v0.3.1\n\n## v0.3.0\n")}
	}
	return fsys
}

var specs = []string{"relay-claim", "collector-inputs"}

func TestModules(t *testing.T) {
	tests := []struct {
		name    string
		change  func(fstest.MapFS)
		wantErr []string
	}{
		{name: "the fixture passes"},
		{name: "a go.mod requiring the kit", change: replace("relay-claim/go.mod", "require ", "require github.com/buildwarden/buildwarden v0.9.0\nrequire "),
			wantErr: []string{"relay-claim/go.mod: requires github.com/buildwarden/buildwarden, a module of the kit"}},
		{name: "a go.mod requiring a package path of the kit", change: replace("conformance/go.mod", "require ", "require github.com/buildwarden/buildwarden/ledger v0.9.0\nrequire "),
			wantErr: []string{"conformance/go.mod: requires github.com/buildwarden/buildwarden/ledger"}},
		{name: "a go.mod with a replace", change: replace("relay-claim/go.mod", "require ", "replace github.com/buildwarden/buildwarden-specs/conformance => ../conformance\n\nrequire "),
			wantErr: []string{"relay-claim/go.mod: carries a replace line for github.com/buildwarden/buildwarden-specs/conformance"}},
		{name: "a go.mod of another module", change: replace("collector-inputs/go.mod", "specs/collector-inputs", "specs/collector-outputs"),
			wantErr: []string{"collector-inputs/go.mod: does not declare the module github.com/buildwarden/buildwarden-specs/collector-inputs"}},
		{name: "a missing go.mod", change: remove("collector-inputs/go.mod"),
			wantErr: []string{"collector-inputs/go.mod: open collector-inputs/go.mod: file does not exist"}},
		{name: "go.work replacing an older harness version", change: replace("conformance/CHANGELOG.md", "## v0.2.0", "## v0.2.1\n\n## v0.2.0"),
			wantErr: []string{`go.work: replaces the harness at "v0.2.0", and the head of conformance/CHANGELOG.md is v0.2.1`}},
		{name: "go.work replacing the harness with no version", change: replace("go.work", "conformance v0.2.0 =>", "conformance =>"),
			wantErr: []string{`go.work: replaces the harness at "", and the head`}},
		{name: "go.work replacing the harness by another directory", change: replace("go.work", "=> ./conformance", "=> ../conformance"),
			wantErr: []string{"go.work: replaces the harness by ../conformance, want ./conformance"}},
		{name: "go.work with no replace", change: replace("go.work", "replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0 => ./conformance\n", ""),
			wantErr: []string{"go.work: has no replace line for github.com/buildwarden/buildwarden-specs/conformance"}},
		{name: "go.work replacing another module", change: replace("go.work", "replace ", "replace golang.org/x/mod => ./mod\nreplace "),
			wantErr: []string{"go.work: replaces golang.org/x/mod; its one replace line is the harness's"}},
		{name: "go.work missing a module", change: replace("go.work", "\t./collector-inputs\n", ""),
			wantErr: []string{"go.work: does not use ./collector-inputs"}},
		{name: "go.work using a module that is not one of them", change: replace("go.work", "\t./collector-inputs\n", "\t./collector-inputs\n\t./tools\n"),
			wantErr: []string{"go.work: uses ./tools, which is not one of the seven modules"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := modules()
			if tt.change != nil {
				tt.change(fsys)
			}
			assertErr(t, Modules(fsys, specs), tt.wantErr)
		})
	}
}

func TestRelease(t *testing.T) {
	changed := func(tags ...string) []DirRelease {
		return []DirRelease{
			{Dir: Harness, Changed: true, Tags: []string{"v0.1.0"}},
			{Dir: "relay-claim", Changed: true, Tags: tags},
			{Dir: "collector-inputs", Changed: false, Tags: []string{"v0.9.0"}},
		}
	}
	tests := []struct {
		name    string
		change  func(fstest.MapFS)
		dirs    []DirRelease
		wantErr []string
	}{
		{name: "versions above the newest tags pass", dirs: changed("v0.3.0", "v0.2.0")},
		{name: "a directory with no tag yet passes", dirs: changed()},
		{name: "a changed directory that adds no version", dirs: changed("v0.2.0", "v0.3.1"),
			wantErr: []string{"relay-claim/CHANGELOG.md: names v0.3.1 at its head, and relay-claim/v0.3.1 is already tagged"}},
		{name: "a changed directory whose version is below its newest tag", dirs: changed("v0.4.0"),
			wantErr: []string{"names v0.3.1 at its head, and relay-claim/v0.4.0 is already tagged"}},
		{name: "a changed harness that adds no version", dirs: []DirRelease{{Dir: Harness, Changed: true, Tags: []string{"v0.2.0"}}},
			wantErr: []string{"conformance/CHANGELOG.md: names v0.2.0 at its head, and conformance/v0.2.0 is already tagged"}},
		{name: "an unchanged directory is not checked", dirs: changed("v0.3.0"),
			change: replace("collector-inputs/go.mod", "conformance v0.2.0", "conformance v0.1.0")},
		{name: "a changed specification naming an older harness", dirs: changed(),
			change:  replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.1.0"),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.1.0", and the head of conformance/CHANGELOG.md is v0.2.0`}},
		{name: "a changed specification not naming the harness", dirs: changed(),
			change:  replace("relay-claim/go.mod", "require github.com/buildwarden/buildwarden-specs/conformance v0.2.0\n", ""),
			wantErr: []string{`relay-claim/go.mod: requires the harness at ""`}},
		{name: "a changed directory with no version heading", dirs: changed(),
			change:  set("relay-claim/CHANGELOG.md", "# Changelog\n"),
			wantErr: []string{"relay-claim/CHANGELOG.md: no version heading"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := modules()
			if tt.change != nil {
				tt.change(fsys)
			}
			assertErr(t, Release(fsys, tt.dirs), tt.wantErr)
		})
	}
}

func TestNewest(t *testing.T) {
	for _, tt := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"v0.1.0"}, "v0.1.0"},
		{[]string{"v0.9.0", "v0.10.0", "v0.2.0"}, "v0.10.0"},
		{[]string{"latest", "v0.1.0"}, "v0.1.0"},
	} {
		if got := Newest(tt.in); got != tt.want {
			t.Errorf("Newest(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
