package check

import (
	"fmt"
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
			wantErr: []string{"go.work: replaces golang.org/x/mod; its replace lines are the harness's"}},
		{name: "go.work replacing a pre-release of the head a go.mod requires",
			change: func(fsys fstest.MapFS) {
				replace("go.work", "replace ", "replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0-dev.3 => ./conformance\nreplace ")(fsys)
				replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.2.0-dev.3")(fsys)
			}},
		{name: "go.work replacing a pre-release of the head no go.mod requires",
			change:  replace("go.work", "replace ", "replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0-rc.1 => ./conformance\nreplace "),
			wantErr: []string{"go.work: replaces the harness at v0.2.0-rc.1, a pre-release no specification's go.mod requires: drop the stray line"}},
		{name: "go.work keeping a pre-release line once the go.mod requires the release",
			change: func(fsys fstest.MapFS) {
				replace("go.work", "replace ", "replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0-dev.3 => ./conformance\nreplace ")(fsys)
				replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.2.0-rc.1")(fsys)
				replace("go.work", "replace ", "replace github.com/buildwarden/buildwarden-specs/conformance v0.2.0-rc.1 => ./conformance\nreplace ")(fsys)
			},
			wantErr: []string{"go.work: replaces the harness at v0.2.0-dev.3, a pre-release no specification's go.mod requires"}},
		{name: "go.work replacing a pre-release of another version",
			change:  replace("go.work", "replace ", "replace github.com/buildwarden/buildwarden-specs/conformance v0.1.0-dev.1 => ./conformance\nreplace "),
			wantErr: []string{`go.work: replaces the harness at "v0.1.0-dev.1", and the head of conformance/CHANGELOG.md is v0.2.0: the harness is replaced at that version and its pre-releases only`}},
		{name: "go.work replacing only a pre-release of the head", change: replace("go.work", "conformance v0.2.0 =>", "conformance v0.2.0-dev.1 =>"),
			wantErr: []string{"go.work: has no replace line for github.com/buildwarden/buildwarden-specs/conformance at the version in progress"}},
		{name: "a go.mod requiring a pre-release of the head that go.work does not replace",
			change:  replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.2.0-dev.3"),
			wantErr: []string{"go.work: has no replace line for the harness at v0.2.0-dev.3, which relay-claim/go.mod requires"}},
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

// atMinor heads relay-claim's CHANGELOG.md with v0.3.0, the next minor
// after a release v0.2.x, as a program trunk's change does.
func atMinor(fsys fstest.MapFS) {
	replace("relay-claim/CHANGELOG.md", "## v0.3.1\n\n", "")(fsys)
}

// atHarnessDev is atMinor with relay-claim's go.mod requiring the harness
// at v0.2.0-dev.n, a pre-release of its head.
func atHarnessDev(n int) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) {
		atMinor(fsys)
		replace("relay-claim/go.mod", "conformance v0.2.0", fmt.Sprintf("conformance v0.2.0-dev.%d", n))(fsys)
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
		program bool // a program trunk's change
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
		{name: "a specification on main requiring a pre-release of the harness's head", dirs: changed(),
			change:  replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.2.0-dev.1"),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.2.0-dev.1", a pre-release, and the head of conformance/CHANGELOG.md is v0.2.0: only a program trunk's specification requires a pre-release of the harness`}},

		{name: "a patch on main below a program trunk's pre-release passes", dirs: changed("v0.3.0", "v0.4.0-dev.1")},
		{name: "a patch on main below its newest release", dirs: changed("v0.3.0", "v0.4.0", "v0.4.0-dev.1"),
			wantErr: []string{"names v0.3.1 at its head, and relay-claim/v0.4.0 is already tagged"}},

		// A program trunk's change: each changed directory's head is the
		// next minor after its newest release, as wf tag-next proposes, and
		// a specification requires the pre-release of the harness's head
		// that the tree's harness is. In changed(), the harness changes and
		// its head, v0.2.0, has no tag, so that is v0.2.0-dev.1.
		{name: "a program trunk's change at the next minors", program: true, dirs: changed("v0.2.0", "v0.2.3", "v0.3.0-dev.4"),
			change: atHarnessDev(1)},
		{name: "a program trunk's change to directories with no release", program: true,
			change: func(fsys fstest.MapFS) {
				replace("relay-claim/CHANGELOG.md", "## v0.3.1", "## v0.1.0")(fsys)
				replace("conformance/CHANGELOG.md", "## v0.2.0\n\n## v0.1.0", "## v0.1.0")(fsys)
				replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.1.0-dev.2")(fsys)
			},
			dirs: []DirRelease{{Dir: Harness, Changed: true, Tags: []string{"v0.1.0-dev.1"}}, {Dir: "relay-claim", Changed: true}}},
		{name: "a program trunk's specification requiring the harness's next -dev tag", program: true,
			dirs:   []DirRelease{{Dir: Harness, Changed: true, Tags: []string{"v0.1.0", "v0.2.0-dev.1", "v0.2.0-dev.2", "v0.2.0-rc.1"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change: atHarnessDev(3)},
		{name: "a program trunk's specification guessing the harness's next -dev tag wrong", program: true,
			dirs:    []DirRelease{{Dir: Harness, Changed: true, Tags: []string{"v0.1.0", "v0.2.0-dev.1", "v0.2.0-dev.2"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change:  atHarnessDev(2),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.2.0-dev.2", and the head of conformance/CHANGELOG.md is v0.2.0: a program trunk's specification requires v0.2.0-dev.3, the -dev tag wf tag-next pushes for the harness this change touches`}},
		{name: "a program trunk's specification requiring the harness's newest pre-release", program: true,
			dirs: []DirRelease{{Dir: Harness, Tags: []string{"v0.1.0", "v0.2.0-dev.4", "v0.2.0-rc.3"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change: func(fsys fstest.MapFS) {
				atMinor(fsys)
				replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.2.0-rc.3")(fsys)
			}},
		{name: "a program trunk's specification requiring a stale pre-release of the harness", program: true,
			dirs:    []DirRelease{{Dir: Harness, Tags: []string{"v0.1.0", "v0.2.0-dev.1", "v0.2.0-dev.3"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change:  atHarnessDev(1),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.2.0-dev.1", and the head of conformance/CHANGELOG.md is v0.2.0: a program trunk's specification requires v0.2.0-dev.3, the harness's newest pre-release of its head`}},
		{name: "a program trunk's specification requiring the harness's unreleased head", program: true, dirs: changed("v0.2.0"),
			change:  atMinor,
			wantErr: []string{"relay-claim/go.mod: requires the harness at v0.2.0, the head of conformance/CHANGELOG.md, which has no release tag: a program trunk's specification requires v0.2.0-dev.1"}},
		{name: "a program trunk's specification when the harness's head has no tag", program: true,
			dirs:    []DirRelease{{Dir: Harness, Tags: []string{"v0.1.0"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change:  atHarnessDev(1),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.2.0-dev.1", and the head of conformance/CHANGELOG.md, v0.2.0, is neither released nor tagged as a pre-release`}},
		{name: "a program trunk's specification requiring the harness's released head", program: true,
			dirs:   []DirRelease{{Dir: Harness, Tags: []string{"v0.2.0", "v0.2.0-dev.1"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change: atMinor},
		{name: "a program trunk's specification requiring a pre-release of the harness's released head", program: true,
			dirs:    []DirRelease{{Dir: Harness, Tags: []string{"v0.2.0", "v0.2.0-dev.1"}}, {Dir: "relay-claim", Changed: true, Tags: []string{"v0.2.0"}}},
			change:  atHarnessDev(1),
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.2.0-dev.1", and the head of conformance/CHANGELOG.md is v0.2.0, which is released: a program trunk's specification requires it`}},
		{name: "a program trunk's specification requiring a pre-release of another harness version", program: true, dirs: changed("v0.2.0"),
			change: func(fsys fstest.MapFS) {
				atMinor(fsys)
				replace("relay-claim/go.mod", "conformance v0.2.0", "conformance v0.1.0-dev.1")(fsys)
			},
			wantErr: []string{`relay-claim/go.mod: requires the harness at "v0.1.0-dev.1", and the head of conformance/CHANGELOG.md is v0.2.0: a program trunk's specification requires v0.2.0-dev.1`}},
		{name: "a program trunk's change heading a patch", program: true, dirs: changed("v0.3.0"),
			wantErr: []string{"relay-claim/CHANGELOG.md: names v0.3.1 at its head, and a program trunk's change to relay-claim heads it with v0.4.0, the next minor after its newest release"}},
		{name: "a program trunk's change skipping a minor", program: true,
			dirs:    []DirRelease{{Dir: Harness, Changed: true, Tags: []string{"v0.0.9"}}},
			wantErr: []string{"conformance/CHANGELOG.md: names v0.2.0 at its head, and a program trunk's change to conformance heads it with v0.1.0"}},
		{name: "a program trunk's change that adds no version", program: true, dirs: changed("v0.3.1"),
			wantErr: []string{"relay-claim/CHANGELOG.md: names v0.3.1 at its head, and relay-claim/v0.3.1 is already tagged"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := modules()
			if tt.change != nil {
				tt.change(fsys)
			}
			assertErr(t, Release(fsys, tt.dirs, tt.program), tt.wantErr)
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

func TestNextRelease(t *testing.T) {
	for _, tt := range []struct {
		in   []string
		want string
	}{
		{nil, "v0.1.0"},
		{[]string{"v0.1.0-dev.1"}, "v0.1.0"},
		{[]string{"v0.1.0"}, "v0.2.0"},
		{[]string{"v0.1.0", "v0.1.3", "v0.2.0-dev.5"}, "v0.2.0"},
		{[]string{"v0.9.0", "v0.10.2"}, "v0.11.0"},
		{[]string{"v1.4.1", "latest"}, "v1.5.0"},
	} {
		if got := NextRelease(tt.in); got != tt.want {
			t.Errorf("NextRelease(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNextPre(t *testing.T) {
	for _, tt := range []struct {
		in   []string
		kind string
		want string
	}{
		{nil, "dev", "v0.2.0-dev.1"},
		{[]string{"v0.1.0", "v0.2.0-dev.1", "v0.2.0-dev.10", "v0.2.0-rc.4", "v0.3.0-dev.20"}, "dev", "v0.2.0-dev.11"},
		{[]string{"v0.2.0-dev.3", "v0.2.0-rc.4"}, "rc", "v0.2.0-rc.5"},
	} {
		if got := NextPre(tt.in, "v0.2.0", tt.kind); got != tt.want {
			t.Errorf("NextPre(%q, v0.2.0, %s) = %q, want %q", tt.in, tt.kind, got, tt.want)
		}
	}
}
