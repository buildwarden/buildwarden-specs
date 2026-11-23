package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"an unknown subcommand", []string{"layout"}},
		{"release with no base", []string{"release", "relay-claim"}},
		{"release with an unknown flag", []string{"release", "-head", "x"}},
		{"tag with no main", []string{"tag", "relay-claim/v0.1.0", "relay-claim"}},
		{"tag with no tag", []string{"tag", "-main", "origin/main"}},
		{"tag with an empty program trunk", []string{"tag", "-main", "origin/main", "-program", "", "relay-claim/v0.1.0-dev.1", "relay-claim"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if status := run(tt.args, &stdout, &stderr); status != 2 {
				t.Errorf("status %d, want 2", status)
			}
			if !strings.Contains(stderr.String(), "speccheck release -base <ref> <directory>...") {
				t.Errorf("stderr %q has no usage", stderr.String())
			}
		})
	}
}

func TestFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"docs", "absent"}, &stdout, &stderr); status != 1 {
		t.Errorf("status %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "speccheck docs:\nabsent: open absent") {
		t.Errorf("stderr %q does not name the missing directory", stderr.String())
	}
}

// tagRepo makes a git repository in a temporary directory and changes to
// it, with this history:
//
//	main:                     c1 (v0.1.0) -- c3 (v0.2.0, only on main)
//	                            \
//	program/componentization:    c2 (v0.2.0)
//
// c1 has the heads relay-claim v0.1.0 and conformance v0.1.0 and the tags
// relay-claim/v0.1.0 and conformance/v0.1.0; c2 raises both heads to
// v0.2.0; c3 raises relay-claim's to v0.2.0 on main alone. It returns the
// commits by name.
func tagRepo(t *testing.T) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "speccheck", "GIT_AUTHOR_EMAIL": "speccheck@example.invalid",
		"GIT_COMMITTER_NAME": "speccheck", "GIT_COMMITTER_EMAIL": "speccheck@example.invalid",
	} {
		t.Setenv(k, v)
	}
	sh := func(args ...string) string {
		t.Helper()
		out, err := git(args...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	write := func(file, head string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("# Changelog\n\n"+head+"\n\n- A change.\n\n## v0.1.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(msg string) string {
		t.Helper()
		sh("add", "-A")
		sh("commit", "-q", "--no-gpg-sign", "-m", msg)
		return sh("rev-parse", "HEAD")
	}
	c := map[string]string{}
	sh("init", "-q", "-b", "main")
	if err := os.MkdirAll("relay-claim", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("relay-claim/CHANGELOG.md", []byte("# Changelog\n\n## v0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("conformance", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("conformance/CHANGELOG.md", []byte("# Changelog\n\n## v0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c["c1"] = commit("c1")
	sh("tag", "relay-claim/v0.1.0")
	sh("tag", "conformance/v0.1.0")
	sh("switch", "-q", "-c", "program/componentization")
	write("relay-claim/CHANGELOG.md", "## v0.2.0")
	write("conformance/CHANGELOG.md", "## v0.2.0")
	c["c2"] = commit("c2")
	sh("switch", "-q", "main")
	write("relay-claim/CHANGELOG.md", "## v0.2.0")
	if err := os.WriteFile("README.md", []byte("main alone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c["c3"] = commit("c3")
	return c
}

func TestTag(t *testing.T) {
	c := tagRepo(t)
	const program = "program/componentization"
	for _, tt := range []struct {
		name     string
		tag      string // the tag, made for the case unless tagRepo made it
		at       string // the commit it is made at
		programs []string
		wantErr  string // "" for a pass
	}{
		{name: "a release on main", tag: "relay-claim/v0.1.0", at: "c1"},
		{name: "a release on main, with the program trunk named", tag: "relay-claim/v0.1.0", at: "c1", programs: []string{program}},
		{name: "a release off main", tag: "relay-claim/v0.2.0", at: "c2", programs: []string{program},
			wantErr: "the tag relay-claim/v0.2.0 is not on main: a release is a tag on main"},
		{name: "a release that is not the head of its CHANGELOG.md", tag: "relay-claim/v0.0.9", at: "c1",
			wantErr: "relay-claim/CHANGELOG.md: names v0.1.0 at its head, and the tag is relay-claim/v0.0.9"},
		{name: "a -dev pre-release on the program trunk", tag: "relay-claim/v0.2.0-dev.1", at: "c2", programs: []string{program}},
		{name: "an -rc pre-release on the program trunk", tag: "relay-claim/v0.2.0-rc.1", at: "c2", programs: []string{program}},
		{name: "the harness's pre-release on the program trunk", tag: "conformance/v0.2.0-dev.1", at: "c2", programs: []string{program}},
		{name: "a pre-release on one of two program trunks", tag: "relay-claim/v0.2.0-dev.2", at: "c2", programs: []string{"main", program}},
		{name: "a -dev pre-release on main alone", tag: "relay-claim/v0.2.0-dev.3", at: "c3", programs: []string{program},
			wantErr: "the tag relay-claim/v0.2.0-dev.3 is not on program/componentization: a pre-release is a tag on a program trunk"},
		{name: "a pre-release with no program trunk named", tag: "relay-claim/v0.2.0-dev.4", at: "c2",
			wantErr: "no program trunk is named (-program)"},
		{name: "a program trunk that does not exist", tag: "relay-claim/v0.2.0-dev.5", at: "c2", programs: []string{"program/absent"},
			wantErr: "the program trunk program/absent:"},
		{name: "a pre-release of a version that is released", tag: "relay-claim/v0.1.0-dev.1", at: "c1", programs: []string{program},
			wantErr: "the tag relay-claim/v0.1.0-dev.1 is a pre-release of relay-claim/v0.1.0, which is already released"},
		{name: "a pre-release that is not of the head of its CHANGELOG.md", tag: "relay-claim/v0.3.0-dev.1", at: "c2", programs: []string{program},
			wantErr: "relay-claim/CHANGELOG.md: names v0.2.0 at its head, and the tag relay-claim/v0.3.0-dev.1 is a pre-release of v0.3.0"},
		{name: "a -beta suffix", tag: "relay-claim/v0.2.0-beta.1", at: "c2", programs: []string{program},
			wantErr: `the tag "relay-claim/v0.2.0-beta.1" has a suffix that is not -dev.N or -rc.N`},
		{name: "-dev with no number", tag: "relay-claim/v0.2.0-dev", at: "c2", programs: []string{program},
			wantErr: `the tag "relay-claim/v0.2.0-dev" has a suffix that is not -dev.N or -rc.N`},
		{name: "-rc.0", tag: "relay-claim/v0.2.0-rc.0", at: "c2", programs: []string{program},
			wantErr: "has a suffix that is not -dev.N or -rc.N"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := git("rev-parse", "--verify", "--quiet", "refs/tags/"+tt.tag); err != nil {
				if _, err := git("tag", tt.tag, c[tt.at]); err != nil {
					t.Fatal(err)
				}
				// Each case sees only the tags tagRepo made and its own.
				t.Cleanup(func() { git("tag", "-d", tt.tag) })
			}
			if _, err := git("checkout", "-q", "--detach", tt.tag); err != nil {
				t.Fatal(err)
			}
			args := []string{"tag", "-main", "main"}
			for _, p := range tt.programs {
				args = append(args, "-program", p)
			}
			args = append(args, tt.tag, "relay-claim")
			var stdout, stderr bytes.Buffer
			status := run(args, &stdout, &stderr)
			if tt.wantErr == "" {
				if status != 0 {
					t.Fatalf("status %d, want 0; stderr:\n%s", status, stderr.String())
				}
				return
			}
			if status != 1 {
				t.Fatalf("status %d, want 1; stdout %q, stderr %q", status, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestTagCheckout(t *testing.T) {
	c := tagRepo(t)
	if _, err := git("tag", "relay-claim/v0.2.0-dev.1", c["c2"]); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	// The checkout is main's head, c3, not the tagged commit.
	if status := run([]string{"tag", "-main", "main", "-program", "program/componentization", "relay-claim/v0.2.0-dev.1", "relay-claim"}, &stdout, &stderr); status != 1 {
		t.Fatalf("status %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "check out the tag") {
		t.Errorf("stderr %q does not say to check out the tag", stderr.String())
	}
}
