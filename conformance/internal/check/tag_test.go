package check

import (
	"testing"
	"testing/fstest"
)

func TestTag(t *testing.T) {
	tests := []struct {
		name        string
		tag         string
		change      func(fstest.MapFS)
		wantDir     string
		wantVersion string
		wantErr     []string
	}{
		{name: "a specification at the head of its CHANGELOG.md", tag: "relay-claim/v0.3.1",
			wantDir: "relay-claim", wantVersion: "v0.3.1"},
		{name: "the harness at the head of its CHANGELOG.md", tag: "conformance/v0.2.0",
			wantDir: "conformance", wantVersion: "v0.2.0"},
		{name: "an older version of the directory", tag: "relay-claim/v0.3.0",
			wantErr: []string{"relay-claim/CHANGELOG.md: names v0.3.1 at its head, and the tag is relay-claim/v0.3.0"}},
		{name: "a version no heading names", tag: "collector-inputs/v1.0.0",
			wantErr: []string{"names v0.3.1 at its head, and the tag is collector-inputs/v1.0.0"}},
		{name: "a version that is not vX.Y.Z", tag: "relay-claim/v0.3",
			wantErr: []string{"names v0.3.1 at its head, and the tag is relay-claim/v0.3"}},
		{name: "a directory that is no module here", tag: "build-ledger/v0.1.0",
			wantErr: []string{`the tag "build-ledger/v0.1.0" names build-ledger, which is not the harness's directory or one of the specifications`}},
		{name: "a tag with no directory", tag: "v0.6.0",
			wantErr: []string{`the tag "v0.6.0" is not <directory>/vX.Y.Z`}},
		{name: "a tag with two slashes", tag: "relay-claim/x/v0.3.1",
			wantErr: []string{`the tag "relay-claim/x/v0.3.1" is not <directory>/vX.Y.Z`}},
		{name: "a CHANGELOG.md with no version heading", tag: "relay-claim/v0.3.1",
			change:  set("relay-claim/CHANGELOG.md", "# Changelog\n"),
			wantErr: []string{"relay-claim/CHANGELOG.md: no version heading"}},
		{name: "a directory with no CHANGELOG.md", tag: "relay-claim/v0.3.1",
			change:  remove("relay-claim/CHANGELOG.md"),
			wantErr: []string{"relay-claim/CHANGELOG.md: open relay-claim/CHANGELOG.md"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := modules()
			if tt.change != nil {
				tt.change(fsys)
			}
			dir, version, err := Tag(fsys, tt.tag, specs)
			assertErr(t, err, tt.wantErr)
			if dir != tt.wantDir || version != tt.wantVersion {
				t.Errorf("Tag(%q) = %q, %q, want %q, %q", tt.tag, dir, version, tt.wantDir, tt.wantVersion)
			}
		})
	}
}
