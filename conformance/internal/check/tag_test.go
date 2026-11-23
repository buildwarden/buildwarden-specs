package check

import (
	"testing"
	"testing/fstest"
)

func TestTag(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		change  func(fstest.MapFS)
		want    Tagged
		wantErr []string
	}{
		{name: "a specification at the head of its CHANGELOG.md", tag: "relay-claim/v0.3.1",
			want: Tagged{Dir: "relay-claim", Version: "v0.3.1", Release: "v0.3.1"}},
		{name: "the harness at the head of its CHANGELOG.md", tag: "conformance/v0.2.0",
			want: Tagged{Dir: "conformance", Version: "v0.2.0", Release: "v0.2.0"}},
		{name: "a -dev pre-release of the head of its CHANGELOG.md", tag: "relay-claim/v0.3.1-dev.1",
			want: Tagged{Dir: "relay-claim", Version: "v0.3.1-dev.1", Release: "v0.3.1", Prerelease: true}},
		{name: "an -rc pre-release of the head of its CHANGELOG.md", tag: "relay-claim/v0.3.1-rc.12",
			want: Tagged{Dir: "relay-claim", Version: "v0.3.1-rc.12", Release: "v0.3.1", Prerelease: true}},
		{name: "the harness's pre-release", tag: "conformance/v0.2.0-dev.3",
			want: Tagged{Dir: "conformance", Version: "v0.2.0-dev.3", Release: "v0.2.0", Prerelease: true}},
		{name: "a pre-release of an older version", tag: "relay-claim/v0.3.0-dev.1",
			wantErr: []string{"relay-claim/CHANGELOG.md: names v0.3.1 at its head, and the tag relay-claim/v0.3.0-dev.1 is a pre-release of v0.3.0"}},
		{name: "a pre-release of a version past the head", tag: "relay-claim/v0.4.0-rc.1",
			wantErr: []string{"names v0.3.1 at its head, and the tag relay-claim/v0.4.0-rc.1 is a pre-release of v0.4.0"}},
		{name: "a -beta suffix", tag: "relay-claim/v0.3.1-beta.1",
			wantErr: []string{`the tag "relay-claim/v0.3.1-beta.1" has a suffix that is not -dev.N or -rc.N`}},
		{name: "-dev with no number", tag: "relay-claim/v0.3.1-dev",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
		{name: "-dev.0", tag: "relay-claim/v0.3.1-dev.0",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
		{name: "a number with a leading zero", tag: "relay-claim/v0.3.1-rc.01",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
		{name: "two suffixes", tag: "relay-claim/v0.3.1-dev.1-rc.1",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
		{name: "build metadata after the suffix", tag: "relay-claim/v0.3.1-dev.1+abc",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
		{name: "a suffix on a version that is not vX.Y.Z", tag: "relay-claim/v0.3-dev.1",
			wantErr: []string{"has a suffix that is not -dev.N or -rc.N"}},
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
			got, err := Tag(fsys, tt.tag, specs)
			assertErr(t, err, tt.wantErr)
			if got != tt.want {
				t.Errorf("Tag(%q) = %+v, want %+v", tt.tag, got, tt.want)
			}
		})
	}
}
