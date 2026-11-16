package command

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/buildwarden/buildwarden-specs/conformance"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

func testSpec(doc, list string) spec.Spec {
	return spec.Spec{
		Directory: "relay-claim",
		Prefix:    "CLAIM",
		Document:  "v1.md",
		Files: fstest.MapFS{
			"v1.md":            {Data: []byte(doc)},
			spec.ChangelogFile: {Data: []byte("# Changelog\n\n## v0.4.0\n")},
			spec.ListFile:      {Data: []byte(list)},
		},
	}
}

func TestSubcommands(t *testing.T) {
	harness, err := conformance.Version()
	if err != nil {
		t.Fatal(err)
	}
	threeReqs := testSpec("**CLAIM-1.** a\n\n**CLAIM-2.** b\n\n**CLAIM-3.** c\n", "CLAIM-2 a person reads it\n")
	dir := t.TempDir()
	relayTarget := filepath.Join(dir, "relay-host.toml")
	if err := os.WriteFile(relayTarget, []byte("role = \"relay\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	badTarget := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badTarget, []byte("role = \"driver\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cited := []runner.Case{
		{Name: "claim-ok", Cites: []string{"CLAIM-1"}},
		{Name: "claim-again", Cites: []string{"CLAIM-1"}},
	}
	tests := []struct {
		name       string
		s          spec.Spec
		cases      []runner.Case
		args       []string
		wantStatus int
		wantOut    string
		wantErr    string
	}{
		{name: "no subcommand", s: threeReqs, wantStatus: ExitUsage, wantErr: "usage:"},
		{name: "unknown subcommand", s: threeReqs, args: []string{"test"}, wantStatus: ExitUsage, wantErr: `unknown subcommand "test"`},
		{name: "help", s: threeReqs, args: []string{"help"}, wantStatus: ExitOK, wantErr: "bw-conformance-relay-claim run -target <file>"},
		{
			name: "version", s: threeReqs, args: []string{"version"}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0\nconformance " + harness + "\nmodels written from: none yet\n",
		},
		{name: "version takes no argument", s: threeReqs, args: []string{"version", "x"}, wantStatus: ExitUsage, wantErr: `unexpected argument "x"`},
		{name: "run without a target", s: threeReqs, args: []string{"run"}, wantStatus: ExitUsage, wantErr: "-target is required"},
		{name: "run with an unknown flag", s: threeReqs, args: []string{"run", "-x"}, wantStatus: ExitUsage, wantErr: "flag provided but not defined: -x"},
		{
			name: "run with no cases", s: threeReqs, args: []string{"run", "-target", relayTarget}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0: the suite has no cases yet; nothing was run against " + relayTarget + " (role relay)\n",
		},
		{
			name: "run against a bad target file", s: threeReqs, args: []string{"run", "-target", badTarget}, wantStatus: ExitFail,
			wantErr: `role "driver" is not one this harness knows`,
		},
		{
			name: "run against a missing target file", s: threeReqs, args: []string{"run", "-target", filepath.Join(dir, "absent.toml")}, wantStatus: ExitFail,
			wantErr: "absent.toml",
		},
		{
			name: "run with cases", s: threeReqs, cases: cited, args: []string{"run", "-target", relayTarget}, wantStatus: ExitFail,
			wantErr: "relay-claim v0.4.0 has 2 cases, and this harness cannot run cases yet",
		},
		{
			name: "requirements", s: threeReqs, cases: cited, args: []string{"requirements"}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0 (v1.md)\n" +
				"CLAIM-1\tcases: claim-ok, claim-again\n" +
				"CLAIM-2\tnot machine-checked: a person reads it\n" +
				"CLAIM-3\tneither cited by a case nor listed as not machine-checked\n",
		},
		{
			name: "requirements of a skeleton", s: testSpec("# t\n", ""), args: []string{"requirements"}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0 (v1.md)\nno requirements yet\n",
		},
		{
			name: "requirements -check fails on a requirement with no case", s: threeReqs, cases: cited, args: []string{"requirements", "-check"}, wantStatus: ExitFail,
			wantErr: "relay-claim/v1.md: CLAIM-3 is neither cited by a case of the suite nor listed in not-machine-checked.txt",
		},
		{
			name: "requirements -check passes when covered", s: testSpec("**CLAIM-1.** a\n\n**CLAIM-2.** b\n", "CLAIM-2 a person reads it\n"),
			cases: cited, args: []string{"requirements", "-check"}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0: 2 requirements, 2 cases, 1 listed as not machine-checked: covered\n",
		},
		{
			name: "requirements -check passes on a skeleton", s: testSpec("# t\n", ""), args: []string{"requirements", "-check"}, wantStatus: ExitOK,
			wantOut: "relay-claim v0.4.0: 0 requirements, 0 cases, 0 listed as not machine-checked: covered\n",
		},
		{
			name: "a malformed document fails", s: testSpec("**CLAIM-01.** a\n", ""), args: []string{"requirements"}, wantStatus: ExitFail,
			wantErr: `relay-claim/v1.md: line 1: "CLAIM-01" is not a requirement identifier`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := Main(tt.s, tt.cases, tt.args, &stdout, &stderr)
			if status != tt.wantStatus {
				t.Errorf("status %d, want %d (stderr %q)", status, tt.wantStatus, stderr.String())
			}
			if tt.wantOut != "" && stdout.String() != tt.wantOut {
				t.Errorf("stdout %q, want %q", stdout.String(), tt.wantOut)
			}
			if tt.wantOut == "" && stdout.Len() > 0 {
				t.Errorf("unexpected stdout %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantErr)
			}
		})
	}
}
