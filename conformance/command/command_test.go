package command

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance"
	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// TestMain runs the test binary as a collector when the environment says
// so: it prints its one argument and exits.
func TestMain(m *testing.M) {
	if os.Getenv("BW_COMMAND_HELPER") == "" {
		os.Exit(m.Run())
	}
	fmt.Println(os.Args[len(os.Args)-1])
	os.Exit(0)
}

const relayHost = `role = "relay"
os = ["linux", "darwin", "windows"]
launcher = "exec"
[exec]
argv = ["relay", "-claim-addr", "{claim}"]
[relay]
mode = "host"
link = "frames"
build_link = { prefix = "192.0.2.0/30", relay = "192.0.2.1", guest = "192.0.2.2" }
`

// collectorText is a collector target that runs the test binary, which
// prints say.
func collectorText(t *testing.T, say string) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return `role = "collector"
os = ["linux", "darwin", "windows"]
launcher = "exec"
[exec]
argv = ['` + exe + `', "{claim}", "{out}", ["{script}"], ["{context}"], ` + say + `]
env = { BW_COMMAND_HELPER = "1" }
[collector]
attachment = "claims"
forms = { no_script = true, no_context = true }
`
}

func otherOS() string {
	if runtime.GOOS == "plan9" || runtime.GOOS == "linux" {
		return "windows"
	}
	return "linux"
}

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
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	relayTarget := write("relay-host.toml", relayHost)
	collectorTarget := write("collector.toml", collectorText(t, `"pass"`))
	failingTarget := write("failing.toml", collectorText(t, `"fail"`))
	elsewhere := write("elsewhere.toml", strings.Replace(collectorText(t, `"pass"`), `os = ["linux", "darwin", "windows"]`, `os = ["`+otherOS()+`"]`, 1))
	badTarget := write("bad.toml", "role = \"driver\"\n")
	listensTarget := write("listens.toml", "role = \"collector\"\nos = [\"linux\", \"darwin\", \"windows\"]\nlauncher = \"external\"\n"+
		"[external]\nurl = \"https://c.example/\"\nsession_token = [\"s\"]\n[collector]\nattachment = \"listens\"\n")
	run := func(t *runner.T) {
		in := t.Instance(attach.Params{Claim: "127.0.0.1:9", Out: "out", Capture: "none"})
		for in.Exit() == "" {
			if t.Context().Err() != nil {
				t.Fatalf("the collector did not exit")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !strings.Contains(string(in.Log()), "pass") {
			t.Errorf("the collector said: %s", in.Log())
		}
	}
	cited := []runner.Case{
		{Name: "claim-ok", Cites: []string{"CLAIM-1"}, Role: "collector", Run: run},
		{Name: "claim-again", Cites: []string{"CLAIM-1"}, Role: "collector", Run: run},
	}
	header := func(target, role string) string {
		return "relay-claim v0.4.0, conformance " + harness + ", against " + target + " (" + role + ", exec)\nmodels written from: " + modelsLine() + "\n"
	}
	line := func(result, name string) string {
		return result + "\trelay-claim v0.4.0\tconformance " + harness + "\t" + name + "\tCLAIM-1\n"
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
			wantOut: "relay-claim v0.4.0\nconformance " + harness + "\n" + modelsTable(),
		},
		{name: "version takes no argument", s: threeReqs, args: []string{"version", "x"}, wantStatus: ExitUsage, wantErr: `unexpected argument "x"`},
		{name: "run without a target", s: threeReqs, args: []string{"run"}, wantStatus: ExitUsage, wantErr: "-target is required"},
		{name: "run with an unknown flag", s: threeReqs, args: []string{"run", "-x"}, wantStatus: ExitUsage, wantErr: "flag provided but not defined: -x"},
		{
			name: "run with no cases", s: threeReqs, args: []string{"run", "-target", relayTarget}, wantStatus: ExitOK,
			wantOut: header(relayTarget, "relay") + "the suite has no cases for a relay target; nothing was run\n" +
				"relay-claim v0.4.0, conformance " + harness + ", against " + relayTarget + ": 0 passed, 0 failed, 0 not applicable\n",
		},
		{
			name: "run with no cases for the target's role", s: threeReqs, cases: cited, args: []string{"run", "-target", relayTarget}, wantStatus: ExitOK,
			wantOut: header(relayTarget, "relay") + "the suite has no cases for a relay target; nothing was run\n" +
				"relay-claim v0.4.0, conformance " + harness + ", against " + relayTarget + ": 0 passed, 0 failed, 0 not applicable\n",
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
			name: "run with cases", s: threeReqs, cases: cited, args: []string{"run", "-target", collectorTarget}, wantStatus: ExitOK,
			wantOut: header(collectorTarget, "collector") + line("pass", "claim-ok") + line("pass", "claim-again") +
				"relay-claim v0.4.0, conformance " + harness + ", against " + collectorTarget + ": 2 passed, 0 failed, 0 not applicable\n",
		},
		{
			name: "run with a failing case", s: threeReqs, cases: cited[:1], args: []string{"run", "-target", failingTarget}, wantStatus: ExitFail,
			wantOut: "\nrelay-claim v0.4.0, conformance " + harness + ", against " + failingTarget + ": 0 passed, 1 failed, 0 not applicable\n",
		},
		{
			name: "run against a target for another host", s: threeReqs, cases: cited, args: []string{"run", "-target", elsewhere}, wantStatus: ExitFail,
			wantErr: elsewhere + " declares os " + otherOS() + ", and this host's is " + runtime.GOOS,
		},
		{
			name: "run against an attachment not built", s: threeReqs, cases: cited, args: []string{"run", "-target", listensTarget}, wantStatus: ExitFail,
			wantErr: "a collector that listens is named by the target-file format and not built by this harness yet",
		},
		{
			name: "run a suite the runner refuses", s: threeReqs, cases: []runner.Case{{Name: "x", Cites: []string{"CLAIM-1"}, Role: "driver", Run: run}},
			args: []string{"run", "-target", collectorTarget}, wantStatus: ExitFail,
			wantErr: `case "x": role "driver" is not one this harness knows`,
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
			if strings.HasPrefix(tt.wantOut, "\n") {
				if !strings.HasSuffix(stdout.String(), tt.wantOut) {
					t.Errorf("stdout %q does not end %q", stdout.String(), tt.wantOut)
				}
			} else if tt.wantOut != "" && stdout.String() != tt.wantOut {
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

// modelsLine is the table of the models' versions as a report's header
// gives it, and modelsTable as the version subcommand prints it.
func modelsLine() string {
	var out []string
	for _, m := range conformance.Models {
		out = append(out, m.Directory+" "+m.Version)
	}
	if len(out) == 0 {
		return "none yet"
	}
	return strings.Join(out, ", ")
}

func modelsTable() string {
	if len(conformance.Models) == 0 {
		return "models written from: none yet\n"
	}
	out := "models written from:\n"
	for _, m := range conformance.Models {
		out += "  " + m.Directory + " " + m.Version + "\n"
	}
	return out
}
