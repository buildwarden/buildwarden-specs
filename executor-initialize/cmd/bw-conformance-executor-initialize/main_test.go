package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/command"
	executorinitialize "github.com/buildwarden/buildwarden-specs/executor-initialize"
)

// TestRequirementsAllListed holds the command to what it is until S2's item
// adds the executor's cases: requirements -check passes, and every
// requirement is listed with the reason it has no case.
func TestRequirementsAllListed(t *testing.T) {
	t.Parallel()
	var out, errb bytes.Buffer
	if c := command.Main(executorinitialize.Spec, nil, []string{"requirements", "-check"}, &out, &errb); c != 0 {
		t.Fatalf("requirements -check exited %d: %s%s", c, out.String(), errb.String())
	}
	out.Reset()
	if c := command.Main(executorinitialize.Spec, nil, []string{"requirements"}, &out, &errb); c != 0 {
		t.Fatalf("requirements exited %d: %s", c, errb.String())
	}
	l, err := executorinitialize.Spec.Load()
	if err != nil {
		t.Fatal(err)
	}
	listed := 0
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "INIT-") {
			if !strings.Contains(line, "\tnot machine-checked: ") {
				t.Errorf("a requirement is not listed with a reason: %q", line)
			}
			listed++
		}
	}
	if want := len(l.Requirements); listed != want || want == 0 {
		t.Errorf("requirements printed %d requirements, and the document has %d", listed, want)
	}
}

// TestRunRunsNothing has run read a target file whose program does not
// exist: the command starts nothing, so it reports no case and succeeds.
func TestRunRunsNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tf := filepath.Join(dir, "relay.toml")
	body := `role = "relay"
os = ["linux", "darwin", "windows"]
launcher = "exec"

[exec]
argv = ["./no-such-relay", "-mode", "host"]

[relay]
mode = "host"
link = "frames"
build_link = { prefix = "10.100.0.0/30", relay = "10.100.0.1", guest = "10.100.0.2" }
`
	if err := os.WriteFile(tf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if c := command.Main(executorinitialize.Spec, nil, []string{"run", "-target", tf}, &out, &errb); c != 0 {
		t.Fatalf("run exited %d: %s%s", c, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "0 passed, 0 failed, 0 not applicable") {
		t.Errorf("run reported:\n%s", out.String())
	}
}
