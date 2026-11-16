package inprocess

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// TestSuite runs a suite of cases that start nothing, so that what is
// tested is Suite's walk over the configurations and not the models.
func TestSuite(t *testing.T) {
	t.Parallel()
	s := spec.Spec{Directory: "relay-claim", Prefix: "CLAIM", Document: "v1.md", Files: fstest.MapFS{
		"v1.md":                   {Data: []byte("# Claim\n\n**CLAIM-1.** The relay MUST.\n")},
		spec.ChangelogFile:        {Data: []byte("# Changelog\n\n## v0.1.0\n\n- First.\n")},
		"not-machine-checked.txt": {Data: []byte("")},
	}}
	var mu sync.Mutex
	seen := map[string]int{}
	note := func(t *runner.T) {
		mu.Lock()
		defer mu.Unlock()
		seen[t.Declared().Role+" "+t.Declared().Mode]++
	}
	Suite(t, s, []runner.Case{
		{Name: "relay", Cites: []string{"CLAIM-1"}, Role: "relay", Run: note},
		{Name: "collector", Cites: []string{"CLAIM-1"}, Role: "collector", Run: note},
	})
	want := map[string]int{"relay host": 1, "relay vm": 1, "relay container": 1, "collector ": len(Forms())}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("the cases ran in %v, want %v", seen, want)
	}
}

func TestNeverRun(t *testing.T) {
	t.Parallel()
	cases := []runner.Case{
		{Name: "ran", Role: "relay"},
		{Name: "ran once", Role: "relay"},
		{Name: "never applicable", Role: "relay"},
		{Name: "unreported", Role: "collector"},
	}
	reports := []runner.Report{
		{Target: "in-process host", Cases: []runner.CaseReport{
			{Name: "ran", Result: runner.Pass},
			{Name: "ran once", Result: runner.NotApplicable, Reason: "r1"},
			{Name: "never applicable", Result: runner.NotApplicable, Reason: "no frames"},
		}},
		{Target: "in-process vm", Cases: []runner.CaseReport{
			{Name: "ran", Result: runner.Fail},
			{Name: "ran once", Result: runner.Pass},
			{Name: "never applicable", Result: runner.NotApplicable, Reason: "no ip"},
		}},
	}
	got := neverRun(cases, reports)
	if len(got) != 2 {
		t.Fatalf("got %q, want two cases named", got)
	}
	for i, want := range []string{
		"case never applicable ran against no in-process configuration of the relay role (every configuration found it not applicable: in-process host: no frames; in-process vm: no ip)",
		"case unreported ran against no in-process configuration of the collector role (no configuration reported it)",
	} {
		if got[i] != want {
			t.Errorf("got %q\nwant %q", got[i], want)
		}
	}
}

func TestRoles(t *testing.T) {
	t.Parallel()
	got := roles([]runner.Case{{Role: "relay"}, {Role: "collector"}, {Role: "relay"}})
	if want := []string{"collector", "relay"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, r := range got {
		if !strings.Contains(strings.Join(target.Roles, " "), r) {
			t.Errorf("%s is not a role the harness knows", r)
		}
	}
}
