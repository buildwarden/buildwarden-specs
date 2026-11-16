package inprocess

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// Suite is a specification module's self-test: it runs the suite cases of
// the specification s against each in-process configuration of each role
// the cases have, each configuration as a parallel subtest of t named
// "<role>/<configuration>". It fails t for a suite the runner would not run,
// for a case that fails or a run with an error, with the run's report, and
// for a case that is not applicable in every configuration of its role,
// since each case must run at least once against the harness's own model
// of that role.
func Suite(t *testing.T, s spec.Spec, cases []runner.Case) {
	t.Helper()
	r, err := newRunner(s, cases)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []runner.Report
	t.Run("in-process", func(t *testing.T) {
		for _, role := range roles(cases) {
			for _, c := range Configurations(role) {
				t.Run(role+"/"+c.Name, func(t *testing.T) {
					t.Parallel()
					rep, err := runOne(t.Context(), r, c, cases)
					if err != nil {
						t.Fatal(err)
					}
					mu.Lock()
					reports = append(reports, rep)
					mu.Unlock()
					if rep.Failed() {
						var b bytes.Buffer
						_ = rep.Write(&b)
						t.Errorf("the suite failed against %s:\n%s", rep.Target, b.String())
					}
				})
			}
		}
	})
	for _, msg := range neverRun(cases, reports) {
		t.Error(msg)
	}
}

// newRunner is the runner of s's suite, as its command builds it.
func newRunner(s spec.Spec, cases []runner.Case) (runner.Runner, error) {
	l, err := s.Load()
	if err != nil {
		return runner.Runner{}, err
	}
	if err := runner.Check(cases); err != nil {
		return runner.Runner{}, fmt.Errorf("the suite:\n%w", err)
	}
	h, err := conformance.Version()
	if err != nil {
		return runner.Runner{}, err
	}
	return runner.Runner{Spec: s.Directory, Version: l.Version, Harness: h, Models: conformance.ModelList()}, nil
}

// runOne runs the cases against a fresh attachment of configuration c, which
// the runner closes.
func runOne(ctx context.Context, r runner.Runner, c Configuration, cases []runner.Case) (runner.Report, error) {
	a, err := c.New()
	if err != nil {
		return runner.Report{}, fmt.Errorf("the in-process configuration %s: %w", c.Name, err)
	}
	return r.Run(ctx, "in-process "+c.Name, a, cases), nil
}

// roles are the roles the cases have, in a fixed order.
func roles(cases []runner.Case) []string {
	var out []string
	for _, c := range cases {
		if !slices.Contains(out, c.Role) {
			out = append(out, c.Role)
		}
	}
	sort.Strings(out)
	return out
}

// neverRun names each case that no report ran: one reported not applicable
// by every configuration of its role, with each reason given.
func neverRun(cases []runner.Case, reports []runner.Report) []string {
	ran := map[string]bool{}
	reasons := map[string][]string{}
	for _, rep := range reports {
		for _, cr := range rep.Cases {
			if cr.Result == runner.NotApplicable {
				reasons[cr.Name] = append(reasons[cr.Name], rep.Target+": "+cr.Reason)
			} else {
				ran[cr.Name] = true
			}
		}
	}
	var out []string
	for _, c := range cases {
		if ran[c.Name] {
			continue
		}
		why := "no configuration reported it"
		if rs := reasons[c.Name]; len(rs) > 0 {
			sort.Strings(rs)
			why = "every configuration found it not applicable: " + strings.Join(rs, "; ")
		}
		out = append(out, fmt.Sprintf("case %s ran against no in-process configuration of the %s role (%s)", c.Name, c.Role, why))
	}
	return out
}
