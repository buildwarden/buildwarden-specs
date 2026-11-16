// Package runner runs a suite against an attachment and reports each case
// as passed, failed, or not applicable by what the target declares. There
// is no skip for a case the target should pass, and no retry.
//
// A suite is the package cases of a specification's module, which exports
// its cases as a []Case; the module's command hands them to the runner, and
// so does the module's own go test, with the harness's in-process
// attachment.
package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// Time limits of a case. They are constants of a harness release, not
// settings.
const (
	// CaseLimit is how long a case may run. Its context is done then.
	CaseLimit = 2 * time.Minute
	// CaseGrace is how long a case whose context is done has to return
	// before the runner reports it failed and goes on without it.
	CaseGrace = 10 * time.Second
)

// Case is one case of a suite.
type Case struct {
	// Name identifies the case in a report and is unique in its suite.
	Name string
	// Cites are the requirements the case checks, by identifier, all of its
	// own specification ("CLAIM-7"). The coverage check counts a requirement
	// as checked when a case of its own suite cites it.
	Cites []string
	// Role is the role of the component the case runs against: one of
	// target.Roles. The runner runs a case only against a target of its
	// role.
	Role string
	// Ends says that the case ends the instance it runs against (an
	// accepted claim, a completion), so it is given a fresh one. Cases that
	// leave their instance usable share one.
	Ends bool
	// Applies, when set, says whether the case applies to what the target
	// declares: it returns "" when it does, and otherwise the reason it
	// does not, which the report gives. It sees nothing but the
	// declaration, so a case is never found not applicable by what happened
	// when it ran.
	Applies func(d target.Declared) string
	// Run performs the case and reports a failure through t.
	Run func(t *T)
}

// Check holds a suite to the form the runner runs: every case named, once,
// with a role this harness knows and something to run.
func Check(cases []Case) error {
	var errs []error
	seen := map[string]bool{}
	for i, c := range cases {
		switch {
		case c.Name == "":
			errs = append(errs, fmt.Errorf("case %d has no name", i+1))
		case seen[c.Name]:
			errs = append(errs, fmt.Errorf("two cases are named %q", c.Name))
		}
		seen[c.Name] = true
		if !slices.Contains(target.Roles, c.Role) {
			errs = append(errs, fmt.Errorf("case %q: role %q is not one this harness knows (%v)", c.Name, c.Role, target.Roles))
		}
		if c.Run == nil {
			errs = append(errs, fmt.Errorf("case %q has nothing to run", c.Name))
		}
	}
	return errors.Join(errs...)
}

// Runner runs one specification's suite.
type Runner struct {
	// Spec and Version are the specification's directory and version, and
	// Harness the harness's version, which every case's report names.
	Spec    string
	Version string
	Harness string
	// Models is the table of the specification versions the harness's
	// models were written from, which every report carries.
	Models []string
	// Limit is a case's time limit; zero is CaseLimit. Only the harness's
	// own tests set it.
	Limit time.Duration
}

// Run runs the cases of the target's role against the attachment a, in
// their order, and reports each. Target names the target in the report.
// Every instance is stopped and a is closed before Run returns.
func (r Runner) Run(ctx context.Context, targetName string, a attach.Attachment, cases []Case) Report {
	d := a.Declared()
	rep := Report{
		Spec: r.Spec, Version: r.Version, Harness: r.Harness, Models: r.Models,
		Target: targetName, Role: d.Role, Launcher: d.Launcher,
	}
	shared := &instances{a: a, byParams: map[attach.Params]attach.Instance{}}
	for _, c := range cases {
		if c.Role != d.Role {
			continue
		}
		cr := CaseReport{Name: c.Name, Cites: c.Cites}
		switch reason := notApplicable(c, d); {
		case reason != "":
			cr.Result, cr.Reason = NotApplicable, reason
		default:
			cr.Failures = r.runCase(ctx, c, a, shared)
			cr.Result = Pass
			if len(cr.Failures) > 0 {
				cr.Result = Fail
			}
		}
		rep.Cases = append(rep.Cases, cr)
	}
	for _, err := range shared.stop() {
		rep.Errors = append(rep.Errors, fmt.Sprintf("stopping a shared instance: %v", err))
	}
	if err := a.Close(); err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("closing the attachment: %v", err))
	}
	return rep
}

func notApplicable(c Case, d target.Declared) string {
	if c.Ends && !d.FreshInstances {
		return "the target is one instance, and the case ends the instance it runs against"
	}
	if c.Applies != nil {
		return c.Applies(d)
	}
	return ""
}

// runCase runs one case to its end, or to its time limit and grace, and
// returns its failures, with the logs of the instances it used when it
// failed.
func (r Runner) runCase(ctx context.Context, c Case, a attach.Attachment, shared *instances) []string {
	limit := r.Limit
	if limit == 0 {
		limit = CaseLimit
	}
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	t := &T{ctx: cctx, c: c, a: a, shared: shared, fresh: &instances{a: a}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("the case panicked: %v", p)
			}
		}()
		c.Run(t)
	}()
	select {
	case <-done:
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			t.Errorf("the case ran past its time limit of %s", limit)
		}
	case <-cctx.Done():
		select {
		case <-done:
			if errors.Is(cctx.Err(), context.DeadlineExceeded) {
				t.Errorf("the case ran past its time limit of %s", limit)
			}
		case <-time.After(CaseGrace):
			t.Errorf("the case did not return within %s of its time limit of %s, and the runner went on without it", CaseGrace, limit)
		}
	}
	t.finish()
	return t.report()
}

// instances are the instances started for a case, or those shared by the
// cases that leave theirs usable, one for each Params.
type instances struct {
	a        attach.Attachment
	mu       sync.Mutex
	byParams map[attach.Params]attach.Instance
	started  []attach.Instance
}

func (s *instances) get(ctx context.Context, p attach.Params, share bool) (attach.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if share {
		if in, ok := s.byParams[p]; ok {
			return in, nil
		}
	}
	in, err := s.a.Start(ctx, p)
	if err != nil {
		return nil, err
	}
	if share {
		s.byParams[p] = in
	}
	s.started = append(s.started, in)
	return in, nil
}

func (s *instances) stop() []error {
	s.mu.Lock()
	started := s.started
	s.started = nil
	s.mu.Unlock()
	var errs []error
	for i := len(started) - 1; i >= 0; i-- {
		if err := started[i].Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
