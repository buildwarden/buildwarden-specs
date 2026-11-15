// Package runner holds what a suite is made of: cases, each naming the
// requirements of its own specification that it checks. A suite is the
// package cases of a specification's module, which exports its cases as a
// []Case; the command of that module hands them to the runner.
package runner

import "fmt"

// Case is one case of a suite.
type Case struct {
	// Name identifies the case in a report and is unique in its suite.
	Name string
	// Cites are the requirements the case checks, by identifier, all of its
	// own specification ("CLAIM-7"). The coverage check counts a requirement
	// as checked when a case of its own suite cites it.
	Cites []string
	// Run performs the case and reports a failure through t.
	Run func(t *T)
}

// T is what a running case reports through. Stage 4a of the harness gives it
// the component under test and the roles around it.
type T struct {
	failures []string
}

// Errorf records a failure of the case and lets it go on.
func (t *T) Errorf(format string, args ...any) {
	t.failures = append(t.failures, fmt.Sprintf(format, args...))
}

// Failed reports whether the case has recorded a failure.
func (t *T) Failed() bool { return len(t.failures) > 0 }

// Failures returns the failures the case recorded, in order.
func (t *T) Failures() []string { return append([]string(nil), t.failures...) }
