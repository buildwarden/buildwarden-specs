package runner

import (
	"fmt"
	"io"
	"strings"
)

// Result is a case's verdict.
type Result int

// The verdicts. There is no skip.
const (
	Pass Result = iota + 1
	Fail
	NotApplicable
)

func (r Result) String() string {
	switch r {
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	case NotApplicable:
		return "n/a"
	}
	return "unknown"
}

// CaseReport is one case's line of a report.
type CaseReport struct {
	Name   string
	Cites  []string
	Result Result
	// Reason is why a case is not applicable.
	Reason string
	// Failures are a failed case's failures, its log lines and its
	// instances' output.
	Failures []string
}

// Report is what a run of one suite against one target found.
type Report struct {
	Spec     string
	Version  string
	Harness  string
	Models   []string
	Target   string
	Role     string
	Launcher string
	Cases    []CaseReport
	// Errors are what went wrong around the cases, such as closing the
	// attachment; any fails the run.
	Errors []string
}

// Counts are the numbers of cases passed, failed and not applicable.
func (r Report) Counts() (passed, failed, notApplicable int) {
	for _, c := range r.Cases {
		switch c.Result {
		case Pass:
			passed++
		case Fail:
			failed++
		case NotApplicable:
			notApplicable++
		}
	}
	return passed, failed, notApplicable
}

// Failed reports whether a case failed or the run had an error.
func (r Report) Failed() bool {
	_, failed, _ := r.Counts()
	return failed > 0 || len(r.Errors) > 0
}

// Write writes the report as text: a header naming the specification, the
// harness and the target, with the models' table; one line for each case,
// tab-separated, naming its verdict, the specification and its version, the
// harness's version, the case and the requirements it cites, followed for a
// failure by its failures, indented, and for a case not applicable by the
// reason; and a last line with the counts.
func (r Report) Write(w io.Writer) error {
	var b strings.Builder
	launcher := r.Launcher
	if launcher == "" {
		launcher = "in-process"
	}
	fmt.Fprintf(&b, "%s %s, conformance %s, against %s (%s, %s)\n", r.Spec, r.Version, r.Harness, r.Target, r.Role, launcher)
	models := "none yet"
	if len(r.Models) > 0 {
		models = strings.Join(r.Models, ", ")
	}
	fmt.Fprintf(&b, "models written from: %s\n", models)
	if len(r.Cases) == 0 {
		fmt.Fprintf(&b, "the suite has no cases for a %s target; nothing was run\n", r.Role)
	}
	for _, c := range r.Cases {
		fmt.Fprintf(&b, "%s\t%s %s\tconformance %s\t%s\t%s", c.Result, r.Spec, r.Version, r.Harness, c.Name, strings.Join(c.Cites, " "))
		if c.Result == NotApplicable {
			fmt.Fprintf(&b, "\tnot applicable: %s", c.Reason)
		}
		b.WriteString("\n")
		for _, f := range c.Failures {
			b.WriteString(indent(f))
		}
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "error: %s\n", e)
	}
	passed, failed, na := r.Counts()
	fmt.Fprintf(&b, "%s %s, conformance %s, against %s: %d passed, %d failed, %d not applicable\n", r.Spec, r.Version, r.Harness, r.Target, passed, failed, na)
	_, err := io.WriteString(w, b.String())
	return err
}

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	return "\t" + strings.ReplaceAll(s, "\n", "\n\t") + "\n"
}
