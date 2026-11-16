// Package coverage is the coverage check of one specification: every
// requirement its document states is cited by a case of its own suite or
// listed as not machine-checked. It is apart from package check so that the
// commands, which run it, need none of the parsers the other checks use.
package coverage

import (
	"errors"
	"fmt"

	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// Check is the coverage check of one specification, whose files say l
// and whose suite is cases. It fails on a requirement that no case cites
// and the list does not give; on a case that cites an identifier the
// document does not state, or cites none; on a listed identifier that the
// document does not state, or that a case cites, which the list would then
// misreport; and on a case name that is empty or not unique.
func Check(s spec.Spec, l spec.Loaded, cases []runner.Case) error {
	var p []error
	addf := func(where, format string, args ...any) {
		p = append(p, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...)))
	}
	stated := map[string]bool{}
	for _, id := range l.Requirements {
		stated[id] = true
	}
	citedBy := map[string]string{}
	names := map[string]bool{}
	for i, c := range cases {
		where := s.Directory + "/cases"
		switch {
		case c.Name == "":
			addf(where, "case %d has no name", i+1)
		case names[c.Name]:
			addf(where, "two cases are named %q", c.Name)
		}
		names[c.Name] = true
		if len(c.Cites) == 0 {
			addf(where, "case %q cites no requirement", c.Name)
		}
		for _, id := range c.Cites {
			if !stated[id] {
				addf(where, "case %q cites %s, which %s does not state", c.Name, id, s.Document)
				continue
			}
			if _, ok := citedBy[id]; !ok {
				citedBy[id] = c.Name
			}
		}
	}
	listed := map[string]bool{}
	list := s.Directory + "/" + spec.ListFile
	for _, u := range l.Unchecked {
		listed[u.ID] = true
		switch {
		case !stated[u.ID]:
			addf(list, "lists %s, which %s does not state", u.ID, s.Document)
		case citedBy[u.ID] != "":
			addf(list, "lists %s as not machine-checked, and case %q cites it", u.ID, citedBy[u.ID])
		}
	}
	for _, id := range l.Requirements {
		if citedBy[id] == "" && !listed[id] {
			addf(s.Directory+"/"+s.Document, "%s is neither cited by a case of the suite nor listed in %s", id, spec.ListFile)
		}
	}
	return errors.Join(p...)
}
