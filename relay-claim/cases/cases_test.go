package cases_test

import (
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/inprocess"
	relayclaim "github.com/buildwarden/buildwarden-specs/relay-claim"
	"github.com/buildwarden/buildwarden-specs/relay-claim/cases"
)

// TestAgainstTheHarness runs the suite against the harness's own relay in
// each of its modes, and its own collector in each form.
func TestAgainstTheHarness(t *testing.T) {
	t.Parallel()
	inprocess.Suite(t, relayclaim.Spec, cases.Cases)
}
