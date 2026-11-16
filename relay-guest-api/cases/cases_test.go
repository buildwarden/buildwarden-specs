package cases_test

import (
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/inprocess"
	relayguestapi "github.com/buildwarden/buildwarden-specs/relay-guest-api"
	"github.com/buildwarden/buildwarden-specs/relay-guest-api/cases"
)

// TestAgainstTheHarness runs the suite against the harness's own relay in
// each of its modes, and its own collector in each form.
func TestAgainstTheHarness(t *testing.T) {
	t.Parallel()
	inprocess.Suite(t, relayguestapi.Spec, cases.Cases)
}
