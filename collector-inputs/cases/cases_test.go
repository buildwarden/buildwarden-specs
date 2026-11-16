package cases_test

import (
	"testing"

	collectorinputs "github.com/buildwarden/buildwarden-specs/collector-inputs"
	"github.com/buildwarden/buildwarden-specs/collector-inputs/cases"
	"github.com/buildwarden/buildwarden-specs/conformance/inprocess"
)

// TestAgainstTheHarness runs the suite against the harness's own collector
// in each form, and its own relay in each of its modes.
func TestAgainstTheHarness(t *testing.T) {
	t.Parallel()
	inprocess.Suite(t, collectorinputs.Spec, cases.Cases)
}
