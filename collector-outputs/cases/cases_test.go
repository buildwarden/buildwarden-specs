package cases_test

import (
	"testing"

	collectoroutputs "github.com/buildwarden/buildwarden-specs/collector-outputs"
	"github.com/buildwarden/buildwarden-specs/collector-outputs/cases"
	"github.com/buildwarden/buildwarden-specs/conformance/inprocess"
)

// TestAgainstTheHarness runs the suite against the harness's own collector
// in each form, and its own relay in each of its modes.
func TestAgainstTheHarness(t *testing.T) {
	t.Parallel()
	inprocess.Suite(t, collectoroutputs.Spec, cases.Cases)
}
