package cases

import (
	"testing"

	bootstrapconfig "github.com/buildwarden/buildwarden-specs/bootstrap-config"
	"github.com/buildwarden/buildwarden-specs/conformance/inprocess"
)

// TestAgainstTheHarness runs the suite against the harness's own relay in
// each of its modes, and its own collector in each form.
func TestAgainstTheHarness(t *testing.T) {
	t.Parallel()
	inprocess.Suite(t, bootstrapconfig.Spec, Cases)
}

// TestBeyondSchema holds the check of BOOTCFG-4 (b) to the bodies the
// schema passes and the requirement does not, and to the two documents the
// reference producer sends.
func TestBeyondSchema(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{
		`{"version":1,"trust":{"mode":"exclusive"}}`,
		`{"version":1,"trust":{"mode":"append"}}`,
		`{"version": 1}`,
	} {
		if err := beyondSchema([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
		if err := bootstrapconfig.Spec.Validate(schemaFile, []byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"version":1.0}`,
		`{"version":1e0}`,
		"\xef\xbb\xbf{\"version\":1}",
		`{"version":1,"version":1}`,
		`{"version":1,"trust":{"mode":"append","mode":"append"}}`,
		"{\"version\":1,\"trust\":{\"mode\":\"\xff\"}}",
	} {
		if err := beyondSchema([]byte(bad)); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}
