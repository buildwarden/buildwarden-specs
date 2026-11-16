package conformance

import "testing"

// TestVersion holds the harness's CHANGELOG.md to the form its version is
// read from.
func TestVersion(t *testing.T) {
	v, err := Version()
	if err != nil {
		t.Fatal(err)
	}
	if v == "" {
		t.Fatal("empty version")
	}
}
