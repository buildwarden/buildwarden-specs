package bootstrapconfig

import "testing"

// TestSpecLoads holds the directory's document, list and CHANGELOG.md to the
// forms the README's conventions give them.
func TestSpecLoads(t *testing.T) {
	if _, err := Spec.Load(); err != nil {
		t.Fatal(err)
	}
}
