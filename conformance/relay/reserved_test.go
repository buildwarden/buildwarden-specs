package relay

import "testing"

// TestValidName checks GUEST-28 for an artifact's name and GUEST-33 for a
// context path: a context path's segment may start with ".", "-" or "_" but,
// like an artifact's, does not end with one.
func TestValidName(t *testing.T) {
	cases := []struct {
		name            string
		artifact, ctxOK bool
	}{
		{"a", true, true},
		{"dir/file.txt", true, true},
		{".warden/x", false, true},
		{"-a/_b", false, true},
		{"a.", false, false},
		{"a-", false, false},
		{"dir/b_", false, false},
		{"dir./b", false, false},
		{".", false, false},
		{"..", false, false},
		{"a/../b", false, false},
		{"a//b", false, false},
		{"/a", false, false},
		{"a/", false, false},
		{"", false, false},
		{"a b", false, false},
	}
	for _, c := range cases {
		if got := validName(c.name, false); got != c.artifact {
			t.Errorf("validName(%q, artifact) = %v, want %v", c.name, got, c.artifact)
		}
		if got := validName(c.name, true); got != c.ctxOK {
			t.Errorf("validName(%q, context) = %v, want %v", c.name, got, c.ctxOK)
		}
	}
}
