// Package target reads a target file: the TOML file that describes a
// component under test to the harness. This is its first form, which reads
// the role; the launchers and the attachment points join it with the
// harness's core.
package target

import (
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Roles are the roles of a component under test that this harness knows.
var Roles = []string{"relay", "collector"}

// File is what a target file says.
type File struct {
	// Role is the role of the component under test: one of Roles.
	Role string `toml:"role"`
}

// Read reads and checks the target file at path.
func Read(path string) (File, error) {
	var f File
	if _, err := toml.DecodeFile(path, &f); err != nil {
		return File{}, fmt.Errorf("target file %s: %w", path, err)
	}
	if err := f.check(); err != nil {
		return File{}, fmt.Errorf("target file %s: %w", path, err)
	}
	return f, nil
}

func (f File) check() error {
	known := strings.Join(Roles, ", ")
	switch {
	case f.Role == "":
		return fmt.Errorf("role is missing; this harness knows %s", known)
	case !slices.Contains(Roles, f.Role):
		return fmt.Errorf("role %q is not one this harness knows (%s)", f.Role, known)
	}
	return nil
}
