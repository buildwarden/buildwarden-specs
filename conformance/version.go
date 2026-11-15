package conformance

import (
	_ "embed"
	"fmt"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

//go:embed CHANGELOG.md
var changelog []byte

// Version returns the harness's version, the one at the head of its
// CHANGELOG.md, which is what its tag conformance/vX.Y.Z will name.
func Version() (string, error) {
	v, err := spec.ChangelogVersion(changelog)
	if err != nil {
		return "", fmt.Errorf("conformance/%s: %w", spec.ChangelogFile, err)
	}
	return v, nil
}

// Model names a specification and the version of it that the harness's
// models of its roles were written from.
type Model struct {
	Directory string
	Version   string
}

// Models is the table of the specification versions the harness's models
// were written from. It is kept by hand, in the change that changes a model;
// it is empty until the first model is written.
var Models = []Model{}
