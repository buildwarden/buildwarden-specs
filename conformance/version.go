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
// were written from. It is kept by hand, in the change that changes a model.
// The ledger verifier's source is not a specification of this repository:
// its package comment names the commit of buildwarden/buildwarden it was
// written from.
var Models = []Model{
	// The claimant (package claimant), and the relay's claim endpoint
	// (package relay).
	{Directory: "relay-claim", Version: "v0.1.0"},
	// The collector that tests a relay (package collector), which also
	// serves the bootstrap config a relay carries, and the relay's side of
	// the collector protocol (package relay).
	{Directory: "collector-outputs", Version: "v0.1.0"},
	{Directory: "collector-inputs", Version: "v0.1.0"},
	{Directory: "bootstrap-config", Version: "v0.1.0"},
	// The build environment and its address lease (packages buildenv and
	// dhcp).
	{Directory: "relay-guest-api", Version: "v0.1.0"},
}
