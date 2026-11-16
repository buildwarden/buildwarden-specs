// Package cases is the collector-outputs suite: the cases that check an implementation
// against the requirements of collector-outputs/v1.md, each citing the ones it checks.
package cases

import "github.com/buildwarden/buildwarden-specs/conformance/runner"

// Cases are the suite's cases.
var Cases = []runner.Case{
	oneOutput,
}
