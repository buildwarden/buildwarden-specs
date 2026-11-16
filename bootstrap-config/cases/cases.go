// Package cases is the bootstrap-config suite: the cases that check an implementation
// against the requirements of bootstrap-config/v1.md, each citing the ones it checks.
//
// Against a relay it checks the carrier (BOOTCFG-1 to BOOTCFG-3), and
// against a collector the document the producer supplied it (BOOTCFG-4 to
// BOOTCFG-6). It runs no executor: the executor's requirements are listed
// in not-machine-checked.txt.
package cases

import "github.com/buildwarden/buildwarden-specs/conformance/runner"

// Cases are the suite's cases.
var Cases = []runner.Case{
	carriesAccepted,
	carriesRejected,
	collectorHasNone,
	collectorFails,
	collectorUnreachable,
	producedValid,
	producedSame,
	producedNone,
}
