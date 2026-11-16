// Package cases is the collector-outputs suite: the cases that check an implementation
// against the requirements of collector-outputs/v1.md, each citing the ones it checks.
package cases

import "github.com/buildwarden/buildwarden-specs/conformance/runner"

// Cases are the suite's cases: first those of the collector role, then
// those of the relay role.
var Cases = []runner.Case{
	oneOutput,
	eachOutput,
	ledgerAnswered,
	artifactNamesRefused,
	artifactsStored,
	capturesNamed,
	capturesStored,
	capturesWithoutHash,
	environmentStored,
	environmentOverLimit,
	methodsRefused,
	unauthorizedOutputs,
	noTokenNeeded,
	tokenless,
	consoleStored,

	outputMethods,
	baseURL,
	noTokenSent,
	ledgerFirst,
	capturesHashed,
	environmentFirst,
	environmentTooLarge,
	notStored,
}
