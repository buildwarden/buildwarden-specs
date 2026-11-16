// Package cases is the collector-inputs suite: the cases that check an implementation
// against the requirements of collector-inputs/v1.md, each citing the ones it checks.
package cases

import "github.com/buildwarden/buildwarden-specs/conformance/runner"

// Cases are the suite's cases: first those of the collector role, then
// those of the relay role.
var Cases = []runner.Case{
	scriptServed,
	noScriptServed,
	bootstrapServed,
	noBootstrapServed,
	contextServed,
	contextEmpty,
	contextUnsafe,
	contextMissing,
	noContextServed,
	contextLinks,
	inputMethods,
	signalsAnswered,
	signalMethods,
	completionRead,
	statusRunning,
	statusCompleted,
	healthz,
	unauthorizedInputs,
	tokenless,

	inputsOnRequest,
	noTokenSent,
	notAnInput,
	contextPaths,
	heartbeatForwarded,
	readyOnce,
	completionSent,
	signalsNotDelivered,
	completionUnanswered,
}
