// Package cases is the relay-guest-api suite: the cases that check an implementation
// against the requirements of relay-guest-api/v1.md, each citing the ones it checks.
package cases

import "github.com/buildwarden/buildwarden-specs/conformance/runner"

// Cases are the suite's cases. Those below HTTP come first: the relay's
// address and ports, the frame link, the address lease, DNS, and the
// upstream dials the relay refuses.
var Cases = []runner.Case{
	ownAddress,
	interfacePorts,
	beforeClaim,
	arpAnswered,
	macLearned,
	announced,
	captured,
	udpOnly,
	leaseAnswered,
	leaseStateless,
	leaseIgnores,
	dnsServed,
	reservedA,
	reservedOther,
	forwardFirst,
	forwardRefused,
	forwardSilent,
	servfail,
	refusedLink,
	refusedHost,
	refusedAny,
}
