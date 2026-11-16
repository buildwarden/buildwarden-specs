// Package cases is the relay-claim suite: the cases that check an implementation
// against the requirements of relay-claim/v1.md, each citing the ones it checks.
//
// The relay's cases run against a relay target. Those that leave the relay
// as they found it share one instance: the refusals by method and by token,
// and the claims refused without a tunnel. Every other one claims, or may
// spend, the instance it uses and so starts its own, and the field cases
// send all their refusals to one fresh relay with its tunnel open before a
// valid claim, so that they also show the relay claimable after each.
//
// The claimant's cases run against a collector target that is its own
// claimant: the harness's relay is claimed by it through a recorder that
// reads what it sends.
//
// Not applicable by what a target declares, besides the role: the token
// cases to a relay that cannot be started with a token (or without one);
// the cases of one mode to the others (vm: CLAIM-37, CLAIM-38; host:
// CLAIM-39; container: CLAIM-40; vm and host: CLAIM-41 and the refusal of
// CLAIM-32); the host-mode case with a build_link to a relay whose build
// link is not a frame link; the resolver configuration's cases to a relay
// the harness gives none; and the claimant's cases to a collector that does
// not claim.
package cases

import (
	"slices"

	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// Cases are the suite's cases.
var Cases = slices.Concat([]runner.Case{
	// The shared relay, which is never claimed.
	methodsRefused,
	tokenRefused,
	noTunnelOpen,
	unknownFieldNamed,
	// A relay for each case.
	authorizedClaim,
	unauthorizedConsumesNothing,
	noToken,
	oneTunnel,
	whileProcessing,
	refusedKeepsClaimable,
	undecodable,
	collectorURLRequired,
	buildLinkInvalid,
	upstreamDNSInvalid,
	claimLimit,
	collectorAtURL,
	collectorUnreachable,
	environmentUnusable,
	resolverOrder,
	resolverDefault,
	noUsableResolver,
	vmLink,
	vmNoLink,
	hostLink,
	hostNoLink,
	containerRefusesLink,
	noDialIntoLink,
	beforeTheReply,
	readyRefused,
	afterTheClaim,
	ledgerSigned,
	// The claimant.
	claimantRequests,
	claimantRetries,
}, collectorToken(), captureModes(), upstreamRoots(), environmentLanded(), resolverFailover())
