// Package attach is the one interface through which the runner gives a case
// the component under test and the networks the harness's roles use around
// it. A case is written once against it and does not know whether a
// launcher or the harness itself stands behind it. Every role takes its
// listeners and connections from an attachment's Network and never opens a
// socket of its own choosing, so the same role runs on the host's network,
// in a sandbox, or on the harness's in-memory network.
package attach

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// Side names one side of the component under test, on which the harness's
// roles listen and dial.
type Side int

// The sides of a component under test.
const (
	// Claim is where a relay's claim endpoint is, and where the harness's
	// relay waits for a collector that claims.
	Claim Side = iota + 1
	// Build is a relay's build link on an "ip" link: where the harness's
	// build environment connects.
	Build
	// Upstream is the relay's upstream network: where the harness's
	// resolver and origin servers listen.
	Upstream
)

func (s Side) String() string {
	switch s {
	case Claim:
		return "claim"
	case Build:
		return "build"
	case Upstream:
		return "upstream"
	}
	return "unknown"
}

// Network is where the harness's roles listen and dial on one side.
type Network interface {
	// Address is the harness's own address on this side: the host a role
	// listens on.
	Address() netip.Addr
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Params are what one start of the component under test is given. A value
// left empty is not given: the optional part of a command line that holds
// it is left out. Two starts with equal Params are the same start, which is
// how the runner shares one instance among the cases that leave it usable.
type Params struct {
	// NoClaimToken starts a relay without a claim token.
	NoClaimToken bool

	// Claim is the claim address a collector that claims is started
	// against, and Token the claim token it sends there.
	Claim string
	Token string
	// Out, Context, Script and Capture are a collector's output location,
	// build context directory, build script file and capture mode.
	Out     string
	Context string
	Script  string
	Capture string
}

// Endpoint is a relay's claim endpoint and the claim token it was started
// with, empty when it has none.
type Endpoint struct {
	Address string
	Token   string
}

// Instance is one started instance of the component under test.
type Instance interface {
	// Claim is a relay instance's claim endpoint; it is empty for a
	// collector.
	Claim() Endpoint
	// ReadBack returns a directory, in the disk layout, of what a
	// collector instance stored. It is called after the session's
	// completion and is an error for a target that declares no read-back.
	ReadBack(ctx context.Context) (string, error)
	// Log is what the component wrote, attached to a failure and never
	// asserted on.
	Log() []byte
	// Exit is how the component ended, or empty while it runs. Like the
	// log, it is attached to a failure and never asserted on.
	Exit() string
	// Stop ends the instance and frees what its start took.
	Stop() error
}

// Attachment is the component under test, as the runner hands it to the
// cases.
type Attachment interface {
	// Declared is what the component declares, by which a case is not
	// applicable.
	Declared() target.Declared
	// Network is where the harness's roles listen and dial on side s. It
	// is an error for a side the component has not.
	Network(s Side) (Network, error)
	// Start starts a fresh instance.
	Start(ctx context.Context, p Params) (Instance, error)
	// Close frees what the attachment holds; every instance has been
	// stopped first.
	Close() error
}

// ErrNoSide is returned by Network for a side the component has not.
var ErrNoSide = errors.New("the component under test has no such side")
