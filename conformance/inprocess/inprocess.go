// Package inprocess is the harness's in-process attachment: a Go API that a
// module's tests hand to the runner in place of a target file, so that every
// suite runs, under plain go test, against the harness's own model of the
// role it tests (the relay cases against package relay's relay in each of
// its three modes, the collector cases against package collector's collector
// in each form). It is not a launcher: the target-file format has no name for
// it, and no command can select it.
//
// It gives the model, from memory, each thing a launcher gives a real relay
// from the kernel: a fresh instance for each start; a claim endpoint; the
// build link, a frame pipe in host mode ("frames") and the relay's listeners
// at its own address on an in-memory network in vm and container mode
// ("ip"); the upstream, an in-memory network on which a case starts the
// harness's resolvers and origins (package upstream); the resolver
// configuration that stands for /etc/resolv.conf, and the build interface's
// addresses and routes, as start parameters; and the mode. For a collector it
// gives the harness's collector with the harness's claimant in front of it,
// as a "claims" target has, which claims the relay a case starts at the
// attachment's claim side.
//
// Each attachment has three in-memory segments of its own, so that a party on
// one reaches no other: the claim side, the upstream, and the build link of
// vm and container mode. Their addresses are fixed, and exported below.
//
// A specification module's go test hands its suite to Suite, which runs it
// against each of Configurations. No case is known that no in-process
// configuration can carry: each case runs at least once, where it applies,
// against one of them, and Suite fails a case that does not.
package inprocess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The address plan of an in-process attachment.
var (
	// ClaimRelay is where a relay's claim endpoint listens, on a port the
	// segment chooses, and where the harness's relay waits for a collector
	// that claims; ClaimHarness is where the harness's claimant dials from.
	ClaimRelay   = netip.MustParseAddr("198.18.0.1")
	ClaimHarness = netip.MustParseAddr("198.18.0.2")
	// UpstreamRelay is the relay's own address on the upstream, and
	// UpstreamHarness the harness's there: the address the attachment's
	// upstream side gives the roles, and the nameserver of the resolver
	// configuration.
	UpstreamRelay   = netip.MustParseAddr("198.51.100.1")
	UpstreamHarness = netip.MustParseAddr("203.0.113.10")
	// BuildLink is what a host-mode and a vm-mode attachment declare the
	// harness sends as a claim's build_link.
	BuildLink = target.BuildLink{Prefix: "10.100.0.0/30", Relay: "10.100.0.1", Guest: "10.100.0.2"}
	// VMInterface is the address on a vm-mode relay's build interface
	// before a claim gives it one (CLAIM-38), and VMOtherAddresses and
	// VMOtherRoutes those of its other interface, the upstream's, which a
	// build_link may not use (CLAIM-36).
	VMInterface      = netip.MustParsePrefix("10.0.2.15/24")
	VMOtherAddresses = []netip.Prefix{netip.PrefixFrom(UpstreamRelay, 24)}
	VMOtherRoutes    = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("172.31.0.0/16"), netip.MustParsePrefix("0.0.0.0/0")}
	// ContainerRelay is the address a container-mode relay is given on its
	// build link, and ContainerGuest the build environment's there.
	ContainerRelay = netip.MustParsePrefix("10.88.0.2/16")
	ContainerGuest = netip.MustParseAddr("10.88.0.3")
	// ResolvConf is the nameservers of the resolver configuration a relay
	// is started with, in order: 127.0.0.1, which a relay leaves out
	// (CLAIM-32), then the harness's upstream address.
	ResolvConf = []netip.Addr{netip.MustParseAddr("127.0.0.1"), UpstreamHarness}
)

// Modes are the relay's three modes, each an in-process configuration.
var Modes = []string{relay.ModeHost, relay.ModeVM, relay.ModeContainer}

// Relay is an attachment of the harness's relay in mode.
func Relay(mode string) (attach.Attachment, error) {
	a := &relayAttachment{mode: mode, claim: memnet.New(), up: memnet.New(), build: memnet.New()}
	switch mode {
	case relay.ModeHost:
		a.d = a.declared("frames")
		a.d.BuildLink = &BuildLink
	case relay.ModeVM:
		a.d = a.declared("ip")
		a.d.BuildLink = &BuildLink
	case relay.ModeContainer:
		a.d = a.declared("ip")
		a.d.AddressByLauncher = true
		a.d.Address = ContainerRelay.Addr().String()
	default:
		return nil, fmt.Errorf("inprocess: mode %q is none of %v", mode, Modes)
	}
	return a, nil
}

type relayAttachment struct {
	mode  string
	d     target.Declared
	claim *memnet.Net
	up    *memnet.Net
	build *memnet.Net
}

func (a *relayAttachment) declared(link string) target.Declared {
	return target.Declared{
		Role: "relay", Mode: a.mode, Link: link,
		ResolverConfig: true, ClaimToken: true, NoClaimToken: true, FreshInstances: true,
	}
}

func (a *relayAttachment) Declared() target.Declared { return a.d }

// Network is the claimant's address on the claim side, the build
// environment's on the build link of vm and container mode, and the
// harness's on the upstream.
func (a *relayAttachment) Network(s attach.Side) (attach.Network, error) {
	switch s {
	case attach.Claim:
		return a.claim.Host(ClaimHarness), nil
	case attach.Upstream:
		return a.up.Host(UpstreamHarness), nil
	case attach.Build:
		switch a.mode {
		case relay.ModeVM:
			return a.build.Host(netip.MustParseAddr(BuildLink.Guest)), nil
		case relay.ModeContainer:
			return a.build.Host(ContainerGuest), nil
		}
		return nil, fmt.Errorf("a host-mode relay's build link is a frame link, which each instance gives: %w", attach.ErrNoSide)
	}
	return nil, fmt.Errorf("a relay has no %s side: %w", s, attach.ErrNoSide)
}

func (a *relayAttachment) Close() error { return nil }

// Start starts a fresh relay: with a claim token of its own unless p asks
// for none, and in host mode with a fresh frame pipe.
func (a *relayAttachment) Start(ctx context.Context, p attach.Params) (attach.Instance, error) {
	in := &relayInstance{}
	gc := relay.GuestConfig{Mode: a.mode}
	own := []netip.Addr{UpstreamRelay}
	switch a.mode {
	case relay.ModeHost:
		in.harness, in.relayEnd = memnet.Frames()
		gc.Frames = in.relayEnd
	case relay.ModeVM:
		gc.Net = a.build.Host(VMInterface.Addr())
		gc.Interface = []netip.Prefix{VMInterface}
		gc.OtherAddresses, gc.OtherRoutes = VMOtherAddresses, VMOtherRoutes
		own = append(own, VMInterface.Addr())
	case relay.ModeContainer:
		gc.Net = a.build.Host(ContainerRelay.Addr())
		gc.Interface = []netip.Prefix{ContainerRelay}
		own = append(own, ContainerRelay.Addr())
	}
	guest, err := relay.NewGuest(gc)
	if err != nil {
		in.closeFrames()
		return nil, err
	}
	var token string
	if !p.NoClaimToken {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
	}
	r, err := relay.Start(ctx, relay.Config{
		Net: a.claim.Host(ClaimRelay), Token: token,
		Upstream: a.up.Host(UpstreamRelay), ResolvConf: ResolvConf, Own: own,
		Build: guest,
	})
	if err != nil {
		in.closeFrames()
		return nil, err
	}
	in.Relay = r
	return in, nil
}

// relayInstance is one started relay, with the harness's end of its frame
// link in host mode.
type relayInstance struct {
	*relay.Relay
	harness, relayEnd net.Conn
	once              sync.Once
}

// Frames is the harness's end of the frame pipe in host mode.
func (in *relayInstance) Frames() (net.Conn, error) {
	if in.harness == nil {
		return nil, fmt.Errorf("the relay's build link is ip: %w", attach.ErrNoFrames)
	}
	return in.harness, nil
}

// Stop ends the relay and closes both ends of its frame pipe.
func (in *relayInstance) Stop() error {
	err := in.Relay.Stop()
	in.closeFrames()
	return err
}

func (in *relayInstance) closeFrames() {
	in.once.Do(func() {
		for _, c := range []net.Conn{in.harness, in.relayEnd} {
			if c != nil {
				_ = c.Close()
			}
		}
	})
}

// Configuration is one in-process configuration of a role: a name for it,
// and a fresh attachment of it.
type Configuration struct {
	Name string
	New  func() (attach.Attachment, error)
}

// Configurations are the in-process configurations of role, in a fixed
// order: for "relay" the three modes, and for "collector" the eight forms. A
// module's go test runs its suite against each, so that each case runs at
// least once where it applies.
func Configurations(role string) []Configuration {
	var out []Configuration
	switch role {
	case "relay":
		for _, m := range Modes {
			out = append(out, Configuration{Name: m, New: func() (attach.Attachment, error) { return Relay(m) }})
		}
	case "collector":
		forms := Forms()
		names := make([]string, 0, len(forms))
		for n := range forms {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			f := forms[n]
			out = append(out, Configuration{Name: n, New: func() (attach.Attachment, error) { return Collector(f), nil }})
		}
	}
	return out
}
