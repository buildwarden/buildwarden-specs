package sandbox

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The address plan. Every address of the documentation ranges (RFC 5737) is
// the harness's own in its namespace, so that a case may start its resolvers
// and origins at any of them, as package upstream allows, and a host-mode
// relay, whose dial filter refuses loopback, private and link-local
// addresses, reaches them. The links between the relays and the harness take
// their addresses from the shared address space (RFC 6598), which neither
// the dial filter nor the cases use.
var (
	// UpstreamHarness is the harness's address on the claim side and the
	// upstream, and the nameserver of ResolvConf.
	UpstreamHarness = netip.MustParseAddr("203.0.113.10")
	// HarnessRanges are the ranges whose every address is local to the
	// harness's namespace: the documentation ranges.
	HarnessRanges = upstream.DocumentationRanges
	// LinkRange holds every instance's upstream link: instance slot s has
	// 100.64.0.4s/30, the relay at .4s+1 and the harness at .4s+2.
	LinkRange = netip.MustParsePrefix("100.64.0.0/24")
	// LauncherRelay and LauncherHarness are the relay's and the build
	// environment's addresses on a build link whose relay address the
	// launcher assigns (address_by_launcher). They are the in-process
	// attachment's (package inprocess, ContainerRelay and ContainerGuest).
	LauncherRelay   = netip.MustParsePrefix("10.88.0.2/16")
	LauncherHarness = netip.MustParsePrefix("10.88.0.3/16")
	// PreClaim is the address on the relay's interface of a build link
	// that the claim's build_link addresses, before a claim does: what a
	// vm-mode relay keeps when a claim has no build_link. It is the
	// in-process attachment's (VMInterface).
	PreClaim = netip.MustParsePrefix("10.0.2.15/24")
)

// ClaimPort is the port of an instance's claim endpoint, at the relay's
// address on its upstream link.
const ClaimPort = 8301

// Slots is how many instances one sandbox holds at once: the /30 links that
// fit in LinkRange.
const Slots = 64

// ResolvConf is the resolver configuration a relay is started with, as
// /etc/resolv.conf: 127.0.0.1, which a relay leaves out, and then the
// harness's upstream address. It is the in-process attachment's (package
// inprocess, ResolvConf).
const ResolvConf = "nameserver 127.0.0.1\nnameserver 203.0.113.10\n"

// Upstream is the upstream link of the instance in slot s: the relay's
// address and the harness's, each with the link's length.
func Upstream(s int) (relay, harness netip.Prefix) {
	base := LinkRange.Addr().As4()
	base[3] = byte(4 * s)
	b := netip.AddrFrom4(base)
	return netip.PrefixFrom(b.Next(), 30), netip.PrefixFrom(b.Next().Next(), 30)
}

// Claim is the claim endpoint of the instance in slot s.
func Claim(s int) netip.AddrPort {
	r, _ := Upstream(s)
	return netip.AddrPortFrom(r.Addr(), ClaimPort)
}

// Link is a relay's build link as the sandbox makes it.
type Link struct {
	// Kind is "frames" or "ip".
	Kind string
	// Relay is the address put on the relay's end of an "ip" link before
	// it is claimed, and Harness the build environment's at the other end.
	Relay, Harness netip.Prefix
}

// BuildLink is the build link a relay target gets: on "frames" a socket pair,
// on "ip" a veth pair addressed from the target's build_link, with PreClaim
// on the relay's end, or from LauncherRelay and LauncherHarness when the
// launcher assigns the relay's address. A build link that meets the upstream
// addresses is an error.
func BuildLink(r *target.Relay) (Link, error) {
	switch r.Link {
	case "frames":
		if r.AddressByLauncher {
			return Link{}, errors.New("a relay on a frames link takes its address from the claim's build_link, so the sandbox cannot assign it: give [relay] build_link")
		}
		return Link{Kind: "frames"}, checkBuildLink(r.BuildLink)
	case "ip":
		if r.AddressByLauncher {
			return Link{Kind: "ip", Relay: LauncherRelay, Harness: LauncherHarness}, nil
		}
		if err := checkBuildLink(r.BuildLink); err != nil {
			return Link{}, err
		}
		p := netip.MustParsePrefix(r.BuildLink.Prefix)
		g := netip.MustParseAddr(r.BuildLink.Guest)
		return Link{Kind: "ip", Relay: PreClaim, Harness: netip.PrefixFrom(g, p.Bits())}, nil
	}
	return Link{}, fmt.Errorf("relay.link %q is none of frames, ip", r.Link)
}

// checkBuildLink refuses a build_link that overlaps the ranges the sandbox
// uses: the harness's, the links', and PreClaim's, which the relay would then
// find on two interfaces.
func checkBuildLink(b *target.BuildLink) error {
	if b == nil {
		return errors.New("[relay] has no build_link")
	}
	p, err := netip.ParsePrefix(b.Prefix)
	if err != nil {
		return fmt.Errorf("relay.build_link.prefix: %w", err)
	}
	used := append(append([]netip.Prefix{}, HarnessRanges...), LinkRange, PreClaim.Masked())
	for _, r := range used {
		if p.Overlaps(r) {
			return fmt.Errorf("relay.build_link %s overlaps %s, which the sandbox uses; choose a build link outside %v", p, r, used)
		}
	}
	return nil
}

// Names are the names of one instance's links and container: unique to the
// harness process and the instance, and short enough for an interface name
// (15 bytes). The build link's sorts before the upstream's.
type Names struct {
	Build, Upstream, Container string
}

// NamesFor names instance id of the harness process pid.
func NamesFor(pid, id int) Names {
	tag := fmt.Sprintf("%x-%x", pid&0xffffff, id&0xfffff)
	return Names{
		Build:     "bwb" + tag,
		Upstream:  "bwu" + tag,
		Container: fmt.Sprintf("bw-conformance-%d-%d", pid, id),
	}
}
