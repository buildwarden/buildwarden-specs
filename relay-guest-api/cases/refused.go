package cases

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The relay modes a target declares (RELAY-04 in buildwarden/buildwarden).
const (
	modeHost      = "host"
	modeContainer = "container"
)

// withBuildLink is the Applies of a case for a relay that refuses the
// addresses of its build link: one in vm mode or host mode, whose claim
// carries the build_link the target declares.
func withBuildLink(d target.Declared) string {
	switch {
	case d.Mode == modeContainer:
		return "a container-mode relay refuses no address itself"
	case d.BuildLink == nil:
		return "the target declares no build_link for its claim"
	}
	return ""
}

// hostMode is the Applies of a case for a host-mode relay.
func hostMode(d target.Declared) string {
	if d.Mode == modeHost {
		return ""
	}
	return "the relay is in " + d.Mode + " mode, and only a host-mode relay refuses loopback, private and link-local addresses"
}

// watchBuildSide listens on port 80 of the build_link's guest address on a
// kernel interface, where a relay that dialed the build link would reach
// the build environment, and reports whether anything connected. On a
// frame link the relay's upstream dials leave by its upstream, never the
// link, so there is nothing to watch.
func watchBuildSide(r *relayRun) func() bool {
	if r.d.Link != buildenv.IP {
		return func() bool { return false }
	}
	ln, err := r.t.Network(attach.Build).Listen(r.t.Context(), "tcp", netip.AddrPortFrom(r.guestAddr(), 80).String())
	if err != nil {
		r.t.Fatalf("a listener at the build environment's %s:80: %v", r.guestAddr(), err)
	}
	r.t.Cleanup(func() { _ = ln.Close() })
	var reached atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			reached.Store(true)
			_ = c.Close()
		}
	}()
	return reached.Load
}

// pairedRefused asks the relay, from env, for a name that resolves to a and
// to the origin, in either order, for each address a of addrs, and checks
// that each is answered with the 502 of GUEST-46 and that the origin, which
// would answer, received nothing. It is what makes a refusal observable
// where the harness has no server at the refused address: a relay that did
// not refuse a would fail to connect there and then connect to the origin,
// or connect to the origin first. names prefixes the names it sets.
func pairedRefused(t *runner.T, r *relayRun, env *buildenv.Env, names string, addrs []netip.Addr) {
	for i, a := range addrs {
		for j, order := range [][]netip.Addr{{a, originAddr}, {originAddr, a}} {
			name := fmt.Sprintf("%s-%d-%d.example", names, i, j)
			for _, res := range r.up.Resolvers {
				res.Set(name, order...)
			}
			resp, body, err := proxied(t.Context(), env, name)
			unreachable(t, "GET / with Host "+name+", which resolves to "+order[0].String()+" and "+order[1].String(), resp, body, err)
		}
	}
	for _, x := range r.up.Origins.Exchanges() {
		t.Errorf("the origin at %s received %s %s with Host %s: the relay connected to a name that resolves to a refused address", originAddr, x.Method, x.Target, x.Host)
	}
}

// refusedLink: every address of the build link, by its address and by a
// name that resolves to it, is refused with the 502; a name that resolves
// to it and to the origin is refused and the origin receives nothing; and
// on a kernel interface nothing reaches the build environment. The paired
// names are what catch a relay that does not refuse the link's addresses
// where its upstream holds nothing at them (in-process, and in host mode,
// whose private-address rule covers the link besides).
var refusedLink = runner.Case{
	Name:    "a relay with a build link refuses to connect to any address inside it, its own included",
	Cites:   []string{"GUEST-46"},
	Role:    "relay",
	Ends:    true,
	Applies: withBuildLink,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		reached := watchBuildSide(r)
		env := r.build(nil)
		var hosts []string
		var addrs []netip.Addr
		p := r.linkPrefix().Masked()
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			hosts = append(hosts, a.String())
			addrs = append(addrs, a)
		}
		const inside = "inside.example"
		for _, res := range r.up.Resolvers {
			res.Set(inside, r.guestAddr())
		}
		hosts = append(hosts, inside, net.JoinHostPort(r.guestAddr().String(), "80"))
		for _, h := range hosts {
			resp, body, err := proxied(t.Context(), env, h)
			unreachable(t, "GET / with Host "+h+" in the build link "+p.String(), resp, body, err)
		}
		pairedRefused(t, r, env, "link", addrs)
		if reached() {
			t.Errorf("the relay connected to the build environment's %s:80 on the build environment's behalf", r.guestAddr())
		}
	},
}

// refusedHost: a host-mode relay refuses loopback, unspecified, private,
// link-local and the metadata addresses, by address and by name. The
// harness's upstream holds no server at those addresses, so a literal
// address's 502 alone does not tell a refusal from a failed dial; each
// address is also given with the origin's under one name, which a relay
// that did not refuse it would reach the origin by.
var refusedHost = runner.Case{
	Name:    "a host-mode relay refuses loopback, unspecified, private, link-local and the cloud metadata addresses",
	Cites:   []string{"GUEST-46"},
	Role:    "relay",
	Ends:    true,
	Applies: hostMode,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		var addrs []netip.Addr
		for _, a := range []string{
			"127.0.0.1", "127.3.2.1", "0.0.0.0",
			"10.0.2.80", "172.16.5.4", "192.168.0.1",
			"169.254.1.1", "224.0.0.251",
			"169.254.169.254", "100.100.100.200",
			"::1", "::", "fd00::1", "fe80::1", "ff02::1",
		} {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		var hosts []string
		for i, a := range addrs {
			if a.Is6() {
				hosts = append(hosts, "["+a.String()+"]")
			} else {
				hosts = append(hosts, a.String())
			}
			name := fmt.Sprintf("refused-%d.example", i)
			for _, res := range r.up.Resolvers {
				res.Set(name, a)
			}
			hosts = append(hosts, name)
		}
		for _, h := range hosts {
			resp, body, err := proxied(t.Context(), env, h)
			unreachable(t, "GET / with Host "+h, resp, body, err)
		}
		pairedRefused(t, r, env, "refused-paired", addrs)
	},
}

// refusedAny: a name that resolves to an address the relay refuses and to
// the origin's, in either order, is refused, and the origin, which would
// answer, receives nothing.
var refusedAny = runner.Case{
	Name:    "a name is refused when any address it resolves to is refused",
	Cites:   []string{"GUEST-46"},
	Role:    "relay",
	Ends:    true,
	Applies: withBuildLink,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		pairedRefused(t, r, env, "refused-any", []netip.Addr{r.guestAddr()})
	},
}
