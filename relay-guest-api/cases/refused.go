package cases

import (
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

// refusedLink: every address of the build link, by its address and by a
// name that resolves to it, is refused with the 502, and on a kernel
// interface nothing reaches the build environment.
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
		p := r.linkPrefix().Masked()
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			hosts = append(hosts, a.String())
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
		if reached() {
			t.Errorf("the relay connected to the build environment's %s:80 on the build environment's behalf", r.guestAddr())
		}
	},
}

// refusedHost: a host-mode relay refuses loopback, unspecified, private,
// link-local and the metadata addresses, by address and by name. The
// harness's upstream cannot hold servers at those addresses, so what is
// checked is the 502 alone.
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
		addrs := []string{
			"127.0.0.1", "127.3.2.1", "0.0.0.0",
			"10.0.2.80", "172.16.5.4", "192.168.0.1",
			"169.254.1.1", "224.0.0.251",
			"169.254.169.254", "100.100.100.200",
		}
		hosts := append([]string{}, addrs...)
		hosts = append(hosts, "[::1]", "[fd00::1]", "[fe80::1]")
		for i, a := range addrs {
			name := "refused-" + string(rune('a'+i)) + ".example"
			for _, res := range r.up.Resolvers {
				res.Set(name, netip.MustParseAddr(a))
			}
			hosts = append(hosts, name)
		}
		for _, h := range hosts {
			resp, body, err := proxied(t.Context(), env, h)
			unreachable(t, "GET / with Host "+h, resp, body, err)
		}
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
		for _, v := range []struct {
			name  string
			addrs []netip.Addr
		}{
			{"refused-first.example", []netip.Addr{r.guestAddr(), originAddr}},
			{"refused-last.example", []netip.Addr{originAddr, r.guestAddr()}},
		} {
			for _, res := range r.up.Resolvers {
				res.Set(v.name, v.addrs...)
			}
			resp, body, err := proxied(t.Context(), env, v.name)
			unreachable(t, "GET / with Host "+v.name+", which resolves to "+v.addrs[0].String()+" and "+v.addrs[1].String(), resp, body, err)
		}
		for _, x := range r.up.Origins.Exchanges() {
			t.Errorf("the origin at %s received %s %s with Host %s: the relay connected to a name that resolves to a refused address", originAddr, x.Method, x.Target, x.Host)
		}
	},
}
