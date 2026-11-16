package cases

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// inMode applies to a relay in one of modes.
func inMode(modes ...string) func(d target.Declared) string {
	return func(d target.Declared) string {
		for _, m := range modes {
			if d.Mode == m {
				return ""
			}
		}
		return fmt.Sprintf("the relay's mode is %q, and the case is for %s mode", d.Mode, strings.Join(modes, " or "))
	}
}

// both applies where each of fs does.
func both(fs ...func(d target.Declared) string) func(d target.Declared) string {
	return func(d target.Declared) string {
		for _, f := range fs {
			if why := f(d); why != "" {
				return why
			}
		}
		return ""
	}
}

func withLink(d target.Declared) string {
	if d.BuildLink == nil {
		return "the target declares no build_link for the harness to send"
	}
	return ""
}

func withResolverConfig(d target.Declared) string {
	if !d.ResolverConfig {
		return "the harness does not give the relay its resolver configuration"
	}
	return ""
}

// The second listed resolver of resolverOrder.
var secondResolver = netip.MustParseAddr("198.51.100.53")

// resolverOrder claims a fresh relay with two resolvers in upstream_dns, both
// answering, and a third at the address the relay's resolver configuration
// names, and has the build resolve the origin and fetch it. The first listed
// resolver is asked first, and the one the claim does not list is never
// asked.
var resolverOrder = runner.Case{
	Name:  "with upstream_dns the relay asks exactly the listed resolvers, the first first",
	Cites: []string{"CLAIM-31"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		conf := t.Network(attach.Upstream).Address()
		up := startWorld(t, upstream.World{
			Resolvers: []netip.Addr{resolverAddr, secondResolver, conf},
			Origins:   []upstream.Origin{{Name: originName, Addr: originAddr}},
		})
		r := newRun(t, up, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		c := r.base().with(claim{"upstream_dns": []string{resolverAddr.String(), secondResolver.String()}})
		ca := accepted(t, "the claim", r.send(c))
		env := r.build(declaredLink(r.d))
		if as, err := env.Resolve(t.Context(), originName); err != nil || len(as) != 1 || as[0] != originAddr {
			t.Errorf("the build's DNS for %s: %v, %v; want %v", originName, as, err, originAddr)
		}
		fetchOrigin(t, env, ca, "http", "/bytes/10")
		first := up.Resolvers[0].Queries()
		if len(first) == 0 {
			t.Fatalf("the first resolver of upstream_dns, %s, was asked nothing", resolverAddr)
		}
		for _, q := range up.Resolvers[1].Queries() {
			if q.At.Before(first[0].At) {
				t.Errorf("the second resolver of upstream_dns was asked for %s before the first was asked anything", q.Name)
			}
		}
		for _, q := range up.Resolvers[2].Queries() {
			t.Errorf("the resolver of the relay's resolver configuration, %s, which the claim's upstream_dns does not list, was asked for %s", conf, q.Name)
		}
	},
}

// resolverDefault claims a fresh relay without upstream_dns: its resolver is
// the one its resolver configuration names after 127.0.0.1, which the
// harness gives as its own upstream address.
var resolverDefault = runner.Case{
	Name:    "without upstream_dns the relay asks the nameservers of its resolver configuration",
	Cites:   []string{"CLAIM-32"},
	Role:    "relay",
	Ends:    true,
	Applies: withResolverConfig,
	Run: func(t *runner.T) {
		conf := t.Network(attach.Upstream).Address()
		up := startWorld(t, upstream.World{
			Resolvers: []netip.Addr{conf},
			Origins:   []upstream.Origin{{Name: originName, Addr: originAddr}},
		})
		r := newRun(t, up, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		accepted(t, "a claim without upstream_dns", r.send(r.base().with(claim{"upstream_dns": remove})))
		env := r.build(declaredLink(r.d))
		if as, err := env.Resolve(t.Context(), originName); err != nil || len(as) != 1 || as[0] != originAddr {
			t.Errorf("the build's DNS for %s: %v, %v; want %v", originName, as, err, originAddr)
		}
		if len(up.Resolvers[0].Queries()) == 0 {
			t.Errorf("the nameserver of the relay's resolver configuration, %s, was asked nothing", conf)
		}
	},
}

// linkAround is a build_link of length 29 whose prefix holds a, with relay
// and guest addresses other than a.
func linkAround(a netip.Addr) map[string]string {
	p := netip.PrefixFrom(a, 29).Masked()
	var hosts []string
	for h := p.Addr().Next(); p.Contains(h) && len(hosts) < 2; h = h.Next() {
		if h != a {
			hosts = append(hosts, h.String())
		}
	}
	return map[string]string{"prefix": p.String(), "relay": hosts[0], "guest": hosts[1]}
}

// noUsableResolver claims a fresh relay without upstream_dns and with a
// build_link that holds the one usable nameserver of its resolver
// configuration, the harness's upstream address: a relay leaves 127.0.0.1
// and its build link's addresses out, so none is left, and the claim is
// refused. Only that first refusal is asserted (Known divergences, D17).
var noUsableResolver = runner.Case{
	Name:    "without upstream_dns and with no usable nameserver the claim is refused",
	Cites:   []string{"CLAIM-32", "CLAIM-49"},
	Role:    "relay",
	Ends:    true,
	Applies: both(withResolverConfig, inMode(relay.ModeHost, relay.ModeVM)),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		conf := t.Network(attach.Upstream).Address()
		rep := r.send(r.base().with(claim{"upstream_dns": remove, "build_link": linkAround(conf)}))
		if refusal(t, "a claim whose build_link holds "+conf.String(), rep, http.StatusBadRequest, "claim refused: ", false) &&
			!strings.Contains(string(rep.Body), "upstream_dns") {
			t.Errorf("the refusal %q does not name upstream_dns", rep.Body)
		}
	},
}

// vmLink claims a fresh vm-mode relay with the declared build_link: the
// relay serves at its relay address, and its lease gives the guest address
// at the link's length.
var vmLink = runner.Case{
	Name:    "a vm-mode relay takes the build_link's relay address and leases its guest address",
	Cites:   []string{"CLAIM-37"},
	Role:    "relay",
	Ends:    true,
	Applies: both(inMode(relay.ModeVM), withLink),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		accepted(t, "the claim", r.send(r.base()))
		link := declaredLink(r.d)
		r.build(link)
		pc, err := t.Network(attach.Build).ListenPacket(t.Context(), "udp", "0.0.0.0:68")
		if err != nil {
			t.Fatalf("the DHCP client's socket: %v", err)
		}
		defer pc.Close()
		l, err := dhcp.LeasePacket(t.Context(), pc, guestMAC)
		if err != nil {
			t.Fatalf("a lease on the build link: %v", err)
		}
		checkLease(t, l, link)
	},
}

// checkLease fails the case unless l is the guest address of link at its
// length, from the relay address.
func checkLease(t *runner.T, l dhcp.Lease, link map[string]string) {
	p := netip.MustParsePrefix(link["prefix"])
	want := netip.PrefixFrom(netip.MustParseAddr(link["guest"]), p.Bits())
	if l.Address != want || l.Server != netip.MustParseAddr(link["relay"]) {
		t.Errorf("the lease is %v from %v, want %v from %s", l.Address, l.Server, want, link["relay"])
	}
}

// vmNoLink claims a fresh vm-mode relay without a build_link: its build
// interface has an address, which it keeps, so the claim is accepted.
var vmNoLink = runner.Case{
	Name:    "a vm-mode relay claimed without a build_link keeps its address",
	Cites:   []string{"CLAIM-38"},
	Role:    "relay",
	Ends:    true,
	Applies: inMode(relay.ModeVM),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		accepted(t, "a claim without build_link", r.send(r.base().with(claim{"build_link": remove})))
	},
}

// otherLink is the build_link hostLink sends: one no relay has as its own
// segment (a Go relay's -subnet default is 10.100.0.0/30), outside the
// ranges the sandbox addresses itself from, and with the relay and guest
// addresses in an order no default has.
var otherLink = map[string]string{"prefix": "10.101.0.0/29", "relay": "10.101.0.5", "guest": "10.101.0.3"}

// onFrames applies to a relay whose build link is a frame link, both of
// whose ends the harness owns, so that the case can choose its addresses.
func onFrames(d target.Declared) string {
	if d.Link != buildenv.Frames {
		return "the relay's build link is not a frame link, whose addresses the harness could choose"
	}
	return ""
}

// hostLink claims a fresh host-mode relay with a build_link that differs
// from the relay's own segment: the lease on the frame link is the
// build_link's, from its relay address.
var hostLink = runner.Case{
	Name:    "a host-mode relay builds its link on the build_link",
	Cites:   []string{"CLAIM-39"},
	Role:    "relay",
	Ends:    true,
	Applies: both(inMode(relay.ModeHost), onFrames),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		accepted(t, "a claim with the build_link "+otherLink["prefix"], r.send(r.base().with(claim{"build_link": otherLink})))
		env := r.build(otherLink)
		l, _ := env.Lease()
		checkLease(t, l, otherLink)
	},
}

// hostNoLink claims a fresh host-mode relay without a build_link: it builds
// its link on its own segment, on which the build takes a lease and reaches
// it.
var hostNoLink = runner.Case{
	Name:    "a host-mode relay claimed without a build_link builds its link on its own segment",
	Cites:   []string{"CLAIM-39"},
	Role:    "relay",
	Ends:    true,
	Applies: inMode(relay.ModeHost),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		accepted(t, "a claim without build_link", r.send(r.base().with(claim{"build_link": remove})))
		r.build(nil)
	},
}

// containerRefusesLink claims a fresh container-mode relay, its tunnel open,
// with a valid build_link, which it refuses, and then without one.
var containerRefusesLink = runner.Case{
	Name:    "a container-mode relay refuses a claim that carries a build_link",
	Cites:   []string{"CLAIM-40", "CLAIM-49", "CLAIM-48"},
	Role:    "relay",
	Ends:    true,
	Applies: inMode(relay.ModeContainer),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		link := map[string]string{"prefix": "10.100.0.0/30", "relay": "10.100.0.1", "guest": "10.100.0.2"}
		rep := r.send(r.base().with(claim{"build_link": link}))
		if refusal(t, "a claim with a build_link", rep, http.StatusBadRequest, "claim refused: ", false) &&
			!strings.Contains(string(rep.Body), "build_link") {
			t.Errorf("the refusal %q does not name build_link", rep.Body)
		}
		accepted(t, "a claim without build_link after the refusal", r.send(r.base()))
	},
}

// insideName is the name the resolver answers with an address inside the
// build link in noDialIntoLink.
const insideName = "inside.example"

// noDialIntoLink claims a fresh relay with its build link, has the
// upstream resolver answer a name with the guest's own address, inside the
// link, where the build environment listens on port 80, and has the build
// ask the relay's proxy for that name. The relay must not connect there: the
// listener accepts nothing by the time the build has the relay's answer.
// The request goes to the relay's own address on both kinds of link, so that
// on a frame link the build does not connect to itself.
var noDialIntoLink = runner.Case{
	Name:    "a relay with a build link opens no upstream connection into it",
	Cites:   []string{"CLAIM-41"},
	Role:    "relay",
	Ends:    true,
	Applies: both(inMode(relay.ModeHost, relay.ModeVM), withLink),
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		link := declaredLink(r.d)
		r.up.Resolvers[0].Set(insideName, netip.MustParseAddr(link["guest"]))
		accepted(t, "the claim", r.send(r.base()))
		env := r.build(link)
		var bn attach.Network = env.Network()
		if env.Link() == buildenv.IP {
			bn = t.Network(attach.Build)
		}
		ln, err := bn.Listen(t.Context(), "tcp", net.JoinHostPort(link["guest"], "80"))
		if err != nil {
			t.Fatalf("the build environment's listener at %s:80: %v", link["guest"], err)
		}
		accepted := make(chan string, 4)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- c.RemoteAddr().String()
				_ = c.Close()
			}
		}()
		defer ln.Close()
		conn, err := env.Network().Dial(t.Context(), "tcp", net.JoinHostPort(env.Relay().String(), "80"))
		if err != nil {
			t.Fatalf("dialling the relay's port 80: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(within))
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", insideName)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Logf("the relay's answer for http://%s/: %v", insideName, err)
		} else {
			_ = resp.Body.Close()
		}
		select {
		case from := <-accepted:
			t.Errorf("the relay connected to %s:80, inside its build link, from %s", link["guest"], from)
		default:
		}
	},
}
