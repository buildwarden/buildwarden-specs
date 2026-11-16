package cases

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The upstream world the cases start: resolvers, of which a claim names
// the first two as its upstream_dns and never the third, and one origin,
// each at an address of the documentation ranges, which every attachment's
// upstream holds.
var (
	firstResolver    = netip.MustParseAddr("192.0.2.53")
	secondResolver   = netip.MustParseAddr("192.0.2.54")
	unlistedResolver = netip.MustParseAddr("192.0.2.55")
	originAddr       = netip.MustParseAddr("192.0.2.80")
	guestMAC         = net.HardwareAddr{0x02, 0, 0, 0, 0x0c, 0x03}
)

const originName = "origin.example"

// within bounds the waits a case makes for something the relay does at once
// in a conforming implementation: a reply to a datagram, a frame it is to
// send. It is a bound, never a verdict's measure: a case that waits it out
// has failed.
const within = 10 * time.Second

// quiet is how long a case listens for an answer the relay must not give,
// after it has seen the relay answer a request sent after the one it must
// not answer. A conforming relay never sends that answer, so the wait
// decides nothing for it.
const quiet = time.Second

// relayRun is one relay instance a case starts, with the harness's roles
// around it: the claimant at its claim endpoint, the harness's collector
// over the tunnel, and the upstream world.
type relayRun struct {
	t    *runner.T
	d    target.Declared
	in   attach.Instance
	cl   claimant.Claimant
	up   *upstream.Upstream
	coll *collector.Collector
	// ca is the claim reply's ca_cert, once claim has returned.
	ca *x509.Certificate
}

// defaultWorld is two listed resolvers, one unlisted, and the origin.
func defaultWorld() upstream.World {
	return upstream.World{
		Resolvers: []netip.Addr{firstResolver, secondResolver, unlistedResolver},
		Origins:   []upstream.Origin{{Name: originName, Addr: originAddr}},
	}
}

// startRelay starts a fresh instance (every case here claims one, and so
// ends it) and the default world on the attachment's upstream.
func startRelay(t *runner.T) *relayRun {
	up, err := upstream.Start(t.Context(), t.Network(attach.Upstream), defaultWorld())
	if err != nil {
		t.Fatalf("the harness's upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	in := t.Instance(attach.Params{})
	return &relayRun{
		t: t, d: t.Declared(), in: in, up: up,
		cl: claimant.Claimant{Net: t.Network(attach.Claim), Endpoint: in.Claim()},
	}
}

// listed is the claim's upstream_dns: the first two resolvers, in order.
func (r *relayRun) listed() []string {
	return []string{firstResolver.String(), secondResolver.String()}
}

// claim claims the relay over the tunnel, with the harness's collector on
// it, the target's build_link when it declares one, and the first two
// resolvers as upstream_dns; it fails the case unless the relay answers 200
// with an identity.
func (r *relayRun) claim() {
	t := r.t
	r.coll = collector.New(collector.Form{}, nil)
	cfg := claimant.Config{UpstreamDNS: r.listed()}
	if l := r.d.BuildLink; l != nil {
		cfg.BuildLink = &claimant.BuildLink{Prefix: l.Prefix, Relay: l.Relay, Guest: l.Guest}
	}
	tun, rep, err := r.cl.Session(t.Context(), r.coll, cfg)
	if tun != nil {
		t.Cleanup(func() { _ = tun.Close() })
	}
	if err != nil {
		t.Fatalf("the tunnel and the claim: %v", err)
	}
	if rep.Status != http.StatusOK {
		t.Fatalf("the claim was answered %d %q, want 200", rep.Status, rep.Body)
	}
	_, ca, _, err := rep.Identity()
	if err != nil {
		t.Fatalf("the claim's 200: %v", err)
	}
	r.ca = ca
}

// relayAddr is the relay's address on its build link as the target
// declares it: the build_link's relay, or the address its launcher gives.
func (r *relayRun) relayAddr() netip.Addr {
	s := r.d.Address
	if r.d.BuildLink != nil {
		s = r.d.BuildLink.Relay
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		r.t.Fatalf("the relay's declared address on its build link, %q: %v", s, err)
	}
	return a
}

// guestAddr is the build_link's guest address, which the lease gives.
func (r *relayRun) guestAddr() netip.Addr {
	if r.d.BuildLink == nil {
		r.t.Fatalf("the target declares no build_link")
	}
	a, err := netip.ParseAddr(r.d.BuildLink.Guest)
	if err != nil {
		r.t.Fatalf("the declared build_link's guest, %q: %v", r.d.BuildLink.Guest, err)
	}
	return a
}

// linkPrefix is the declared build_link's prefix.
func (r *relayRun) linkPrefix() netip.Prefix {
	if r.d.BuildLink == nil {
		r.t.Fatalf("the target declares no build_link")
	}
	p, err := netip.ParsePrefix(r.d.BuildLink.Prefix)
	if err != nil {
		r.t.Fatalf("the declared build_link's prefix, %q: %v", r.d.BuildLink.Prefix, err)
	}
	return p
}

// frames is the harness's end of the relay's frame link.
func (r *relayRun) frames() net.Conn {
	f, err := r.in.Frames()
	if err != nil {
		r.t.Fatalf("the relay's frame link: %v", err)
	}
	return f
}

// build is the harness's build environment on the relay's build link,
// started after the claim, once the relay serves GET /health (the
// harness's rule for D19). On a frame link it is given link, the harness's
// end of the link or a tap on it.
func (r *relayRun) build(link net.Conn) *buildenv.Env {
	t, ctx := r.t, r.t.Context()
	var env *buildenv.Env
	var err error
	switch r.d.Link {
	case buildenv.Frames:
		if link == nil {
			link = r.frames()
		}
		env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: link, MAC: guestMAC})
	default:
		env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: t.Network(attach.Build), Relay: r.relayAddr()})
	}
	if err != nil {
		t.Fatalf("the build environment: %v", err)
	}
	if r.d.Link != buildenv.Frames {
		// On a frame link the build environment owns the harness's end of
		// the link, which the instance's Stop closes, and so its stack
		// with it; closing it here as well makes the sandbox's Stop fail.
		t.Cleanup(func() { _ = env.Close() })
	}
	if err := env.Ready(ctx); err != nil {
		t.Fatalf("the relay's build side: %v", err)
	}
	return env
}

// servesLease says whether a relay that the target declares serves the
// address lease once the harness has claimed it: on a frame link always,
// and on a kernel interface when the claim carries a build_link, which the
// harness sends when the target declares one (relay-claim says which mode
// does what at the claim).
func servesLease(d target.Declared) string {
	if d.Link == buildenv.Frames || d.BuildLink != nil {
		return ""
	}
	return "the relay serves no address lease: its build link is a kernel interface and its claim carries no build_link"
}

// onFrames is the Applies of a case for a frame link only.
func onFrames(d target.Declared) string {
	if d.Link == buildenv.Frames {
		return ""
	}
	return "the relay's build link is a kernel interface, not a frame link"
}

// onInterface is the Applies of a case for a kernel interface only.
func onInterface(d target.Declared) string {
	if d.Link == buildenv.IP {
		return ""
	}
	return "the relay's build link is a frame link, not a kernel interface"
}

// proxied sends GET / with host in Host, and Connection: close, to the
// relay's port 80 at its own address from the build environment, and
// returns the response with its body read to its end. It sends close
// because the reply may be one whose body ends at the connection's close
// (GUEST-46, GUEST-47).
func proxied(ctx context.Context, env *buildenv.Env, host string) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	c, err := env.Network().Dial(ctx, "tcp", netip.AddrPortFrom(env.Relay(), 80).String())
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return nil, nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// unreachable checks that the relay answered what with the 502 of
// GUEST-46: Content-Type text/plain and the body "upstream unreachable"
// and a line feed.
func unreachable(t *runner.T, what string, resp *http.Response, body []byte, err error) {
	if err != nil {
		t.Errorf("%s: %v", what, err)
		return
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("%s was answered %d %q, want 502", what, resp.StatusCode, body)
		return
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("%s: the 502 has Content-Type %q, want text/plain", what, ct)
	}
	if string(body) != "upstream unreachable\n" {
		t.Errorf("%s: the 502's body is %q, want %q", what, body, "upstream unreachable\n")
	}
}
