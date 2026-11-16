package cases

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
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

// The upstream world most relay cases start: one resolver, which the claim
// names as its upstream_dns, and one origin, each at an address of the
// documentation ranges, which every attachment's upstream holds.
var (
	resolverAddr = netip.MustParseAddr("192.0.2.53")
	originAddr   = netip.MustParseAddr("192.0.2.80")
	guestMAC     = net.HardwareAddr{0x02, 0, 0, 0, 0x0c, 0x01}
)

const originName = "origin.example"

// within bounds the waits a case makes for something the relay does at once
// in a conforming implementation: the polls of the endpoint after it is
// spent, and the wait for a completion. It is a bound, never a verdict's
// measure: a case that waits it out has failed.
const within = 10 * time.Second

// claim is a claim's body as a case builds it, member by member, so that a
// case can send what no claimant may (a member of the wrong type, an
// unknown member, an explicit empty value).
type claim map[string]any

func (c claim) body() []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

// with is a copy of c with the members of m set, or removed where m's value
// is the remove sentinel.
func (c claim) with(m claim) claim {
	out := claim{}
	for k, v := range c {
		out[k] = v
	}
	for k, v := range m {
		if v == remove {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

type removeMember struct{}

// remove, as a value given to claim.with, removes the member.
var remove = removeMember{}

// declaredLink is the build_link the target declares the harness sends, as
// a claim's member, or nil for a relay whose address its launcher assigns.
func declaredLink(d target.Declared) map[string]string {
	if d.BuildLink == nil {
		return nil
	}
	return map[string]string{"prefix": d.BuildLink.Prefix, "relay": d.BuildLink.Relay, "guest": d.BuildLink.Guest}
}

// relayRun is one relay instance a case claims, with the harness's roles
// around it: the claimant at its claim endpoint and the upstream world.
type relayRun struct {
	t  *runner.T
	d  target.Declared
	in attach.Instance
	cl claimant.Claimant
	up *upstream.Upstream
}

// startRelay starts an instance with p and the default upstream world: a
// fresh instance for a case that ends its instance, the shared one
// otherwise. A case that starts more than one relay starts the world once,
// with defaultWorld, and each relay with newRun.
func startRelay(t *runner.T, p attach.Params) *relayRun {
	return newRun(t, defaultWorld(t), p)
}

// defaultWorld is one resolver, which the claim names as its upstream_dns,
// and one origin.
func defaultWorld(t *runner.T) *upstream.Upstream {
	return startWorld(t, upstream.World{
		Resolvers: []netip.Addr{resolverAddr},
		Origins:   []upstream.Origin{{Name: originName, Addr: originAddr}},
	})
}

// newRun starts an instance with p, around which up is the upstream.
func newRun(t *runner.T, up *upstream.Upstream, p attach.Params) *relayRun {
	in := t.Instance(p)
	return &relayRun{
		t: t, d: t.Declared(), in: in, up: up,
		cl: claimant.Claimant{Net: t.Network(attach.Claim), Endpoint: in.Claim()},
	}
}

// startWorld starts w on the attachment's upstream, stopped when the case
// ends.
func startWorld(t *runner.T, w upstream.World) *upstream.Upstream {
	up, err := upstream.Start(t.Context(), t.Network(attach.Upstream), w)
	if err != nil {
		t.Fatalf("the harness's upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	return up
}

// base is a valid claim that selects the tunnel: the target's build_link,
// when it declares one, and the world's resolvers as upstream_dns.
func (r *relayRun) base() claim {
	c := claim{"collector_url": claimant.TunnelURL, "upstream_dns": r.up.DNS()}
	if l := declaredLink(r.d); l != nil {
		c["build_link"] = l
	}
	return c
}

// tunnel opens the relay's tunnel, serving coll on it, and fails the case
// if the relay refuses it.
func (r *relayRun) tunnel(coll claimant.Served) *claimant.Tunnel {
	tun, err := r.cl.OpenTunnelFor(r.t.Context(), coll)
	if err != nil {
		r.t.Fatalf("POST /v1/tunnel: %v", err)
	}
	r.t.Cleanup(func() { _ = tun.Close() })
	return tun
}

// send sends c as the claim and returns the reply, failing the case when
// the relay gave none.
func (r *relayRun) send(c claim) *claimant.Reply {
	return r.sendBody(c.body())
}

func (r *relayRun) sendBody(b []byte) *claimant.Reply {
	rep, err := r.cl.ClaimBody(r.t.Context(), b)
	if err != nil {
		r.t.Fatalf("POST /v1/claim: %v", err)
	}
	return rep
}

// accepted fails the case unless rep is a 200 whose identity a claimant can
// read, and returns that identity's CA.
func accepted(t *runner.T, what string, rep *claimant.Reply) *x509.Certificate {
	if rep.Status != http.StatusOK {
		t.Fatalf("%s was answered %d %q, want 200", what, rep.Status, rep.Body)
	}
	_, ca, _, err := rep.Identity()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return ca
}

// refusal checks a refusal of this document: status, a body that is the
// reason on one line, either exactly want or starting with it, and a
// Content-Type whose media type is text/plain (CLAIM-51). It reports
// through t.Errorf and says whether rep was the refusal.
func refusal(t *runner.T, what string, rep *claimant.Reply, status int, want string, exact bool) bool {
	reason, rest, _ := strings.Cut(string(rep.Body), "\n")
	reason = strings.TrimSuffix(reason, "\r")
	ok := true
	if rep.Status != status {
		t.Errorf("%s was answered %d %q, want %d", what, rep.Status, rep.Body, status)
		return false
	}
	switch {
	case exact && reason != want:
		t.Errorf("%s: the %d's body is %q, want %q", what, status, rep.Body, want)
		ok = false
	case !exact && !strings.HasPrefix(reason, want):
		t.Errorf("%s: the %d's body is %q, want one that starts %q", what, status, rep.Body, want)
		ok = false
	}
	if strings.TrimRight(rest, "\r\n") != "" {
		t.Errorf("%s: the %d's reason is not on one line: %q", what, status, rep.Body)
		ok = false
	}
	if mt, _, err := mime.ParseMediaType(rep.Header.Get("Content-Type")); err != nil || mt != "text/plain" {
		t.Errorf("%s: the %d has Content-Type %q, want text/plain", what, status, rep.Header.Get("Content-Type"))
		ok = false
	}
	return ok
}

// build is the harness's build environment on the relay's build link once
// the relay has been claimed with link (the claim's build_link, or nil),
// after the relay serves GET /health (the harness, D19). A vm-mode relay
// claimed without a build_link keeps an address the case cannot know, and
// has no build environment here.
func (r *relayRun) build(link map[string]string) *buildenv.Env {
	t, ctx := r.t, r.t.Context()
	var env *buildenv.Env
	var err error
	switch r.d.Link {
	case buildenv.Frames:
		frames, ferr := r.in.Frames()
		if ferr != nil {
			t.Fatalf("the relay's frame link: %v", ferr)
		}
		env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: frames, MAC: guestMAC})
	default:
		addr := r.d.Address
		if link != nil {
			addr = link["relay"]
		}
		a, perr := netip.ParseAddr(addr)
		if perr != nil {
			t.Fatalf("the relay's address on its build link, %q: %v", addr, perr)
		}
		env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: t.Network(attach.Build), Relay: a})
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

// get sends one request from the build environment, trusting ca for TLS,
// and returns its status and body, or the error the build saw.
func get(ctx context.Context, env *buildenv.Env, ca *x509.Certificate, method, url string) (int, []byte, error) {
	roots := x509.NewCertPool()
	if ca != nil {
		roots.AddCert(ca)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Close = true
	resp, err := env.Client(roots).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// fetchOrigin has the build fetch path of the default origin over scheme,
// and fails the case unless it receives the origin's 200 and body.
func fetchOrigin(t *runner.T, env *buildenv.Env, ca *x509.Certificate, scheme, path string) {
	url := scheme + "://" + originName + path
	status, b, err := get(t.Context(), env, ca, http.MethodGet, url)
	if err != nil {
		t.Fatalf("the build's GET %s: %v", url, err)
	}
	if want := upstream.Body(originName, path); status != http.StatusOK || !bytes.Equal(b, want) {
		t.Fatalf("the build's GET %s: %d with %d bytes, want 200 with the origin's %d", url, status, len(b), len(want))
	}
}

// exit ends the build (relay-guest-api, POST http://artifacts/exit) and
// waits for the collector's completion: the last request of the case.
func exit(t *runner.T, env *buildenv.Env, coll *collector.Collector) {
	if _, _, err := get(t.Context(), env, nil, http.MethodPost, "http://artifacts/exit?code=0"); err != nil {
		t.Logf("POST http://artifacts/exit: %v", err)
	}
	select {
	case <-coll.Done():
	case <-time.After(within):
		t.Fatalf("the collector received no completion within %s of the build's exit", within)
	case <-t.Context().Done():
		t.Fatalf("waiting for the completion: %v", t.Context().Err())
	}
}

// notAnswering polls the claim endpoint with an authorized claim, every
// 100 ms for at most within, until a connection is refused or closed with no
// reply, and fails the case if the relay answers one 200, or still answers
// at the end. After a 200 (spent false) a claim it still answers must be
// refused 409 "already claimed" (CLAIM-46). A relay spent by a 500 (spent
// true) accepts no further claim and ends (CLAIM-50), which names no answer
// for a claim it reads while it ends: any status but 200 is taken.
func (r *relayRun) notAnswering(what string, spent bool) {
	t := r.t
	deadline := time.Now().Add(within)
	h := http.Header{"Content-Type": {"application/json"}}
	if r.cl.Endpoint.Token != "" {
		h.Set("Authorization", "Bearer "+r.cl.Endpoint.Token)
	}
	body := r.base().body()
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		rep, err := r.cl.Do(ctx, http.MethodPost, "/v1/claim", h, body)
		cancel()
		if err != nil {
			return
		}
		if rep.Status == http.StatusOK {
			t.Fatalf("%s: a later claim was answered 200", what)
		}
		if !spent && !refusal(t, what+": a later claim", rep, http.StatusConflict, "already claimed", true) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the claim endpoint still answered claims %s later", what, within)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-t.Context().Done():
			t.Fatalf("%s: %v", what, t.Context().Err())
		}
	}
}
