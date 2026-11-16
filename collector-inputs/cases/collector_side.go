package cases

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The cases of the collector role start the harness's relay, with no build
// side, and have the collector under test claim it; they then send the
// session's requests themselves, through the relay's session. What follows
// is what they share.

// resolverConf is the one nameserver of the harness's relay's resolver
// configuration, an address of a documentation range.
var resolverConf = netip.MustParseAddr("192.0.2.53")

// claimToken is the claim token the harness's relay is started with.
const claimToken = "conformance-claim-token"

// claims is the Applies of every collector case: the harness reaches a
// collector by having it claim the harness's relay.
func claims(d target.Declared) string {
	if d.Attachment != "claims" {
		return "the case has the collector claim the harness's relay, and this collector does not claim"
	}
	return ""
}

// all is an Applies made of others: the first reason any of them gives.
func all(fs ...func(target.Declared) string) func(target.Declared) string {
	return func(d target.Declared) string {
		for _, f := range fs {
			if r := f(d); r != "" {
				return r
			}
		}
		return ""
	}
}

// hasToken applies to a collector that has a session token.
func hasToken(d target.Declared) string {
	if d.Forms.NoToken {
		return "the collector has no token"
	}
	return ""
}

// noToken applies to a collector that has none.
func noToken(d target.Declared) string {
	if !d.Forms.NoToken {
		return "the collector has a token"
	}
	return ""
}

// session is one session of the collector under test with the harness's
// relay.
type session struct {
	t  *runner.T
	r  *relay.Relay
	s  *relay.Session
	in attach.Instance
	// out is the collector's output location.
	out string
}

// claimedBy starts the harness's relay and an instance of the collector
// under test against it, with p's script and context, an output location of
// its own and the capture mode "none" unless p names them, and waits for
// the claim. A collector that claims may leave upstream_dns out, so the
// relay is given a resolver configuration naming resolverConf, at which
// nothing listens: a relay on the tunnel resolves no name.
func claimedBy(t *runner.T, p attach.Params) *session {
	ctx := t.Context()
	r, err := relay.Start(ctx, relay.Config{
		Net: t.Network(attach.Claim), Token: claimToken,
		ResolvConf: []netip.Addr{resolverConf},
	})
	if err != nil {
		t.Fatalf("the harness's relay: %v", err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	p.Claim, p.Token = r.Claim().Address, r.Claim().Token
	if p.Out == "" {
		p.Out = t.TempDir()
	}
	if p.Capture == "" {
		p.Capture = relay.CaptureNone
	}
	in := t.Instance(p)
	s, err := r.Session(ctx)
	if err != nil {
		t.Fatalf("the collector's claim: %v; its log:\n%s", err, in.Log())
	}
	return &session{t: t, r: r, s: s, in: in, out: p.Out}
}

// auth is the header a relay sends: the session's token, if it has one.
func (s *session) auth() http.Header {
	h := http.Header{}
	if tok := s.s.Token(); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// requireToken fails the case when the collector, which declares that it
// has a token, claimed without one.
func (s *session) requireToken() string {
	tok := s.s.Token()
	if tok == "" {
		s.t.Fatalf("the collector declares a token, and its claim carried no collector_token")
	}
	return tok
}

// do sends one request with header h, a body of no length in advance (nil
// for none) and trailer tr, and fails the case when it fails.
func (s *session) do(method, path string, h http.Header, body []byte, tr http.Header) *relay.Reply {
	var rd io.Reader
	if body != nil {
		// A reader whose length the client cannot see, so the body has no
		// length in advance.
		rd = io.MultiReader(bytes.NewReader(body))
	}
	rep, err := s.s.Do(s.t.Context(), method, path, h, rd, tr)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	return rep
}
