package cases

import (
	"net/http"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The paths of the two endpoints.
var endpoints = []string{"/v1/tunnel", "/v1/claim"}

// methodsRefused sends every method but POST to both endpoints, each on a
// connection of its own and with no Authorization header, so that a relay
// that looked at the token first would answer 401. The relay is the shared
// one and stays as it was.
var methodsRefused = runner.Case{
	Name:  "both endpoints answer any method but POST 405 before the token",
	Cites: []string{"CLAIM-2", "CLAIM-4", "CLAIM-42", "CLAIM-51"},
	Role:  "relay",
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		for _, path := range endpoints {
			for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
				rep, err := r.cl.Do(t.Context(), m, path, http.Header{}, nil)
				if err != nil {
					t.Errorf("%s %s: %v", m, path, err)
					continue
				}
				refusal(t, m+" "+path, rep, http.StatusMethodNotAllowed, "POST only", true)
			}
		}
	},
}

// hasToken applies to a relay that can be started with a claim token.
func hasToken(d target.Declared) string {
	if !d.ClaimToken {
		return "the relay cannot be started with a claim token"
	}
	return ""
}

// tokenRefused sends both endpoints a request with no Authorization header
// and one with another token, to the shared relay, which was started with a
// token. Only the Bearer form is sent: what the relay makes of another form
// is not asserted (Known divergences, D8).
var tokenRefused = runner.Case{
	Name:    "a relay started with a token answers a request without it 401",
	Cites:   []string{"CLAIM-5", "CLAIM-51"},
	Role:    "relay",
	Applies: hasToken,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		if r.cl.Endpoint.Token == "" {
			t.Fatalf("the relay was started with no claim token, though the target declares it can be")
		}
		for _, path := range endpoints {
			for _, auth := range []string{"", "Bearer not-" + r.cl.Endpoint.Token} {
				h := http.Header{}
				if path == "/v1/claim" {
					h.Set("Content-Type", "application/json")
				} else {
					h.Set("Connection", "Upgrade")
					h.Set("Upgrade", "warden-tunnel")
				}
				if auth != "" {
					h.Set("Authorization", auth)
				}
				var body []byte
				if path == "/v1/claim" {
					body = r.base().body()
				}
				rep, err := r.cl.Do(t.Context(), http.MethodPost, path, h, body)
				if err != nil {
					t.Errorf("POST %s with Authorization %q: %v", path, auth, err)
					continue
				}
				refusal(t, "POST "+path+" with Authorization "+quote(auth), rep, http.StatusUnauthorized, "unauthorized", true)
			}
		}
	},
}

func quote(s string) string {
	if s == "" {
		return "absent"
	}
	return "\"" + s + "\""
}

// unauthorizedConsumesNothing has a fresh relay refuse an unauthorized
// tunnel and an unauthorized claim, and then accept an authorized tunnel
// and claim.
var unauthorizedConsumesNothing = runner.Case{
	Name:    "a 401 consumes neither the tunnel nor the claim",
	Cites:   []string{"CLAIM-7", "CLAIM-8"},
	Role:    "relay",
	Ends:    true,
	Applies: hasToken,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		wrong := claimant.Claimant{Net: r.cl.Net, Endpoint: attach.Endpoint{Address: r.cl.Endpoint.Address, Token: "not-" + r.cl.Endpoint.Token}}
		coll := collector.New(collector.Form{}, nil)
		if _, err := wrong.OpenTunnel(t.Context(), coll); err == nil {
			t.Fatalf("a tunnel with the wrong token was opened")
		} else if re, ok := err.(*claimant.RefusedError); !ok || re.Reply.Status != http.StatusUnauthorized {
			t.Fatalf("a tunnel with the wrong token: %v, want a 401", err)
		}
		rep, err := wrong.ClaimBody(t.Context(), r.base().body())
		if err != nil {
			t.Fatalf("a claim with the wrong token: %v", err)
		}
		refusal(t, "a claim with the wrong token", rep, http.StatusUnauthorized, "unauthorized", true)
		r.tunnel(coll)
		accepted(t, "the authorized claim after the 401s", r.send(r.base()))
	},
}

// noToken starts a relay without a claim token and claims it with a tunnel
// request that carries a token and a claim that carries none.
var noToken = runner.Case{
	Name:  "a relay started without a token accepts requests whatever their Authorization",
	Cites: []string{"CLAIM-9"},
	Role:  "relay",
	Ends:  true,
	Applies: func(d target.Declared) string {
		if !d.NoClaimToken {
			return "the relay cannot be started without a claim token"
		}
		return ""
	},
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{NoClaimToken: true})
		if r.cl.Endpoint.Token != "" {
			t.Fatalf("the relay was started with a claim token, though the case asked for none")
		}
		some := claimant.Claimant{Net: r.cl.Net, Endpoint: attach.Endpoint{Address: r.cl.Endpoint.Address, Token: "any-token"}}
		coll := collector.New(collector.Form{}, nil)
		tun, err := some.OpenTunnelFor(t.Context(), coll)
		if err != nil {
			t.Fatalf("a tunnel with Authorization: Bearer any-token: %v", err)
		}
		t.Cleanup(func() { _ = tun.Close() })
		accepted(t, "a claim with no Authorization", r.send(r.base()))
	},
}
