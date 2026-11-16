package cases

import (
	"mime"
	"net/http"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	relayclaim "github.com/buildwarden/buildwarden-specs/relay-claim"
)

// identitySchema is the schema of a 200 reply's body (CLAIM-33).
const identitySchema = "v1.identity.schema.json"

// authorizedClaim is an authorized claim over the tunnel, which the relay
// answers 200 with an identity. The tunnel and the claim carry the token the
// relay was started with, if any; the claim carries the build_link the target
// declares and, so that it does not depend on the relay's resolver
// configuration, the harness's upstream address as its one resolver. It cites
// only the reply: the tunnel's 101 and the token's form are checked by the
// cases that cite their requirements.
var authorizedClaim = runner.Case{
	Name:  "an authorized claim over the tunnel is answered 200 with an identity",
	Cites: []string{"CLAIM-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		in := t.Instance(attach.Params{})
		d := t.Declared()
		cfg := claimant.Config{UpstreamDNS: []string{t.Network(attach.Upstream).Address().String()}}
		if d.BuildLink != nil {
			cfg.BuildLink = &claimant.BuildLink{Prefix: d.BuildLink.Prefix, Relay: d.BuildLink.Relay, Guest: d.BuildLink.Guest}
		}
		cl := claimant.Claimant{Net: t.Network(attach.Claim), Endpoint: in.Claim()}
		tun, rep, err := cl.Session(t.Context(), collector.New(collector.Form{}, nil), cfg)
		if tun != nil {
			t.Cleanup(func() { _ = tun.Close() })
		}
		if err != nil {
			t.Fatalf("the tunnel and the claim: %v", err)
		}
		if rep.Status != http.StatusOK {
			t.Fatalf("the claim was answered %d %q, want 200", rep.Status, rep.Body)
		}
		if mt, _, err := mime.ParseMediaType(rep.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			t.Errorf("the claim's 200 has Content-Type %q, want application/json", rep.Header.Get("Content-Type"))
		}
		if err := relayclaim.Spec.Validate(identitySchema, rep.Body); err != nil {
			t.Errorf("the claim's 200: %v; the body: %q", err, rep.Body)
		}
		_, ca, _, err := rep.Identity()
		if err != nil {
			t.Fatalf("the claim's 200: %v", err)
		}
		if !ca.IsCA {
			t.Errorf("the claim's ca_cert, %q, is not a certificate authority's", ca.Subject)
		}
	},
}
