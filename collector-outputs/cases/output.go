package cases

import (
	"net/http"
	"net/netip"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// resolverConf is the one nameserver of the harness's relay's resolver
// configuration, an address of a documentation range.
var resolverConf = netip.MustParseAddr("192.0.2.53")

// oneOutput has the harness's relay, with no build side, claimed by the
// collector under test, send it one piece of console output, which the
// collector answers 200 with an empty body. The collector is started for
// this case's relay alone, and so is a fresh instance.
//
// A collector that claims may leave upstream_dns out, so the relay is given a
// resolver configuration (CLAIM-32 in relay-claim) naming resolverConf, at
// which nothing listens: a relay on the tunnel resolves no name.
var oneOutput = runner.Case{
	Name:  "a collector accepts a piece of console output",
	Cites: []string{"COLLOUT-21"},
	Role:  "collector",
	Ends:  true,
	Run: func(t *runner.T) {
		ctx := t.Context()
		r, err := relay.Start(ctx, relay.Config{
			Net: t.Network(attach.Claim), Token: "conformance-claim-token",
			ResolvConf: []netip.Addr{resolverConf},
		})
		if err != nil {
			t.Fatalf("the harness's relay: %v", err)
		}
		t.Cleanup(func() { _ = r.Stop() })
		in := t.Instance(attach.Params{Claim: r.Claim().Address, Token: r.Claim().Token})
		s, err := r.Session(ctx)
		if err != nil {
			t.Fatalf("the collector's claim: %v; its log:\n%s", err, in.Log())
		}
		rep, err := s.Output(ctx, []byte("console\n"))
		if err != nil {
			t.Fatalf("POST /v1/output: %v", err)
		}
		if rep.Status != http.StatusOK || len(rep.Body) != 0 {
			t.Errorf("POST /v1/output was answered %d %q, want 200 with an empty body", rep.Status, rep.Body)
		}
	},
}
