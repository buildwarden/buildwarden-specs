package cases

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// beforeTheReply claims a fresh relay with an environment, and checks what
// the collector had received by the time the claim's 200 arrived: the
// ledger stream begun, the environment answered 200, and ready answered.
// Only the collector's side is observed: what the relay's build side serves
// at that moment is not asserted (Known divergences, D19).
var beforeTheReply = runner.Case{
	Name:  "the relay answers 200 only after the ledger stream, the environment and ready",
	Cites: []string{"CLAIM-44"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		env := map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": emptyMap}
		rep := r.send(r.base().with(claim{"environment": env}))
		replied := time.Now()
		accepted(t, "the claim", rep)
		find := func(method, path string) (collector.Request, bool) {
			for _, q := range coll.Requests() {
				if q.Method == method && q.Path == path {
					return q, true
				}
			}
			return collector.Request{}, false
		}
		if q, ok := find(http.MethodPut, "/v1/ledger"); !ok || !q.BeganAt.Before(replied) {
			t.Errorf("the ledger stream, PUT /v1/ledger, had not reached the collector when the claim's 200 arrived (%v)", ok)
		}
		if q, ok := find(http.MethodPut, "/v1/environment"); !ok || q.Status != http.StatusOK || !q.EndedAt.Before(replied) {
			t.Errorf("PUT /v1/environment had not been answered 200 when the claim's 200 arrived (%v, %d)", ok, q.Status)
		}
		if q, ok := find(http.MethodPost, "/v1/ready"); !ok || q.EndedAt.IsZero() || !q.EndedAt.Before(replied) {
			t.Errorf("POST /v1/ready had not been answered when the claim's 200 arrived (%v)", ok)
		}
	},
}

// readyRefused has the collector answer ready 500: the claim is still
// answered 200.
var readyRefused = runner.Case{
	Name:  "a failed ready does not fail the claim",
	Cites: []string{"CLAIM-44"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, func(q *http.Request) int {
			if q.URL.Path == "/v1/ready" {
				return http.StatusInternalServerError
			}
			return 0
		}))
		accepted(t, "the claim, its ready answered 500", r.send(r.base()))
	},
}

// afterTheClaim claims a fresh relay and then polls its claim endpoint: it
// stops accepting connections, and a claim it still reads is answered 409.
var afterTheClaim = runner.Case{
	Name:  "after its 200 the relay accepts no claim and stops accepting connections",
	Cites: []string{"CLAIM-46", "CLAIM-47"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		accepted(t, "the claim", r.send(r.base()))
		r.notAnswering("after the 200")
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if _, err := r.cl.OpenTunnel(ctx, coll); err == nil {
			t.Errorf("a tunnel was opened after the claim's 200")
		}
	},
}

// ledgerSigned claims a fresh relay, has the build fetch the origin and
// exit, and verifies the ledger the collector received under the reply's
// ledger_public_key, and not under another key.
var ledgerSigned = runner.Case{
	Name:  "the ledger's records verify under the reply's ledger_public_key",
	Cites: []string{"CLAIM-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		rep := r.send(r.base())
		ca := accepted(t, "the claim", rep)
		_, _, key, err := rep.Identity()
		if err != nil {
			t.Fatalf("the claim's identity: %v", err)
		}
		env := r.build(declaredLink(r.d))
		fetchOrigin(t, env, ca, "http", "/bytes/100")
		exit(t, env, coll)
		data, _, _ := coll.Ledger()
		l, err := ledger.Verify(data, key)
		if err != nil {
			t.Fatalf("the ledger does not verify under the reply's key: %v", err)
		}
		if len(l.Records) == 0 {
			t.Errorf("the ledger has no record of the build's exchange")
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := ledger.Verify(data, other); !errors.Is(err, ledger.ErrKey) {
			t.Errorf("the ledger verified under a key that is not the reply's: %v", err)
		}
	},
}
