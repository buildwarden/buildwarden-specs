package cases

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The address and name at which collectorAtURL serves the harness's
// collector on the upstream, and an address on the upstream at which
// nothing listens.
var (
	collectorAddr = netip.MustParseAddr("192.0.2.70")
	nobodyAddr    = netip.MustParseAddr("192.0.2.71")
)

const collectorName = "collector.example"

// collectorAtURL claims a fresh relay with a collector_url that is not the
// tunnel: a name the claim's one resolver answers with an address of the
// upstream, where the harness's collector serves, written with a trailing
// slash. No tunnel is opened.
var collectorAtURL = runner.Case{
	Name:  "a collector_url that is not the tunnel is a base URL the relay requests itself",
	Cites: []string{"CLAIM-23", "CLAIM-31"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.up.Resolvers[0].Set(collectorName, collectorAddr)
		coll := collector.New(collector.Form{}, nil)
		l, err := t.Network(attach.Upstream).Listen(t.Context(), "tcp", netip.AddrPortFrom(collectorAddr, 80).String())
		if err != nil {
			t.Fatalf("the collector's listener: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() { _ = coll.Serve(l) }()
		accepted(t, "the claim", r.send(r.base().with(claim{"collector_url": "http://" + collectorName + "/"})))
		reqs := coll.Requests()
		if len(reqs) == 0 {
			t.Fatalf("the collector at http://%s/ received no request before the claim's 200", collectorName)
		}
		for _, q := range reqs {
			if !strings.HasPrefix(q.Path, "/v1/") {
				t.Errorf("the relay requested %s %q of the collector, whose path does not start /v1/ (the base URL's trailing / is removed)", q.Method, q.Path)
			}
		}
		asked := false
		for _, q := range r.up.Resolvers[0].Queries() {
			asked = asked || strings.EqualFold(q.Name, collectorName+".")
		}
		if !asked {
			t.Errorf("the claim's resolver %s was not asked for %s", resolverAddr, collectorName)
		}
	},
}

// collectorUnreachable claims a fresh relay with a collector_url at which
// nothing listens: the start fails, and the relay is spent.
var collectorUnreachable = runner.Case{
	Name:  "a collector the relay cannot reach fails its start with 500, and the relay is spent",
	Cites: []string{"CLAIM-23", "CLAIM-50"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		rep := r.send(r.base().with(claim{"collector_url": "http://" + nobodyAddr.String()}))
		if refusal(t, "the claim", rep, http.StatusInternalServerError, "relay start failed: ", false) {
			r.notAnswering("after the 500", true)
		}
	},
}

// collectorToken is a case for each of a collector_token, an empty one and
// none, each claiming a fresh relay, which checks the Authorization header
// of every request the relay sent the collector before its 200: the ledger
// stream, ready and, where there is one, the rest, all over the tunnel.
func collectorToken() []runner.Case {
	var out []runner.Case
	for _, v := range []struct {
		name   string
		member any
		want   string
	}{
		{"a collector_token", "session-token", "Bearer session-token"},
		{"an empty collector_token", "", ""},
		{"no collector_token", remove, ""},
	} {
		out = append(out, runner.Case{
			Name:  "with " + v.name + ", every collector request has Authorization " + quote(v.want),
			Cites: []string{"CLAIM-24", "CLAIM-13"},
			Role:  "relay",
			Ends:  true,
			Run: func(t *runner.T) {
				r := startRelay(t, attach.Params{})
				coll := collector.New(collector.Form{Token: strings.TrimPrefix(v.want, "Bearer ")}, nil)
				r.tunnel(coll)
				accepted(t, "a claim with "+v.name, r.send(r.base().with(claim{"collector_token": v.member})))
				reqs := coll.Requests()
				if len(reqs) == 0 {
					t.Errorf("the collector received no request before the claim's 200")
				}
				for _, q := range reqs {
					if got := strings.Join(q.Header.Values("Authorization"), ", "); got != v.want {
						t.Errorf("%s %s carried Authorization %q, want %q", q.Method, q.Path, got, v.want)
					}
					if q.Proto != "HTTP/2.0" {
						t.Errorf("%s %s came over %s, not the tunnel's HTTP/2", q.Method, q.Path, q.Proto)
					}
				}
			},
		})
	}
	return out
}

// captureModes is a case for each capture_mode value, and an absent one,
// each claiming a fresh relay, having the build fetch the origin over HTTP
// and exit, and checking whether the collector stored a capture.
func captureModes() []runner.Case {
	var out []runner.Case
	for _, v := range []struct {
		mode    any
		capture bool
	}{
		{remove, false}, {"", false}, {"none", false},
		{"headers", true}, {"bodies", true}, {"all", true},
	} {
		name := "capture_mode absent"
		if s, ok := v.mode.(string); ok {
			name = "capture_mode \"" + s + "\""
		}
		what := "captures nothing"
		if v.capture {
			what = "captures the build's exchange"
		}
		out = append(out, runner.Case{
			Name:  "a claim with " + name + " " + what,
			Cites: []string{"CLAIM-25"},
			Role:  "relay",
			Ends:  true,
			Run: func(t *runner.T) {
				r := startRelay(t, attach.Params{})
				coll := collector.New(collector.Form{}, nil)
				r.tunnel(coll)
				ca := accepted(t, "a claim with "+name, r.send(r.base().with(claim{"capture_mode": v.mode})))
				env := r.build(declaredLink(r.d))
				fetchOrigin(t, env, ca, "http", "/bytes/100")
				exit(t, env, coll)
				if got := len(coll.Captures()); v.capture != (got > 0) {
					t.Errorf("the collector stored %d captures of the build's one exchange", got)
				}
			},
		})
	}
	return out
}

// upstreamRoots is a case for each of upstream_ca_certs holding the
// origins' CA, with upstream_system_ca false and true, and holding another
// CA only, with upstream_system_ca false. Each claims a fresh relay and has
// the build fetch the origin over TLS: with the origins' CA the fetch
// succeeds; with the other the relay must not trust the origin, which
// therefore receives no request over TLS. Where the origins' CA is sent, it
// is the second certificate of a bundle whose first is another CA's, so that
// every certificate of an entry must be trusted (CLAIM-26). Whether the
// relay's system roots are in or out (CLAIM-27) is not checked: they are its
// host's, and the origins' CA is never one of them.
func upstreamRoots() []runner.Case {
	var out []runner.Case
	for _, v := range []struct {
		name    string
		trusted bool
		system  bool
	}{
		{"the origins' CA and upstream_system_ca false", true, false},
		{"the origins' CA and upstream_system_ca true", true, true},
		{"another CA only and upstream_system_ca false", false, false},
	} {
		verdict := "trusts the origin"
		if !v.trusted {
			verdict = "trusts no origin outside them"
		}
		out = append(out, runner.Case{
			Name:  "upstream TLS with " + v.name + " in the claim " + verdict,
			Cites: []string{"CLAIM-26"},
			Role:  "relay",
			Ends:  true,
			Run: func(t *runner.T) {
				r := startRelay(t, attach.Params{})
				coll := collector.New(collector.Form{}, nil)
				r.tunnel(coll)
				other, err := upstream.NewCA()
				if err != nil {
					t.Fatalf("a CA: %v", err)
				}
				roots := string(other.PEM())
				if v.trusted {
					roots += string(r.up.CA.PEM())
				}
				ca := accepted(t, "a claim with "+v.name, r.send(r.base().with(claim{"upstream_ca_certs": []string{roots}, "upstream_system_ca": v.system})))
				env := r.build(declaredLink(r.d))
				if v.trusted {
					fetchOrigin(t, env, ca, "https", "/bytes/100")
					return
				}
				status, b, err := get(t.Context(), env, ca, http.MethodGet, "https://"+originName+"/bytes/100")
				if err == nil && status == http.StatusOK && bytes.Equal(b, upstream.Body(originName, "/bytes/100")) {
					t.Errorf("the build received the origin's body over TLS")
				}
				for _, x := range r.up.Origins.Exchanges() {
					if x.Port == 443 {
						t.Errorf("the origin received %s %s over TLS from the relay", x.Method, x.Target)
					}
				}
			},
		})
	}
	return out
}

// payload is s in standard base64 with padding, as a claim's byte string.
func payload(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// emptyMap is the CBOR encoding of an empty map: a valid metadata.
var emptyMap = base64.StdEncoding.EncodeToString([]byte{0xa0})

// environmentLanded is a case for a typed payload, one with its type given,
// and an image manifest, each claiming a fresh relay and checking that the
// collector received the payload's bytes in PUT /v1/environment, answered
// 200 before the claim's 200 arrived.
func environmentLanded() []runner.Case {
	var out []runner.Case
	for _, v := range []struct{ name, typ, payload string }{
		{"a typed payload", "", `{"type":"conformance-test/v1","n":1}`},
		{"a typed payload with its type given", "conformance-test/v1", `{"type":"conformance-test/v1"}`},
		{"an image manifest with the type oci-image/v1", "oci-image/v1", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`},
	} {
		out = append(out, runner.Case{
			Name:  "an environment with " + v.name + " is landed with the collector before the claim's 200",
			Cites: []string{"CLAIM-28", "CLAIM-44"},
			Role:  "relay",
			Ends:  true,
			Run: func(t *runner.T) {
				r := startRelay(t, attach.Params{})
				coll := collector.New(collector.Form{}, nil)
				r.tunnel(coll)
				env := map[string]any{"payload": payload(v.payload), "metadata": emptyMap}
				if v.typ != "" {
					env["type"] = v.typ
				}
				rep := r.send(r.base().with(claim{"environment": env}))
				replied := time.Now()
				accepted(t, "the claim", rep)
				got, n := coll.Environment()
				if n != 1 || string(got) != v.payload {
					t.Errorf("the collector received %d environments, the last %q; want 1, %q", n, got, v.payload)
				}
				for _, q := range coll.Requests() {
					if q.Method == http.MethodPut && q.Path == "/v1/environment" && (q.Status != http.StatusOK || !q.EndedAt.Before(replied)) {
						t.Errorf("PUT /v1/environment was answered %d at %v, and the claim's 200 had arrived by %v", q.Status, q.EndedAt, replied)
					}
				}
			},
		})
	}
	return out
}

// environmentUnusable claims a fresh relay with each environment the relay
// cannot use, landed with a collector that answers it 200, and with a valid
// one the collector refuses: each fails the start with 500, and the relay
// is spent (Known divergences, D6).
var environmentUnusable = runner.Case{
	Name:  "an environment the relay cannot use fails its start with 500",
	Cites: []string{"CLAIM-28", "CLAIM-50", "CLAIM-53"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		big := `{"type":"conformance-test/v1","pad":"` + strings.Repeat("a", 1<<20) + `"}`
		cbor := func(b ...byte) string { return base64.StdEncoding.EncodeToString(b) }
		up := defaultWorld(t)
		for _, v := range []struct {
			name   string
			env    map[string]any
			refuse bool
		}{
			{"an empty payload", map[string]any{"payload": "", "metadata": emptyMap}, false},
			{"a payload over 1 MiB", map[string]any{"payload": payload(big), "metadata": emptyMap}, false},
			{"a payload that is not a JSON object", map[string]any{"payload": payload(`["conformance-test/v1"]`), "metadata": emptyMap}, false},
			{"a payload that names no type", map[string]any{"payload": payload(`{"n":1}`), "metadata": emptyMap}, false},
			{"a payload whose type is empty", map[string]any{"payload": payload(`{"type":""}`), "metadata": emptyMap}, false},
			{"a type that differs from the payload's", map[string]any{"type": "other/v1", "payload": payload(`{"type":"conformance-test/v1"}`), "metadata": emptyMap}, false},
			{"metadata that is a CBOR array", map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": cbor(0x80)}, false},
			{"metadata with an integer key", map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": cbor(0xa1, 0x01, 0x01)}, false},
			{"metadata with bytes after the map", map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": cbor(0xa0, 0x00)}, false},
			{"a valid environment the collector refuses", map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": emptyMap}, true},
		} {
			r := newRun(t, up, attach.Params{})
			// The collector answers PUT /v1/environment 500 for the one
			// variant it refuses, and 200 for every other, whatever it
			// holds: the harness's collector would refuse some of those
			// itself (a payload over its own limit), and the 500 must
			// come from the relay's own check of the environment.
			answer := http.StatusOK
			if v.refuse {
				answer = http.StatusInternalServerError
			}
			fault := func(q *http.Request) int {
				if q.URL.Path == "/v1/environment" {
					return answer
				}
				return 0
			}
			r.tunnel(collector.New(collector.Form{}, fault))
			rep := r.send(r.base().with(claim{"environment": v.env}))
			if refusal(t, "a claim with "+v.name, rep, http.StatusInternalServerError, "relay start failed: ", false) {
				r.notAnswering("after the 500 to a claim with "+v.name, true)
			}
		}
	},
}
