package cases

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// variant is one claim a case sends that the relay must refuse 400: its
// name in a failure, its body, and what the reason starts with.
type variant struct {
	name   string
	body   []byte
	prefix string
}

// refuseAll sends a fresh relay, with its tunnel open, each variant in turn,
// checking each is refused 400 with its prefix, and then a valid claim,
// which must be accepted: the refusals left the relay claimable with its
// tunnel open (CLAIM-48). Each variant is otherwise a valid claim, so a
// relay that accepted one would be claimed by it, and the variants after it
// and the valid claim would fail too.
func refuseAll(t *runner.T, variants func(r *relayRun) []variant) {
	r := startRelay(t, attach.Params{})
	r.tunnel(collector.New(collector.Form{}, nil))
	for _, v := range variants(r) {
		refusal(t, v.name, r.sendBody(v.body), http.StatusBadRequest, v.prefix, false)
	}
	accepted(t, "a valid claim after the refusals", r.send(r.base()))
}

// replaceIn is body with old, which occurs in it once, replaced by new: how a
// case writes a body a claim's encoding cannot.
func replaceIn(t *runner.T, body []byte, old, new string) []byte {
	if bytes.Count(body, []byte(old)) != 1 {
		t.Fatalf("the case's body %s does not hold %s once", body, old)
	}
	return bytes.Replace(body, []byte(old), []byte(new), 1)
}

// undecodable is each kind of body CLAIM-18 lists, at the top level and
// inside environment and build_link, and the reason a member that is not a
// field names (CLAIM-19).
var undecodable = runner.Case{
	Name:  "a claim that does not decode is answered 400 invalid claim",
	Cites: []string{"CLAIM-18", "CLAIM-19", "CLAIM-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		refuseAll(t, func(r *relayRun) []variant {
			b := r.base()
			env := map[string]any{"payload": "e30=", "metadata": "oA=="}
			link := map[string]string{"prefix": "10.100.0.0/30", "relay": "10.100.0.1", "guest": "10.100.0.2"}
			if l := declaredLink(r.d); l != nil {
				link = l
			}
			vs := []variant{
				{"a body that is not JSON", []byte("collector_url=http://collector.tunnel"), "invalid claim: "},
				{"a JSON array", []byte(`["http://collector.tunnel"]`), "invalid claim: "},
				{"a JSON string", []byte(`"http://collector.tunnel"`), "invalid claim: "},
				{"an empty body", nil, "invalid claim: "},
				{"collector_url a number", b.with(claim{"collector_url": 7}).body(), "invalid claim: "},
				{"upstream_dns a string", b.with(claim{"upstream_dns": "192.0.2.53"}).body(), "invalid claim: "},
				{"upstream_system_ca a string", b.with(claim{"upstream_system_ca": "false"}).body(), "invalid claim: "},
				{"environment an array", b.with(claim{"environment": []string{"e30="}}).body(), "invalid claim: "},
				{"an environment payload that is not base64", b.with(claim{"environment": map[string]any{"payload": "e30*", "metadata": "oA=="}}).body(), "invalid claim: "},
				{"an environment payload a number", b.with(claim{"environment": map[string]any{"payload": 7, "metadata": "oA=="}}).body(), "invalid claim: "},
				{"a build_link prefix a number", b.with(claim{"build_link": map[string]any{"prefix": 10, "relay": link["relay"], "guest": link["guest"]}}).body(), "invalid claim: "},
			}
			unknown := []struct {
				where, name string
				body        []byte
			}{
				{"the claim", "collector_urls", b.with(claim{"collector_urls": "http://collector.tunnel"}).body()},
				{"environment", "kind", b.with(claim{"environment": map[string]any{"payload": env["payload"], "metadata": env["metadata"], "kind": "x"}}).body()},
				{"build_link", "gateway", b.with(claim{"build_link": map[string]string{"prefix": link["prefix"], "relay": link["relay"], "guest": link["guest"], "gateway": link["relay"]}}).body()},
			}
			for _, u := range unknown {
				vs = append(vs, variant{"a member " + u.name + " of " + u.where, u.body, "invalid claim: "})
			}
			return vs
		})
	},
}

// unknownFieldNamed checks the reason of a claim with an unknown member on a
// relay of its own: it names the member as CLAIM-19 gives it.
var unknownFieldNamed = runner.Case{
	Name:  "the refusal of an unknown member names it",
	Cites: []string{"CLAIM-19"},
	Role:  "relay",
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		rep := r.send(r.base().with(claim{"collector_tokens": "x"}))
		if refusal(t, "a claim with a member collector_tokens", rep, http.StatusBadRequest, "invalid claim: ", false) &&
			!strings.Contains(string(rep.Body), `unknown field "collector_tokens"`) {
			t.Errorf("the refusal of a member collector_tokens is %q, which does not contain %q", rep.Body, `unknown field "collector_tokens"`)
		}
	},
}

// collectorURLRequired sends a claim without collector_url, and one whose
// collector_url is empty.
var collectorURLRequired = runner.Case{
	Name:  "a claim without a collector_url is answered 400",
	Cites: []string{"CLAIM-21", "CLAIM-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		const want = "invalid claim: collector_url is required"
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		for _, v := range []struct {
			name string
			c    claim
		}{
			{"a claim without collector_url", r.base().with(claim{"collector_url": remove})},
			{"a claim whose collector_url is empty", r.base().with(claim{"collector_url": ""})},
		} {
			refusal(t, v.name, r.send(v.c), http.StatusBadRequest, want, true)
		}
		accepted(t, "a valid claim after the refusals", r.send(r.base()))
	},
}

// buildLinkInvalid sends a build_link that breaks each rule of CLAIM-29 in
// turn. The refusal is the field's whatever the relay's mode, a
// container-mode relay's included.
var buildLinkInvalid = runner.Case{
	Name:  "a claim whose build_link breaks a rule is answered 400 invalid claim: build_link",
	Cites: []string{"CLAIM-29", "CLAIM-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		refuseAll(t, func(r *relayRun) []variant {
			links := []struct {
				name                 string
				prefix, relay, guest string
			}{
				{"an IPv6 prefix", "fd00::/126", "fd00::1", "fd00::2"},
				{"an IPv6 relay", "10.100.0.0/30", "fd00::1", "10.100.0.2"},
				{"a prefix that is not an address", "ten/30", "10.100.0.1", "10.100.0.2"},
				{"a prefix with no length", "10.100.0.0", "10.100.0.1", "10.100.0.2"},
				{"a prefix that is not its own network address", "10.100.0.1/30", "10.100.0.1", "10.100.0.2"},
				{"a prefix of length 31", "10.100.0.0/31", "10.100.0.0", "10.100.0.1"},
				{"a prefix of length 7", "10.0.0.0/7", "10.0.0.1", "10.0.0.2"},
				{"a relay outside the prefix", "10.100.0.0/30", "10.100.0.5", "10.100.0.2"},
				{"a guest outside the prefix", "10.100.0.0/30", "10.100.0.1", "10.100.1.2"},
				{"a relay at the network address", "10.100.0.0/29", "10.100.0.0", "10.100.0.2"},
				{"a guest at the broadcast address", "10.100.0.0/29", "10.100.0.1", "10.100.0.7"},
				{"relay and guest the same", "10.100.0.0/29", "10.100.0.1", "10.100.0.1"},
				{"a prefix in 0.0.0.0/8", "0.100.0.0/30", "0.100.0.1", "0.100.0.2"},
				{"a loopback prefix", "127.100.0.0/30", "127.100.0.1", "127.100.0.2"},
				{"a link-local prefix", "169.254.100.0/30", "169.254.100.1", "169.254.100.2"},
				{"a multicast prefix", "224.100.0.0/30", "224.100.0.1", "224.100.0.2"},
				{"a class E prefix", "240.100.0.0/30", "240.100.0.1", "240.100.0.2"},
			}
			var vs []variant
			for _, l := range links {
				vs = append(vs, variant{
					name:   "a build_link with " + l.name,
					body:   r.base().with(claim{"build_link": map[string]string{"prefix": l.prefix, "relay": l.relay, "guest": l.guest}}).body(),
					prefix: "invalid claim: build_link: ",
				})
			}
			for _, m := range []string{"prefix", "relay", "guest"} {
				l := map[string]string{"prefix": "10.100.0.0/30", "relay": "10.100.0.1", "guest": "10.100.0.2"}
				delete(l, m)
				vs = append(vs, variant{"a build_link without " + m, r.base().with(claim{"build_link": l}).body(), "invalid claim: build_link: "})
			}
			return vs
		})
	},
}

// upstreamDNSInvalid sends an upstream_dns that breaks each rule of CLAIM-30
// in turn, the last with a build_link that holds an entry.
var upstreamDNSInvalid = runner.Case{
	Name:  "a claim whose upstream_dns breaks a rule is answered 400 invalid claim: upstream_dns",
	Cites: []string{"CLAIM-30", "CLAIM-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		refuseAll(t, func(r *relayRun) []variant {
			lists := []struct {
				name string
				list []string
			}{
				{"empty", []string{}},
				{"an IPv6 entry", []string{"2001:db8::53"}},
				{"an entry with a port", []string{"192.0.2.53:53"}},
				{"an entry that is a name", []string{"resolver.example"}},
				{"the unspecified address", []string{"0.0.0.0"}},
				{"a multicast address", []string{"224.0.0.251"}},
				{"the broadcast address", []string{"255.255.255.255"}},
				{"a valid entry and then an invalid one", []string{resolverAddr.String(), "2001:db8::53"}},
			}
			var vs []variant
			for _, l := range lists {
				vs = append(vs, variant{"an upstream_dns that is " + l.name, r.base().with(claim{"upstream_dns": l.list}).body(), "invalid claim: upstream_dns: "})
			}
			link := map[string]string{"prefix": "10.100.0.0/29", "relay": "10.100.0.1", "guest": "10.100.0.2"}
			if l := declaredLink(r.d); l != nil {
				link = l
			}
			vs = append(vs, variant{"an upstream_dns entry inside the build_link", r.base().with(claim{"build_link": link, "upstream_dns": []string{resolverAddr.String(), link["guest"]}}).body(), "invalid claim: upstream_dns: "})
			return vs
		})
	},
}

// claimLimit has a fresh relay, its tunnel open, refuse a claim whose JSON
// object ends one byte after 16 MiB, and then accept a valid claim of exactly
// 16 MiB. Both are padded with white space inside the object.
var claimLimit = runner.Case{
	Name:  "a claim of 16 MiB is accepted, and one whose object ends after it is refused",
	Cites: []string{"CLAIM-52"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		const limit = 16 << 20
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, nil))
		padded := func(size int) []byte {
			b := r.base().body()
			pad := bytes.Repeat([]byte(" "), size-len(b))
			return append(append(append([]byte{}, b[:len(b)-1]...), pad...), '}')
		}
		refusal(t, "a claim of 16 MiB and one byte", r.sendBody(padded(limit+1)), http.StatusBadRequest, "invalid claim: ", false)
		accepted(t, "a claim of 16 MiB", r.sendBody(padded(limit)))
	},
}
