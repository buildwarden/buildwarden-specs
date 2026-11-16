package cases

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// authHeader is the Authorization header of r's claimant, if it has a token.
func (r *relayRun) authHeader(h http.Header) http.Header {
	if r.cl.Endpoint.Token != "" {
		h.Set("Authorization", "Bearer "+r.cl.Endpoint.Token)
	}
	return h
}

// tunnelRequest is the tunnel request a claimant sends (CLAIM-11).
func (r *relayRun) tunnelRequest() http.Header {
	return r.authHeader(http.Header{"Connection": {"Upgrade"}, "Upgrade": {"warden-tunnel"}})
}

// hasHeaderToken reports whether the header field holds token among its
// comma-separated values, compared without regard to case.
func hasHeaderToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// oneTunnel checks the 101 to a tunnel request, and that a relay accepts no
// second tunnel: once after a tunnel it accepted has closed, and once while
// the first is open, each on a fresh relay.
var oneTunnel = runner.Case{
	Name:  "an authorized tunnel request is answered 101, and a second one 409",
	Cites: []string{"CLAIM-12", "CLAIM-15"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		// The first relay's tunnel is taken by a request whose connection is
		// closed as soon as the 101 has been read.
		up := defaultWorld(t)
		r := newRun(t, up, attach.Params{})
		rep, err := r.cl.Do(t.Context(), http.MethodPost, "/v1/tunnel", r.tunnelRequest(), nil)
		if err != nil {
			t.Fatalf("POST /v1/tunnel: %v", err)
		}
		if rep.Status != http.StatusSwitchingProtocols {
			t.Fatalf("POST /v1/tunnel was answered %d %q, want 101", rep.Status, rep.Body)
		}
		if !hasHeaderToken(rep.Header, "Connection", "upgrade") || !strings.EqualFold(rep.Header.Get("Upgrade"), "warden-tunnel") {
			t.Errorf("the 101 has Connection %q and Upgrade %q, want Upgrade and warden-tunnel", rep.Header.Values("Connection"), rep.Header.Values("Upgrade"))
		}
		rep, err = r.cl.Do(t.Context(), http.MethodPost, "/v1/tunnel", r.tunnelRequest(), nil)
		if err != nil {
			t.Fatalf("a second POST /v1/tunnel, after the first tunnel closed: %v", err)
		}
		refusal(t, "a second tunnel, after the first closed", rep, http.StatusConflict, "tunnel already open", true)

		// The second relay's tunnel stays open.
		r2 := newRun(t, up, attach.Params{})
		r2.tunnel(collector.New(collector.Form{}, nil))
		rep, err = r2.cl.Do(t.Context(), http.MethodPost, "/v1/tunnel", r2.tunnelRequest(), nil)
		if err != nil {
			t.Fatalf("a second POST /v1/tunnel, while the first is open: %v", err)
		}
		refusal(t, "a second tunnel, while the first is open", rep, http.StatusConflict, "tunnel already open", true)
	},
}

// stalledClaim sends a claim whose body never ends: its headers and the
// first byte of a body of 100. The connection is closed when the case
// ends.
func (r *relayRun) stalledClaim() {
	t := r.t
	conn, err := r.cl.Net.Dial(t.Context(), "tcp", r.cl.Endpoint.Address)
	if err != nil {
		t.Fatalf("dialling the claim endpoint: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	auth := ""
	if r.cl.Endpoint.Token != "" {
		auth = "Authorization: Bearer " + r.cl.Endpoint.Token + "\r\n"
	}
	head := fmt.Sprintf("POST /v1/claim HTTP/1.1\r\nHost: %s\r\n%sContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", r.cl.Endpoint.Address, auth)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("writing the stalled claim: %v", err)
	}
}

// whileProcessing holds a claim in processing, its body stalled, and checks
// what the relay answers meanwhile: another claim 409 "already claimed",
// even one whose body is not JSON (the state before the body); a tunnel
// request 409 "tunnel already open"; and, before the state, a request with
// the wrong method 405 and one with no token 401.
//
// The relay gives no sign that it has read the stalled claim's headers, so
// the case first polls with a claim of {}, which a relay that is not yet
// processing the stalled claim refuses 400 and stays claimable, until it is
// answered 409, for at most within. A stalled claim that arrives while a
// poll is being processed is refused, and its refusal waits for a body that
// never ends, so each poll follows a stalled claim of its own, sent 100 ms
// before it: once one of them is being processed, the poll is answered 409.
var whileProcessing = runner.Case{
	Name:  "while a claim is being processed, another claim and a tunnel are answered 409",
	Cites: []string{"CLAIM-15", "CLAIM-42", "CLAIM-46"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		h := r.authHeader(http.Header{"Content-Type": {"application/json"}})
		deadline := time.Now().Add(within)
		for {
			r.stalledClaim()
			time.Sleep(100 * time.Millisecond)
			rep, err := r.cl.Do(t.Context(), http.MethodPost, "/v1/claim", h, []byte("{}"))
			if err != nil {
				t.Fatalf("a claim of {} beside the stalled claim: %v", err)
			}
			if rep.Status == http.StatusConflict {
				refusal(t, "a claim beside the stalled claim", rep, http.StatusConflict, "already claimed", true)
				break
			}
			if rep.Status != http.StatusBadRequest {
				t.Fatalf("a claim of {} beside the stalled claim was answered %d %q, want 409 or, before the relay has read the stalled claim's headers, 400", rep.Status, rep.Body)
			}
			if time.Now().After(deadline) {
				t.Fatalf("a claim beside the stalled claims was still answered 400, not 409, %s after the first was sent", within)
			}
		}
		ctx := t.Context()
		if rep, err := r.cl.Do(ctx, http.MethodPost, "/v1/claim", h, []byte("not JSON")); err != nil {
			t.Errorf("a claim whose body is not JSON, beside the stalled claim: %v", err)
		} else {
			refusal(t, "a claim whose body is not JSON, beside the stalled claim", rep, http.StatusConflict, "already claimed", true)
		}
		if rep, err := r.cl.Do(ctx, http.MethodPost, "/v1/tunnel", r.tunnelRequest(), nil); err != nil {
			t.Errorf("a tunnel beside the stalled claim: %v", err)
		} else {
			refusal(t, "a tunnel beside the stalled claim", rep, http.StatusConflict, "tunnel already open", true)
		}
		if rep, err := r.cl.Do(ctx, http.MethodGet, "/v1/claim", http.Header{}, nil); err != nil {
			t.Errorf("GET /v1/claim beside the stalled claim: %v", err)
		} else {
			refusal(t, "GET /v1/claim beside the stalled claim", rep, http.StatusMethodNotAllowed, "POST only", true)
		}
		if r.cl.Endpoint.Token != "" {
			if rep, err := r.cl.Do(ctx, http.MethodPost, "/v1/claim", http.Header{"Content-Type": {"application/json"}}, []byte("{}")); err != nil {
				t.Errorf("a claim with no token beside the stalled claim: %v", err)
			} else {
				refusal(t, "a claim with no token beside the stalled claim", rep, http.StatusUnauthorized, "unauthorized", true)
			}
		}
	},
}

// refusedKeepsClaimable has a fresh relay with its tunnel open refuse a
// claim 400, and then accept a valid claim over the same tunnel, on which
// the relay then sends the collector its requests.
var refusedKeepsClaimable = runner.Case{
	Name:  "a claim refused 400 leaves the relay claimable, with its tunnel open",
	Cites: []string{"CLAIM-16", "CLAIM-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		rep := r.send(r.base().with(claim{"upstream_dns": []string{}}))
		refusal(t, "a claim with an empty upstream_dns", rep, http.StatusBadRequest, "invalid claim: upstream_dns: ", false)
		accepted(t, "a valid claim after the 400", r.send(r.base()))
		if !tunnelUsed(coll) {
			t.Errorf("the collector on the tunnel received no request after the claim's 200: %v", coll.Requests())
		}
	},
}

// tunnelUsed reports whether the collector received a request over HTTP/2,
// as one on the tunnel is (CLAIM-13).
func tunnelUsed(coll *collector.Collector) bool {
	for _, q := range coll.Requests() {
		if q.Proto == "HTTP/2.0" {
			return true
		}
	}
	return false
}

// noTunnelOpen sends the shared relay, which has no tunnel, a claim that
// selects the tunnel and is otherwise valid.
var noTunnelOpen = runner.Case{
	Name:  "a claim that selects the tunnel when none is open is answered 400",
	Cites: []string{"CLAIM-22"},
	Role:  "relay",
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		rep := r.send(r.base())
		refusal(t, "a claim that selects the tunnel", rep, http.StatusBadRequest, "invalid claim: collector_url selects the tunnel, but none is open", true)
	},
}
