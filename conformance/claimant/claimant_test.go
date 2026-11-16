package claimant

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/blake2b"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
)

var loopback = attach.Host(netip.MustParseAddr("127.0.0.1"))

// schema compiles a schema file of the relay-claim directory, beside the
// harness in this checkout.
func schema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "relay-claim", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, b []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not JSON: %v: %s", err, b)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("%s does not validate: %v", b, err)
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func boolp(b bool) *bool { return &b }

// TestTunnelAndClaim holds the claimant's two requests to relay-claim: the
// tunnel's headers (CLAIM-11), the token on both (CLAIM-8), the tunnel open
// before the claim (CLAIM-43), and a claim that validates against
// v1.config.schema.json (CLAIM-17).
func TestTunnelAndClaim(t *testing.T) {
	t.Parallel()
	s := newStandIn(t, "tok")
	coll := collector.New(collector.Form{Token: "sess"}, nil)
	c := Claimant{Net: loopback, Endpoint: s.endpoint()}
	cfg := Config{
		CollectorToken: "sess", CaptureMode: "all",
		UpstreamCACerts:  []string{testCA(t)},
		UpstreamSystemCA: boolp(false),
		Environment:      &Environment{Type: "oci-image/v1", Payload: []byte(`{"type":"oci-image/v1"}`), Metadata: []byte{0xa0}},
		BuildLink:        &BuildLink{Prefix: "192.0.2.0/30", Relay: "192.0.2.1", Guest: "192.0.2.2"},
		UpstreamDNS:      []string{"198.51.100.53"},
	}
	tun, rep, err := c.Session(ctx(t), coll, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if rep.Status != http.StatusOK {
		t.Fatalf("claim: %d %s", rep.Status, rep.Body)
	}
	id, ca, key, err := rep.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || id.LedgerPublicKey != standInKey || len(key) != 32 {
		t.Errorf("identity: CA %v, key %s", ca.IsCA, id.LedgerPublicKey)
	}

	tr := s.tunnelRq
	for k, want := range map[string]string{"Connection": "Upgrade", "Upgrade": "warden-tunnel", "Content-Length": "0", "Authorization": "Bearer tok"} {
		got := tr.Header.Get(k)
		if k == "Content-Length" && tr.ContentLength == 0 {
			got = "0"
		}
		if got != want {
			t.Errorf("tunnel request %s = %q, want %q", k, got, want)
		}
	}
	cr := s.claimRq
	if cr.Header.Get("Content-Type") != "application/json" || cr.Header.Get("Authorization") != "Bearer tok" {
		t.Errorf("claim headers: %v", cr.Header)
	}
	validate(t, schema(t, "v1.config.schema.json"), s.claim)
	var sent map[string]any
	if err := json.Unmarshal(s.claim, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["collector_url"] != TunnelURL {
		t.Errorf("collector_url = %v", sent["collector_url"])
	}

	// The collector heard the session's start over the tunnel, with the
	// session's token: the ledger, the environment, ready.
	var paths []string
	for _, r := range coll.Requests() {
		paths = append(paths, r.Method+" "+r.Path)
		// The ledger request is open until the build ends.
		if (r.Status != http.StatusOK && r.Path != "/v1/ledger") || r.Proto != "HTTP/2.0" {
			t.Errorf("%s %s over %s: %d", r.Method, r.Path, r.Proto, r.Status)
		}
	}
	slices.Sort(paths)
	if got := strings.Join(paths, ", "); got != "POST /v1/ready, PUT /v1/environment, PUT /v1/ledger" {
		t.Errorf("the collector received %s", got)
	}
}

// TestClaimLeavesOutEmptyFields holds the claim to CLAIM-20: a field with no
// value is not sent.
func TestClaimLeavesOutEmptyFields(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Config{CollectorURL: TunnelURL})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"collector_url":"http://collector.tunnel"}` {
		t.Errorf("claim = %s", b)
	}
	validate(t, schema(t, "v1.config.schema.json"), b)
}

// flaky is a network whose first dials fail as a relay that is still
// starting fails them: refused, or closed before any reply.
type flaky struct {
	attach.Network
	mu      sync.Mutex
	refuse  int
	hangup  int
	dials   int
	address string
}

func (f *flaky) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	refuse, hangup := f.refuse > 0, f.refuse == 0 && f.hangup > 0
	if refuse {
		f.refuse--
	} else if hangup {
		f.hangup--
	}
	f.mu.Unlock()
	if refuse {
		return nil, errors.New("connection refused")
	}
	if hangup {
		a, b := net.Pipe()
		go func() {
			_, _ = io.CopyN(io.Discard, b, 1)
			_ = b.Close()
		}()
		return a, nil
	}
	return f.Network.Dial(ctx, network, address)
}

// TestRetry holds the claimant to CLAIM-3 and CLAIM-35: a connection that
// fails before the relay answers is tried again, and a reply is final.
func TestRetry(t *testing.T) {
	t.Parallel()
	s := newStandIn(t, "")
	net := &flaky{Network: loopback, refuse: 2, hangup: 2}
	c := Claimant{Net: net, Endpoint: s.endpoint()}
	tun, err := c.OpenTunnel(ctx(t), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if net.dials != 5 {
		t.Errorf("%d dials, want 5: two refused, two closed, one answered", net.dials)
	}

	// A second tunnel is refused 409, once.
	net.dials = 0
	_, err = c.OpenTunnel(ctx(t), http.NotFoundHandler())
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Reply.Status != http.StatusConflict || !errors.Is(err, ErrRefused) {
		t.Fatalf("second tunnel: %v", err)
	}
	if net.dials != 1 {
		t.Errorf("a refused tunnel was dialled %d times", net.dials)
	}

	// A claim refused 400 is not sent again.
	net.dials = 0
	rep, err := c.ClaimBody(ctx(t), []byte(`{"collector_url":"http://collector.tunnel","x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != http.StatusBadRequest || !bytes.HasPrefix(rep.Body, []byte("invalid claim: ")) || net.dials != 1 {
		t.Errorf("claim: %d %q after %d dials", rep.Status, rep.Body, net.dials)
	}
	if _, _, _, err := rep.Identity(); err == nil {
		t.Error("a 400 read as an identity")
	}
}

// TestRetryGivesUp ends at the context, with the failure.
func TestRetryGivesUp(t *testing.T) {
	t.Parallel()
	c := Claimant{Net: &flaky{Network: loopback, refuse: 1 << 30}, Endpoint: attach.Endpoint{Address: "127.0.0.1:1"}}
	cx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if _, err := c.Claim(cx, Config{CollectorURL: TunnelURL}); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Claim = %v, want the context's end", err)
	}
}

// TestIdentity holds the reading of a 200 to CLAIM-34.
func TestIdentity(t *testing.T) {
	t.Parallel()
	ca := testCA(t)
	good, _ := json.Marshal(map[string]any{"ca_cert": ca, "ledger_public_key": standInKey, "later_member": true})
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"unknown members ignored", good, ""},
		{"no ca_cert", []byte(`{"ledger_public_key":"` + standInKey + `"}`), "no ca_cert"},
		{"empty ca_cert", []byte(`{"ca_cert":"","ledger_public_key":"` + standInKey + `"}`), "no ca_cert"},
		{"not PEM", []byte(`{"ca_cert":"x","ledger_public_key":"` + standInKey + `"}`), "no PEM certificate"},
		{"bad key", []byte(`{"ca_cert":` + string(mustJSON(t, ca)) + `,"ledger_public_key":"AB"}`), "ledger_public_key"},
		{"not an object", []byte(`[]`), "not a JSON object"},
	}
	for _, tt := range tests {
		r := &Reply{Status: http.StatusOK, Body: tt.body}
		_, _, _, err := r.Identity()
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: %v", tt.name, err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
	validate(t, schema(t, "v1.identity.schema.json"), good)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDo sends a request of the case's making as it is, once: no token is
// added.
func TestDo(t *testing.T) {
	t.Parallel()
	s := newStandIn(t, "tok")
	c := Claimant{Net: loopback, Endpoint: s.endpoint()}
	for _, tt := range []struct {
		method string
		h      http.Header
		status int
		body   string
	}{
		{http.MethodGet, nil, http.StatusMethodNotAllowed, "POST only\n"},
		{http.MethodPost, nil, http.StatusUnauthorized, "unauthorized\n"},
		{http.MethodPost, http.Header{"Authorization": {"bearer tok"}}, http.StatusUnauthorized, "unauthorized\n"},
	} {
		rep, err := c.Do(ctx(t), tt.method, "/v1/claim", tt.h, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Status != tt.status || string(rep.Body) != tt.body {
			t.Errorf("%s %v: %d %q", tt.method, tt.h, rep.Status, rep.Body)
		}
	}
}

// TestSessionInEveryForm runs a whole session over the tunnel, from the
// stand-in's side, against the harness's collector in each form it can be
// started in: every output stored, every input answered as the form has it,
// the first completion the result, and the tunnel closed at the completion
// or kept open after it.
func TestSessionInEveryForm(t *testing.T) {
	t.Parallel()
	for _, f := range forms() {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			runSession(t, f.form)
		})
	}
}

type namedForm struct {
	name string
	form collector.Form
}

// forms are the collector's forms: each of the four inputs present or not,
// and serving after its completion or not.
func forms() []namedForm {
	var out []namedForm
	for i := 0; i < 32; i++ {
		var f collector.Form
		var name []string
		if i&1 != 0 {
			f.Token = "sess"
			name = append(name, "token")
		}
		if i&2 != 0 {
			f.Script = []byte("#!/bin/sh\nmake\n")
			name = append(name, "script")
		}
		if i&4 != 0 {
			f.Context = map[string][]byte{"Makefile": []byte("all:\n"), ".warden/x.txt": []byte("x"), "src/a.c": []byte("int a;\n")}
			name = append(name, "context")
		}
		if i&8 != 0 {
			f.Bootstrap = []byte(`{"version": 1, "trust": {"mode": "exclusive"}}`)
			name = append(name, "bootstrap")
		}
		if i&16 != 0 {
			f.ServesAfterCompletion = true
			name = append(name, "serves-after")
		}
		if len(name) == 0 {
			name = []string{"bare"}
		}
		out = append(out, namedForm{strings.Join(name, "+"), f})
	}
	return out
}

func runSession(t *testing.T, f collector.Form) {
	s := newStandIn(t, "")
	coll := collector.New(f, nil)
	c := Claimant{Net: loopback, Endpoint: s.endpoint()}
	env := []byte(`{"type":"oci-image/v1","schemaVersion":2}`)
	tun, rep, err := c.Session(ctx(t), coll, Config{CollectorToken: f.Token, Environment: &Environment{Payload: env, Metadata: []byte{0xa0}}})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if rep.Status != http.StatusOK {
		t.Fatalf("claim: %d %s", rep.Status, rep.Body)
	}
	req := func(method, path string, body io.Reader) *http.Request {
		r, err := http.NewRequest(method, TunnelURL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if f.Token != "" {
			r.Header.Set("Authorization", "Bearer "+f.Token)
		}
		return r
	}
	expect := func(r *http.Request, status int, body []byte) http.Header {
		t.Helper()
		resp, b, err := s.send(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL.Path, err)
		}
		if resp.StatusCode != status || (body != nil && !bytes.Equal(b, body)) {
			t.Errorf("%s %s: %d %q, want %d %q", r.Method, r.URL.Path, resp.StatusCode, b, status, body)
		}
		return resp.Header
	}
	ok := func(have bool) int {
		if have {
			return http.StatusOK
		}
		return http.StatusNotFound
	}

	expect(req(http.MethodPut, "/v1/artifacts/out/app.bin", strings.NewReader("built")), 200, []byte{})
	cr := req(http.MethodPut, "/v1/captures/0001-GET-origin.example/pkg", io.NopCloser(strings.NewReader("payload")))
	sum := blake2b.Sum256([]byte("payload"))
	cr.Trailer = http.Header{"Warden-Hash": {hex.EncodeToString(sum[:])}}
	cr.ContentLength = -1
	expect(cr, 200, []byte{})
	expect(req(http.MethodPost, "/v1/output", strings.NewReader("one ")), 200, nil)
	expect(req(http.MethodPost, "/v1/output", strings.NewReader("two")), 200, nil)
	expect(req(http.MethodGet, "/v1/build-script", nil), ok(f.Script != nil), nil)
	h := expect(req(http.MethodGet, "/v1/bootstrap", nil), ok(f.Bootstrap != nil), f.Bootstrap)
	if f.Bootstrap != nil && h.Get("Content-Type") != "application/json" {
		t.Errorf("bootstrap Content-Type %q", h.Get("Content-Type"))
	}
	if f.Context != nil {
		h := expect(req(http.MethodGet, "/v1/context/", nil), 200, []byte(".warden/x.txt\nMakefile\nsrc/a.c\n"))
		if h.Get("Warden-Context") != "list" {
			t.Errorf("listing: Warden-Context %q", h.Get("Warden-Context"))
		}
		h = expect(req(http.MethodGet, "/v1/context/src/a.c", nil), 200, []byte("int a;\n"))
		if h.Get("Warden-Context") != "file" {
			t.Errorf("file: Warden-Context %q", h.Get("Warden-Context"))
		}
	} else {
		expect(req(http.MethodGet, "/v1/context/", nil), 404, nil)
	}
	expect(req(http.MethodPost, "/v1/heartbeat", nil), 200, nil)
	if err := s.endLedger([]byte("records")); err != nil {
		t.Fatal(err)
	}
	expect(req(http.MethodPost, "/v1/complete", strings.NewReader(`{"exit_code": 3, "message": "", "error": ""}`)), 200, nil)

	if f.ServesAfterCompletion {
		expect(req(http.MethodPost, "/v1/complete", strings.NewReader(`{"exit_code": 0, "message": "", "error": ""}`)), 200, nil)
		expect(req(http.MethodGet, "/v1/status", nil), 200, nil)
	} else {
		select {
		case <-tun.Closed():
		case <-time.After(10 * time.Second):
			t.Fatal("the tunnel was not closed at the completion")
		}
		if _, _, err := s.send(req(http.MethodPost, "/v1/heartbeat", nil)); err == nil {
			t.Error("a request after the completion was answered")
		}
	}

	if comp, _ := coll.Completion(); comp.ExitCode != 3 {
		t.Errorf("the result is exit code %d, want the first completion's 3", comp.ExitCode)
	}
	ledger, n, ended := coll.Ledger()
	if string(ledger) != "BLDL\x01records" || n != 1 || !ended {
		t.Errorf("ledger %q, %d requests, ended %v", ledger, n, ended)
	}
	if p, n := coll.Environment(); !bytes.Equal(p, env) || n != 1 {
		t.Errorf("environment %q, %d requests", p, n)
	}
	if a := coll.Artifacts(); string(a["out/app.bin"]) != "built" || len(a) != 1 {
		t.Errorf("artifacts %v", a)
	}
	caps := coll.Captures()
	if len(caps) != 1 || caps[0].Name != "0001-GET-origin.example_pkg" || caps[0].Hash != caps[0].BodyHash || string(caps[0].Body) != "payload" {
		t.Errorf("captures %+v", caps)
	}
	if string(coll.Output()) != "one two" {
		t.Errorf("output %q", coll.Output())
	}
	// The ledger request ended before the completion began. (Which of the
	// stand-in's first requests arrived first is the stand-in's, which
	// sends them on streams of their own.)
	var ledgerEnd, completeBegin int
	for _, r := range coll.Requests() {
		switch {
		case r.Path == "/v1/ledger":
			ledgerEnd = r.End
		case r.Path == "/v1/complete" && completeBegin == 0:
			completeBegin = r.Begin
		}
	}
	if ledgerEnd == 0 || completeBegin < ledgerEnd {
		t.Errorf("the ledger ended at %d and the completion began at %d", ledgerEnd, completeBegin)
	}
}
