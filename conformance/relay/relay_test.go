package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The tests run the relay against the harness's claimant and collector, on
// the in-memory network: the relay's claim endpoint at relayAddr, the
// claimant at claimantAddr, and the upstream world in the documentation
// ranges.

var (
	relayAddr     = netip.MustParseAddr("198.18.0.1")
	claimantAddr  = netip.MustParseAddr("198.18.0.2")
	upstreamAddr  = netip.MustParseAddr("203.0.113.1")
	resolverAddr  = netip.MustParseAddr("192.0.2.53")
	collectorAddr = netip.MustParseAddr("192.0.2.10")
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	t  *testing.T
	n  *memnet.Net
	r  *Relay
	cl claimant.Claimant
}

// newRelay starts a relay on a fresh segment with cfg, its claim side and
// upstream filled in when cfg leaves them empty.
func newRelay(t *testing.T, cfg Config) *fixture {
	t.Helper()
	n := memnet.New()
	if cfg.Net == nil {
		cfg.Net = n.Host(relayAddr)
	}
	if cfg.Upstream == nil {
		cfg.Upstream = n.Host(upstreamAddr)
	}
	r, err := Start(ctx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	return &fixture{t: t, n: n, r: r, cl: claimant.Claimant{Net: n.Host(claimantAddr), Endpoint: r.Claim()}}
}

var envPayload = []byte(`{"type":"oci-image/v1","schemaVersion":2,"layers":[]}`)

func upDNS() []string { return []string{resolverAddr.String()} }

func boolp(b bool) *bool { return &b }

// forms are the collector's forms: each of its four inputs present or not,
// and serving after its completion or not.
func forms() map[string]collector.Form {
	out := map[string]collector.Form{}
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
			f.Context = map[string][]byte{"Makefile": []byte("all:\n"), "src/a.c": []byte("int a;\n")}
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
		out[strings.Join(name, "+")] = f
	}
	return out
}

var (
	getReq = Request{Method: "GET", URL: "https://origin.example/pkg.tar", Protocol: "HTTP/1.1",
		Header: []byte("GET /pkg.tar HTTP/1.1\r\nHost: origin.example\r\nAuthorization: Bearer x\r\nX-Trace: 7\r\n\r\n")}
	respHeader = []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	postReq    = Request{Method: "POST", URL: "http://origin.example/form", Protocol: "HTTP/1.1",
		Header: []byte("POST /form HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 6\r\n\r\n")}
	artReq = Request{Method: "POST", URL: "http://artifacts/out/app.bin", Protocol: "HTTP/1.1",
		Header: []byte("POST /out/app.bin HTTP/1.1\r\nHost: artifacts\r\n\r\n")}
)

func TestSessionInEveryForm(t *testing.T) {
	t.Parallel()
	for name, f := range forms() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runSession(t, f)
		})
	}
}

func runSession(t *testing.T, f collector.Form) {
	fx := newRelay(t, Config{Token: "claim-tok"})
	coll := collector.New(f, nil)
	tun, rep, err := fx.cl.Session(ctx(t), coll, claimant.Config{
		CollectorToken: f.Token, CaptureMode: CaptureAll, UpstreamDNS: upDNS(),
		Environment: &claimant.Environment{Type: "oci-image/v1", Payload: envPayload, Metadata: []byte{0xa1, 0x61, 'k', 0x01}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	// What the collector had when the claim's 200 arrived: the ledger
	// request first, the environment, and ready (CLAIM-44).
	atReply := coll.Requests()
	_, ca, key, err := rep.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("the CA certificate is not a CA's: %+v", ca)
	}
	if len(atReply) < 3 || atReply[0].Path != "/v1/ledger" {
		t.Fatalf("the collector's first requests: %v", paths(atReply))
	}
	if i := index(atReply, "/v1/environment"); i < 1 || atReply[i].Status != 200 {
		t.Errorf("the environment was not landed before the reply: %v", paths(atReply))
	}
	if i := index(atReply, "/v1/ready"); i < 0 || atReply[i].End == 0 {
		t.Errorf("ready was not answered before the reply: %v", paths(atReply))
	}
	for _, r := range atReply {
		if got := r.Header.Get("Authorization"); (f.Token == "") != (got == "") || f.Token != "" && got != "Bearer "+f.Token {
			t.Errorf("%s carried Authorization %q", r.Path, got)
		}
		if r.Proto != "HTTP/2.0" {
			t.Errorf("%s came over %s", r.Path, r.Proto)
		}
	}

	s, err := fx.r.Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.PublicKey(), key) {
		t.Error("the reply's key is not the session's")
	}
	c := ctx(t)
	if _, err := s.Exchange(c, Exchange{Request: getReq, Status: 200, ResponseHeader: respHeader, ResponseBody: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(c, Exchange{Request: postReq, Body: []byte("form=1"), Status: 200, ResponseHeader: respHeader, ResponseBody: []byte("thank")}); err != nil {
		t.Fatal(err)
	}
	if rep, n, err := s.Artifact(c, artReq, "out/app.bin", strings.NewReader("built")); err != nil || rep.Status != 200 || n != 5 {
		t.Fatalf("artifact: %v %v %d", rep, err, n)
	}
	for _, p := range []string{"one ", "two"} {
		if rep, err := s.Output(c, []byte(p)); err != nil || rep.Status != 200 {
			t.Fatalf("output: %v %v", rep, err)
		}
	}
	if in := s.BuildScript(c); in.OK() != (f.Script != nil) || in.OK() && !bytes.Equal(in.Reply.Body, f.Script) {
		t.Errorf("build script: %+v", in)
	}
	if in := s.Bootstrap(c); in.OK() != (f.Bootstrap != nil) || in.OK() && !bytes.Equal(in.Reply.Body, f.Bootstrap) {
		t.Errorf("bootstrap: %+v", in)
	}
	list := s.Context(c, "")
	file := s.Context(c, "src/a.c")
	if f.Context != nil {
		if !list.OK() || !list.List || string(list.Reply.Body) != "Makefile\nsrc/a.c\n" {
			t.Errorf("the context's root: %+v", list)
		}
		if !file.OK() || file.List || string(file.Reply.Body) != "int a;\n" {
			t.Errorf("a context file: %+v", file)
		}
	} else if list.OK() || file.OK() || list.Reply.Status != 404 {
		t.Errorf("a session with no context: %+v %+v", list, file)
	}
	if _, err := s.Complete(c, Completion{ExitCode: 3}); err != nil && f.ServesAfterCompletion {
		t.Fatal(err)
	}
	if _, err := s.Output(c, []byte("late")); !errors.Is(err, ErrCompleted) {
		t.Errorf("an output after the completion: %v", err)
	}
	if f.ServesAfterCompletion {
		if rep, err := s.Complete(c, Completion{ExitCode: 0}); err != nil || rep.Status != 200 {
			t.Errorf("a second completion: %v %v", rep, err)
		}
	}
	if comp, ok := coll.Completion(); !ok || comp.ExitCode != 3 {
		t.Errorf("the result is %+v, want exit code 3", comp)
	}

	data, n, ended := coll.Ledger()
	if n != 1 || !ended {
		t.Errorf("%d ledger requests, ended %v", n, ended)
	}
	l, err := ledger.Verify(data, key)
	if err != nil {
		t.Fatal(err)
	}
	if l.Truncated != 0 || len(l.Unclosed) != 0 {
		t.Errorf("the ledger is cut by %d bytes, with channels %v open", l.Truncated, l.Unclosed)
	}
	env, ok := l.Environment()
	stored, envs := coll.Environment()
	if !ok || envs != 1 || !bytes.Equal(stored, envPayload) {
		t.Fatalf("environment record %v, %d requests", ok, envs)
	}
	if err := l.CheckPayload(env, stored); err != nil {
		t.Error(err)
	}
	// The GET's response body, the POST's request body, and the artifact.
	checkBody(t, l, 5, "hello")
	checkBody(t, l, 8, "form=1")
	checkBody(t, l, 10, "thank")
	checkBody(t, l, 13, "built")
	if l.Records[13].Type != ledger.Artifact {
		t.Errorf("record 13 is %s", l.Records[13].Type)
	}
	if name, _ := l.Records[13].Text("name"); name != "out/app.bin" {
		t.Errorf("the artifact record names %q", name)
	}
	if hs := l.Records[3].Metadata["headers"]; fmt.Sprint(hs) != "[[Authorization <redacted>] [X-Trace 7]]" {
		t.Errorf("the request's header metadata is %v", hs)
	}
	// Each capture's hash is its body's, and the response body's is the
	// ledger's record of it.
	caps := coll.Captures()
	if len(caps) != 7 {
		t.Errorf("%d captures, want 7", len(caps))
	}
	for _, cp := range caps {
		if cp.Hash != cp.BodyHash {
			t.Errorf("capture %s: hash %s of a body whose hash is %s", cp.Name, cp.Hash, cp.BodyHash)
		}
		if cp.Name == "000001-GET-response-body" && cp.Hash != l.PrimaryHash(l.Records[5]) {
			t.Errorf("the response body's capture is %s, the ledger's record %s", cp.Hash, l.PrimaryHash(l.Records[5]))
		}
	}
	if a := coll.Artifacts(); string(a["out/app.bin"]) != "built" {
		t.Errorf("artifacts %v", a)
	}
	if string(coll.Output()) != "one two" {
		t.Errorf("output %q", coll.Output())
	}
	// The ledger request and every output ended before the completion
	// began (COLLOUT-29, COLLIN-35).
	reqs := coll.Requests()
	complete := reqs[index(reqs, "/v1/complete")]
	for _, r := range reqs {
		if r.Path != "/v1/complete" && r.Path != "/v1/heartbeat" && r.End > complete.Begin {
			t.Errorf("%s ended at %d, after the completion began at %d", r.Path, r.End, complete.Begin)
		}
	}
	// A ledger broken in one byte no longer verifies.
	broken := bytes.Clone(data)
	broken[len(broken)/2] ^= 0x40
	if _, err := ledger.Verify(broken, key); err == nil {
		t.Error("a broken ledger verified")
	}
}

func checkBody(t *testing.T, l *ledger.Ledger, i int, body string) {
	t.Helper()
	if i >= len(l.Records) {
		t.Fatalf("the ledger has %d records", len(l.Records))
	}
	if err := l.CheckPayload(l.Records[i], []byte(body)); err != nil {
		t.Error(err)
	}
}

func paths(rs []collector.Request) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

func index(rs []collector.Request, path string) int {
	return slices.IndexFunc(rs, func(r collector.Request) bool { return r.Path == path })
}

// opened opens a tunnel to fx's relay serving coll.
func opened(t *testing.T, fx *fixture, coll *collector.Collector) *claimant.Tunnel {
	t.Helper()
	tun, err := fx.cl.OpenTunnelFor(ctx(t), coll)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return tun
}

func expect(t *testing.T, rep *claimant.Reply, err error, status int, prefix string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != status || !strings.HasPrefix(string(rep.Body), prefix) {
		t.Errorf("got %d %q, want %d %q...", rep.Status, rep.Body, status, prefix)
	}
	if status != 200 && status != 101 {
		if ct := rep.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("a refusal's Content-Type is %q", ct)
		}
		if strings.Count(strings.TrimSuffix(string(rep.Body), "\n"), "\n") != 0 {
			t.Errorf("a refusal's reason is not one line: %q", rep.Body)
		}
	}
}

func TestAuthorizationAndMethods(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{Token: "tok"})
	c := ctx(t)
	do := func(method, path, auth string) (*claimant.Reply, error) {
		h := http.Header{}
		if auth != "" {
			h.Set("Authorization", auth)
		}
		return fx.cl.Do(c, method, path, h, nil)
	}
	for _, p := range []string{"/v1/tunnel", "/v1/claim"} {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rep, err := do(m, p, "")
			expect(t, rep, err, 405, "POST only")
		}
		for _, a := range []string{"", "bearer tok", "Bearertok", "Bearer  tok", "Bearer tok2", "tok"} {
			rep, err := do(http.MethodPost, p, a)
			expect(t, rep, err, 401, "unauthorized")
		}
	}
	rep, err := do(http.MethodPost, "/v1/other", "Bearer tok")
	expect(t, rep, err, 404, "")
	// The 401s consumed nothing (CLAIM-7).
	coll := collector.New(collector.Form{}, nil)
	opened(t, fx, coll)
	rep, err = fx.cl.Claim(c, claimant.Config{CollectorURL: claimant.TunnelURL, UpstreamDNS: upDNS()})
	expect(t, rep, err, 200, "{")
}

func TestNoTokenAcceptsAnyAuthorization(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	c := ctx(t)
	rep, err := fx.cl.Do(c, http.MethodPost, "/v1/claim", http.Header{"Authorization": {"Basic eDp5"}}, []byte(`{"collector_url": "http://collector.tunnel"}`))
	expect(t, rep, err, 400, "invalid claim: collector_url selects the tunnel, but none is open")
}

func TestRefusedClaimsLeaveTheRelayClaimable(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{Token: "tok", ResolvConf: []netip.Addr{netip.MustParseAddr("127.0.0.1"), relayAddr}})
	c := ctx(t)
	rep, err := fx.cl.ClaimBody(c, []byte(`{"collector_url":"http://collector.tunnel","upstream_dns":["192.0.2.53"]}`))
	expect(t, rep, err, 400, "invalid claim: collector_url selects the tunnel, but none is open")
	coll := collector.New(collector.Form{}, nil)
	tun := opened(t, fx, coll)
	rep, err = fx.cl.Do(c, http.MethodPost, "/v1/tunnel", http.Header{"Authorization": {"Bearer tok"}, "Connection": {"Upgrade"}, "Upgrade": {"warden-tunnel"}}, nil)
	expect(t, rep, err, 409, "tunnel already open")

	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	env := `"environment":{"payload":"` + b64(envPayload) + `","metadata":"oA=="}`
	tu := `"collector_url":"http://collector.tunnel"`
	link := func(prefix, relay, guest string) string {
		return `{` + tu + `,"upstream_dns":["192.0.2.53"],"build_link":{"prefix":"` + prefix + `","relay":"` + relay + `","guest":"` + guest + `"}}`
	}
	dnsList := func(list string) string { return `{` + tu + `,"upstream_dns":` + list + `}` }
	big := `{` + tu + `,"upstream_dns":["192.0.2.53"],"collector_token":"` + strings.Repeat("x", MaxClaim) + `"}`
	cases := []struct{ body, want string }{
		{`not json`, "invalid claim: "},
		{`[1]`, "invalid claim: not a JSON object"},
		{`{` + tu + `,"x":1}`, `invalid claim: unknown field "x"`},
		{`{"COLLECTOR_URL":"http://collector.tunnel"}`, "invalid claim: "},
		{`{` + tu + `,"collector_token":null}`, "invalid claim: "},
		{`{` + tu + `,` + tu + `}`, "invalid claim: "},
		{`{` + tu + `}{}`, "invalid claim: "},
		{`{` + tu + `} x`, "invalid claim: "},
		{`{"collector_url":1}`, "invalid claim: "},
		{`{` + tu + `,"upstream_system_ca":"no"}`, "invalid claim: "},
		{`{` + tu + `,"upstream_ca_certs":[1]}`, "invalid claim: "},
		{`{` + tu + `,"upstream_ca_certs":[null]}`, "invalid claim: "},
		{`{` + tu + `,"upstream_ca_certs":["no certificate"]}`, "invalid claim: "},
		{`{` + tu + `,"environment":"x"}`, "invalid claim: "},
		{`{` + tu + `,"environment":{"payload":"e30","metadata":"oA=="}}`, "invalid claim: "},
		{`{` + tu + `,"environment":{"payload":"e3\n0=","metadata":"oA=="}}`, "invalid claim: "},
		{`{` + tu + `,"environment":{"payload":"e30=","metadata":"oA==","extra":1}}`, `invalid claim: environment: unknown field "extra"`},
		{`{` + tu + `,"build_link":1}`, "invalid claim: "},
		{`{"collector_url":""}`, "invalid claim: collector_url is required"},
		{`{"collector_token":"x"}`, "invalid claim: collector_url is required"},
		{`{` + tu + `,"capture_mode":"everything"}`, "invalid claim: "},
		{link("2001:db8::/64", "2001:db8::1", "2001:db8::2"), "invalid claim: build_link: "},
		{link("192.0.2.1/30", "192.0.2.1", "192.0.2.2"), "invalid claim: build_link: "},
		{link("192.0.2.0/31", "192.0.2.0", "192.0.2.1"), "invalid claim: build_link: "},
		{link("10.0.0.0/7", "10.0.0.1", "10.0.0.2"), "invalid claim: build_link: "},
		{link("192.0.2.0/30", "192.0.2.5", "192.0.2.2"), "invalid claim: build_link: "},
		{link("192.0.2.0/30", "192.0.2.0", "192.0.2.2"), "invalid claim: build_link: "},
		{link("192.0.2.0/30", "192.0.2.1", "192.0.2.3"), "invalid claim: build_link: "},
		{link("192.0.2.0/30", "192.0.2.1", "192.0.2.1"), "invalid claim: build_link: "},
		{link("127.0.0.0/30", "127.0.0.1", "127.0.0.2"), "invalid claim: build_link: "},
		{link("169.254.0.0/30", "169.254.0.1", "169.254.0.2"), "invalid claim: build_link: "},
		{link("224.0.0.0/30", "224.0.0.1", "224.0.0.2"), "invalid claim: build_link: "},
		{link("240.0.0.0/30", "240.0.0.1", "240.0.0.2"), "invalid claim: build_link: "},
		{link("0.0.0.0/30", "0.0.0.1", "0.0.0.2"), "invalid claim: build_link: "},
		{`{` + tu + `,"build_link":{"prefix":"192.0.2.0/30","relay":"192.0.2.1"}}`, "invalid claim: build_link: "},
		{dnsList(`[]`), "invalid claim: upstream_dns: "},
		{dnsList(`["192.0.2.53:53"]`), "invalid claim: upstream_dns: "},
		{dnsList(`["2001:db8::53"]`), "invalid claim: upstream_dns: "},
		{dnsList(`["0.0.0.0"]`), "invalid claim: upstream_dns: "},
		{dnsList(`["224.0.0.1"]`), "invalid claim: upstream_dns: "},
		{dnsList(`["255.255.255.255"]`), "invalid claim: upstream_dns: "},
		{dnsList(`"192.0.2.53"`), "invalid claim: "},
		{`{` + tu + `,"upstream_dns":["192.0.2.2"],"build_link":{"prefix":"192.0.2.0/30","relay":"192.0.2.1","guest":"192.0.2.2"}}`, "invalid claim: upstream_dns: "},
		// The resolver configuration names only 127.0.0.1 and the relay's
		// own address (CLAIM-32).
		{`{` + tu + `}`, "claim refused: upstream_dns is absent"},
		{`{` + tu + `,` + env + `}`, "claim refused: upstream_dns"},
		{big, "invalid claim: the body is over"},
	}
	for _, tc := range cases {
		rep, err := fx.cl.ClaimBody(c, []byte(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Status != 400 || !strings.HasPrefix(string(rep.Body), tc.want) {
			b := tc.body
			if len(b) > 120 {
				b = b[:120]
			}
			t.Errorf("%s: got %d %q, want 400 %q...", b, rep.Status, rep.Body, tc.want)
		}
	}
	select {
	case <-tun.Closed():
		t.Fatal("a refused claim closed the tunnel")
	default:
	}
	// Still claimable, on the tunnel that was open (CLAIM-16, CLAIM-48).
	rep, err = fx.cl.ClaimBody(c, []byte(`{`+tu+`,"upstream_dns":["192.0.2.53"],`+env+`,"capture_mode":"","upstream_ca_certs":["`+strings.ReplaceAll(string(testCA(t)), "\n", `\n`)+`"],"upstream_system_ca":false}`))
	expect(t, rep, err, 200, "{")
	s, err := fx.r.Session(c)
	if err != nil {
		t.Fatal(err)
	}
	if cl := s.Claim(); cl.CaptureMode != CaptureNone || cl.SystemRoots || len(cl.Roots) != 1 {
		t.Errorf("the claim was read as %+v", cl)
	}
	// The endpoint no longer accepts connections (CLAIM-47).
	if _, err := fx.cl.Net.Dial(c, "tcp", fx.r.Claim().Address); err == nil {
		t.Error("the claim endpoint accepted a connection after the 200")
	}
	if _, err := s.Complete(c, Completion{}); err != nil {
		t.Log(err)
	}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	ca, err := newCA()
	if err != nil {
		t.Fatal(err)
	}
	return ca.PEM
}

func TestTunnelNeedsItsUpgrade(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	rep, err := fx.cl.Do(ctx(t), http.MethodPost, "/v1/tunnel", nil, nil)
	expect(t, rep, err, 400, "the tunnel needs")
	// The refusal did not use the relay's one tunnel.
	opened(t, fx, collector.New(collector.Form{}, nil))
}

// TestClaimBeingProcessed holds a claim's body unfinished: meanwhile every
// other claim and every tunnel is 409 (CLAIM-15, CLAIM-46), and the claim is
// released once its connection closes.
func TestClaimBeingProcessed(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	c := ctx(t)
	conn, err := fx.cl.Net.Dial(c, "tcp", fx.r.Claim().Address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /v1/claim HTTP/1.1\r\nHost: relay\r\nContent-Length: 100\r\n\r\n{\"coll"); err != nil {
		t.Fatal(err)
	}
	// A probe that is refused 400 while no claim is being processed.
	probe := func(until int) *claimant.Reply {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			rep, err := fx.cl.ClaimBody(c, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Status == until || time.Now().After(deadline) {
				return rep
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// The probe waits for the relay to be processing the claim on conn: a
	// probe sent before it would be processed first, and conn's claim be
	// the one refused.
	for deadline := time.Now().Add(10 * time.Second); ; {
		fx.r.mu.Lock()
		processing := fx.r.processing
		fx.r.mu.Unlock()
		if processing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay did not start processing the claim")
		}
		time.Sleep(5 * time.Millisecond)
	}
	expect(t, probe(409), nil, 409, "already claimed")
	rep, err := fx.cl.Do(c, http.MethodPost, "/v1/tunnel", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"warden-tunnel"}}, nil)
	expect(t, rep, err, 409, "tunnel already open")
	_ = conn.Close()
	expect(t, probe(400), nil, 400, "invalid claim: collector_url is required")
	opened(t, fx, collector.New(collector.Form{}, nil))
	rep, err = fx.cl.ClaimBody(c, []byte(`{"collector_url":"http://collector.tunnel","upstream_dns":["192.0.2.53"]}`))
	expect(t, rep, err, 200, "{")
}

// TestFailedStartsSpendTheRelay: an environment that cannot be used, a
// collector that refuses it, and a collector_url that cannot be reached are
// each answered 500, after which the relay accepts nothing (CLAIM-50).
func TestFailedStartsSpendTheRelay(t *testing.T) {
	t.Parallel()
	env := func(typ string, payload, meta []byte) *claimant.Environment {
		return &claimant.Environment{Type: typ, Payload: payload, Metadata: meta}
	}
	m := []byte{0xa0}
	cases := map[string]struct {
		cfg   claimant.Config
		fault collector.Fault
	}{
		"an empty payload":            {cfg: claimant.Config{Environment: env("", []byte{}, m)}},
		"a payload over 1 MiB":        {cfg: claimant.Config{Environment: env("", append([]byte(`{"type":"x","pad":"`), append(bytes.Repeat([]byte("a"), EnvironmentLimit), '"', '}')...), m)}},
		"a payload that is no object": {cfg: claimant.Config{Environment: env("", []byte(`[1]`), m)}},
		"a payload with no type":      {cfg: claimant.Config{Environment: env("", []byte(`{"schemaVersion":2}`), m)}},
		"an empty type":               {cfg: claimant.Config{Environment: env("", []byte(`{"type":""}`), m)}},
		"another type":                {cfg: claimant.Config{Environment: env("vm-disk-chain/v1", envPayload, m)}},
		"metadata that is an array":   {cfg: claimant.Config{Environment: env("", envPayload, []byte{0x80})}},
		"metadata that is null":       {cfg: claimant.Config{Environment: env("", envPayload, []byte{0xf6})}},
		"metadata with more after":    {cfg: claimant.Config{Environment: env("", envPayload, []byte{0xa0, 0xa0})}},
		"no metadata":                 {cfg: claimant.Config{Environment: env("", envPayload, []byte{})}},
		"a refused environment": {cfg: claimant.Config{Environment: env("", envPayload, m)}, fault: func(r *http.Request) int {
			if r.URL.Path == "/v1/environment" {
				return 507
			}
			return 0
		}},
		"an unreachable collector": {cfg: claimant.Config{CollectorURL: "http://" + collectorAddr.String()}},
		"a collector_url of ftp":   {cfg: claimant.Config{CollectorURL: "ftp://collector.example/"}},
		"an unresolvable name":     {cfg: claimant.Config{CollectorURL: "http://collector.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newRelay(t, Config{})
			c := ctx(t)
			coll := collector.New(collector.Form{}, tc.fault)
			cfg := tc.cfg
			cfg.UpstreamDNS = upDNS()
			var rep *claimant.Reply
			var err error
			if cfg.CollectorURL == "" {
				var tun *claimant.Tunnel
				tun, rep, err = fx.cl.Session(c, coll, cfg)
				if tun != nil {
					defer tun.Close()
				}
			} else {
				rep, err = fx.cl.Claim(c, cfg)
			}
			expect(t, rep, err, 500, "relay start failed: ")
			select {
			case <-fx.r.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the relay did not end")
			}
			if _, err := fx.cl.Net.Dial(c, "tcp", fx.r.Claim().Address); err == nil {
				t.Error("a spent relay accepted a connection")
			}
		})
	}
}

// TestRefusedLedgerAndReady: a collector that refuses the ledger stream or
// ready still sees the claim answered 200 (CLAIM-23, CLAIM-44).
func TestRefusedLedgerAndReady(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1/ledger", "/v1/ready"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			fx := newRelay(t, Config{})
			coll := collector.New(collector.Form{ServesAfterCompletion: true}, func(r *http.Request) int {
				if r.URL.Path == path {
					return 401
				}
				return 0
			})
			tun, rep, err := fx.cl.Session(ctx(t), coll, claimant.Config{UpstreamDNS: upDNS()})
			expect(t, rep, err, 200, "{")
			defer tun.Close()
			s, err := fx.r.Session(ctx(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Complete(ctx(t), Completion{ExitCode: 1}); err != nil {
				t.Fatal(err)
			}
			if lr, done, err := s.LedgerReply(); !done || err != nil || (path == "/v1/ledger") != (lr.Status == 401) {
				t.Errorf("the ledger's reply: %+v %v %v", lr, done, err)
			}
			if comp, ok := coll.Completion(); !ok || comp.ExitCode != 1 {
				t.Errorf("completion %+v %v", comp, ok)
			}
		})
	}
}

// TestCollectorAtABaseURL: a collector_url that is not the tunnel is
// requested by the relay itself, its name resolved through the resolvers
// left of its resolver configuration (CLAIM-23, CLAIM-32), and a redirect
// is not followed.
func TestCollectorAtABaseURL(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{Token: "tok", ResolvConf: []netip.Addr{netip.MustParseAddr("127.0.0.1"), relayAddr, resolverAddr}})
	c := ctx(t)
	res, err := upstream.StartResolver(c, fx.n.Host(resolverAddr), resolverAddr, map[string][]netip.Addr{"collector.example": {collectorAddr}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Close() })
	coll := collector.New(collector.Form{Token: "sess", Script: []byte("s"), ServesAfterCompletion: true}, func(r *http.Request) int {
		if r.URL.Path == "/v1/build-script" {
			return http.StatusTemporaryRedirect
		}
		return 0
	})
	ln, err := fx.n.Host(collectorAddr).Listen(c, "tcp", collectorAddr.String()+":80")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coll.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	rep, err := fx.cl.Claim(c, claimant.Config{CollectorURL: "http://collector.example/", CollectorToken: "sess"})
	expect(t, rep, err, 200, "{")
	s, err := fx.r.Session(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Claim().Resolvers; !slices.Equal(got, []netip.Addr{resolverAddr}) {
		t.Errorf("resolvers %v", got)
	}
	if in := s.BuildScript(c); in.OK() || in.Reply == nil || in.Reply.Status != http.StatusTemporaryRedirect {
		t.Errorf("a redirected input: %+v", in)
	}
	if _, err := s.Output(c, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Complete(c, Completion{}); err != nil {
		t.Fatal(err)
	}
	reqs := coll.Requests()
	if reqs[0].Path != "/v1/ledger" {
		t.Errorf("requests %v", paths(reqs))
	}
	for _, r := range reqs {
		if r.Proto != "HTTP/1.1" || strings.Contains(r.Path, "//") || r.Header.Get("Authorization") != "Bearer sess" {
			t.Errorf("%s %s over %s with %q", r.Method, r.Path, r.Proto, r.Header.Get("Authorization"))
		}
	}
	data, _, _ := coll.Ledger()
	if _, err := ledger.Verify(data, s.PublicKey()); err != nil {
		t.Error(err)
	}
	if q := res.Queries(); len(q) == 0 {
		t.Error("the resolver was not asked")
	}
}

// TestHeartbeat: no heartbeat before the build's first activity, beats while
// it is recent, and none once it is older than 4 s (COLLIN-30).
func TestHeartbeat(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	coll := collector.New(collector.Form{}, nil)
	tun, rep, err := fx.cl.Session(ctx(t), coll, claimant.Config{UpstreamDNS: upDNS()})
	expect(t, rep, err, 200, "{")
	defer tun.Close()
	s, err := fx.r.Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	beats := func() int {
		n := 0
		for _, r := range coll.Requests() {
			if r.Path == "/v1/heartbeat" {
				n++
			}
		}
		return n
	}
	time.Sleep(HeartbeatEvery + 500*time.Millisecond)
	if n := beats(); n != 0 {
		t.Errorf("%d heartbeats before any activity", n)
	}
	s.Activity()
	time.Sleep(HeartbeatActive + HeartbeatEvery + 500*time.Millisecond)
	n := beats()
	if n < 1 || n > 3 {
		t.Errorf("%d heartbeats for one activity", n)
	}
	time.Sleep(HeartbeatEvery + 500*time.Millisecond)
	if m := beats(); m != n {
		t.Errorf("%d heartbeats after the activity grew old, %d before", m, n)
	}
	if s.Heartbeats() != n {
		t.Errorf("the session counts %d heartbeats, the collector %d", s.Heartbeats(), n)
	}
}

// blocking is a body that gives its bytes only once released.
type blocking struct {
	release chan struct{}
	r       io.Reader
}

func (b *blocking) Read(p []byte) (int, error) {
	<-b.release
	return b.r.Read(p)
}

// TestCompleteWaitsForOutputs: an artifact still streaming when the build
// completes is answered before the completion is sent, and a refused one
// leaves no open channel.
func TestCompleteWaitsForOutputs(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	coll := collector.New(collector.Form{ServesAfterCompletion: true}, func(r *http.Request) int {
		if r.URL.Path == "/v1/artifacts/refused" {
			return 500
		}
		return 0
	})
	tun, rep, err := fx.cl.Session(ctx(t), coll, claimant.Config{UpstreamDNS: upDNS()})
	expect(t, rep, err, 200, "{")
	defer tun.Close()
	s, err := fx.r.Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	c := ctx(t)
	if rep, _, err := s.Artifact(c, artReq, "refused", strings.NewReader("no")); err != nil || rep.Status != 500 {
		t.Fatalf("a refused artifact: %v %v", rep, err)
	}
	body := &blocking{release: make(chan struct{}), r: strings.NewReader("slow")}
	streamed := make(chan error, 1)
	go func() {
		_, _, err := s.Artifact(c, artReq, "slow", body)
		streamed <- err
	}()
	// Wait for the artifact's request to begin.
	for index(coll.Requests(), "/v1/artifacts/slow") < 0 {
		time.Sleep(10 * time.Millisecond)
	}
	completed := make(chan error, 1)
	go func() {
		_, err := s.Complete(c, Completion{ExitCode: 0})
		completed <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if index(coll.Requests(), "/v1/complete") >= 0 {
		t.Fatal("the completion was sent while an artifact was streaming")
	}
	close(body.release)
	if err := <-streamed; err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	reqs := coll.Requests()
	art, comp := reqs[index(reqs, "/v1/artifacts/slow")], reqs[index(reqs, "/v1/complete")]
	if art.End > comp.Begin {
		t.Errorf("the artifact ended at %d, after the completion began at %d", art.End, comp.Begin)
	}
	data, _, _ := coll.Ledger()
	l, err := ledger.Verify(data, s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Unclosed) != 0 {
		t.Errorf("channels %v left open", l.Unclosed)
	}
	var arts int
	for _, r := range l.Records {
		if r.Type == ledger.Artifact {
			arts++
		}
	}
	if arts != 1 {
		t.Errorf("%d artifact records, want 1 (the refused one is not recorded as stored)", arts)
	}
	if got := coll.Artifacts(); string(got["slow"]) != "slow" || len(got) != 1 {
		t.Errorf("artifacts %v", got)
	}
}

func TestNamesARelayMayNotSend(t *testing.T) {
	t.Parallel()
	fx := newRelay(t, Config{})
	coll := collector.New(collector.Form{Context: map[string][]byte{"a": []byte("a")}, ServesAfterCompletion: true}, nil)
	tun, rep, err := fx.cl.Session(ctx(t), coll, claimant.Config{UpstreamDNS: upDNS()})
	expect(t, rep, err, 200, "{")
	defer tun.Close()
	s, err := fx.r.Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	c := ctx(t)
	for _, p := range []string{"a//b", "../a", "a/./b", "/a"} {
		if in := s.Context(c, p); in.Err == nil {
			t.Errorf("the context path %q was sent", p)
		}
	}
	if _, _, err := s.Artifact(c, artReq, "a/../b", strings.NewReader("x")); err == nil {
		t.Error("the artifact name a/../b was sent")
	}
	// Do sends what the caller makes, as it is.
	r, err := s.Do(c, http.MethodPut, "/v1/captures/x", nil, strings.NewReader("x"), nil)
	if err != nil || r.Status != 400 {
		t.Errorf("a capture with no trailer: %v %v", r, err)
	}
	if in := s.Context(c, "a b/"); in.Err != nil || in.Reply.Status != 403 {
		t.Errorf("an escaped context path: %+v", in)
	}
	for _, rq := range coll.Requests() {
		if strings.HasPrefix(rq.Path, "/v1/context/") && rq.Path != "/v1/context/a%20b/" {
			t.Errorf("sent %s", rq.Path)
		}
	}
}

// TestOnLoopback: a collector that claims reaches the relay at a claim
// address on loopback, as a claims collector target does.
func TestOnLoopback(t *testing.T) {
	t.Parallel()
	lo := attach.Host(netip.MustParseAddr("127.0.0.1"))
	r, err := Start(ctx(t), Config{Net: lo, Address: "127.0.0.1:0", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	if !strings.HasPrefix(r.Claim().Address, "127.0.0.1:") || r.Claim().Token != "tok" {
		t.Fatalf("the claim endpoint is %+v", r.Claim())
	}
	coll := collector.New(collector.Form{Token: "sess"}, nil)
	cl := claimant.Claimant{Net: lo, Endpoint: r.Claim()}
	tun, rep, err := cl.Session(ctx(t), coll, claimant.Config{CollectorToken: "sess", UpstreamDNS: upDNS()})
	expect(t, rep, err, 200, "{")
	defer tun.Close()
	s, err := r.Session(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Complete(ctx(t), Completion{ExitCode: 2}); err != nil {
		t.Log(err)
	}
	select {
	case <-tun.Closed():
	case <-time.After(10 * time.Second):
		t.Fatal("the collector did not end the session at its completion")
	}
	data, _, _ := coll.Ledger()
	if _, err := ledger.Verify(data, ed25519.PublicKey(s.PublicKey())); err != nil {
		t.Error(err)
	}
}
