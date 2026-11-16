package inprocess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The tests are the stage's self-test, with no case and no requirement
// cited: in each in-process configuration, every role is run against its
// counterpart through a whole build (the claim, the lease, a name resolved,
// an origin fetched over HTTP and over TLS, the inputs, an artifact, the
// console, the exit), after which the collector holds every output in
// order, the ledger verifies under the claim reply's key, and the hash of
// each body in it is the hash of the bytes the build environment received.

var (
	originAddr = netip.MustParseAddr("192.0.2.80")
	guestMAC   = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0f}
	script     = []byte("#!/bin/sh\nmake\n")
	context0   = map[string][]byte{"Makefile": []byte("all:\n"), "src/a.c": []byte("int a;\n")}
)

const originName = "origin.example"

func testCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return c
}

// world starts the upstream: one resolver at the harness's upstream
// address, the one the resolver configuration names, and one origin.
func world(t *testing.T, n attach.Network) *upstream.Upstream {
	t.Helper()
	u, err := upstream.Start(testCtx(t), n, upstream.World{
		Resolvers: []netip.Addr{UpstreamHarness},
		Origins:   []upstream.Origin{{Name: originName, Addr: originAddr}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func TestRelayInEveryMode(t *testing.T) {
	t.Parallel()
	for _, c := range Configurations("relay") {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			a, err := c.New()
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			ctx := testCtx(t)
			up := world(t, network(t, a, attach.Upstream))
			in, err := a.Start(ctx, attach.Params{})
			if err != nil {
				t.Fatal(err)
			}
			defer in.Stop()
			coll := collector.New(collector.Form{Token: "sess", Script: script, Context: context0, Bootstrap: Bootstrap}, nil)
			d := a.Declared()
			cfg := claimant.Config{
				CollectorToken: "sess", CaptureMode: relay.CaptureAll,
				UpstreamCACerts: []string{string(up.CA.PEM())}, UpstreamSystemCA: new(bool),
			}
			// vm mode takes its resolvers from its resolver configuration;
			// the others are given them in the claim.
			if d.Mode != relay.ModeVM {
				cfg.UpstreamDNS = up.DNS()
			}
			if d.BuildLink != nil {
				cfg.BuildLink = &claimant.BuildLink{Prefix: d.BuildLink.Prefix, Relay: d.BuildLink.Relay, Guest: d.BuildLink.Guest}
			}
			cl := claimant.Claimant{Net: network(t, a, attach.Claim), Endpoint: in.Claim()}
			tun, rep, err := cl.Session(ctx, coll, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer tun.Close()
			_, ca, key, err := rep.Identity()
			if err != nil {
				t.Fatal(err)
			}
			var env *buildenv.Env
			if d.Link == buildenv.Frames {
				link, err := in.Frames()
				if err != nil {
					t.Fatal(err)
				}
				env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: link, MAC: guestMAC})
				if err != nil {
					t.Fatal(err)
				}
				l, _ := env.Lease()
				if want := netip.MustParsePrefix("10.100.0.2/30"); l.Address != want || l.Server != netip.MustParseAddr(BuildLink.Relay) {
					t.Errorf("the lease: %v from %v, want %v from %s", l.Address, l.Server, want, BuildLink.Relay)
				}
			} else {
				addr := d.Address
				if d.BuildLink != nil {
					addr = d.BuildLink.Relay
				}
				env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: network(t, a, attach.Build), Relay: netip.MustParseAddr(addr)})
				if err != nil {
					t.Fatal(err)
				}
				if d.Mode == relay.ModeVM {
					lease(t, a, d.BuildLink.Guest)
				}
			}
			defer env.Close()
			received := build(t, env, ca, true, true)
			waitCompletion(t, coll)
			checkCollector(t, coll, received)
			data, _, _ := coll.Ledger()
			checkLedger(t, data, key, received)
		})
	}
}

// lease takes a lease over the build link of a vm-mode relay claimed with a
// build_link, as a guest with no address yet.
func lease(t *testing.T, a attach.Attachment, guest string) {
	t.Helper()
	pc, err := network(t, a, attach.Build).ListenPacket(testCtx(t), "udp", "0.0.0.0:68")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	l, err := dhcp.LeasePacket(testCtx(t), pc, guestMAC)
	if err != nil {
		t.Fatal(err)
	}
	if l.Address.Addr() != netip.MustParseAddr(guest) {
		t.Errorf("the lease gave %v, want %s", l.Address, guest)
	}
}

func network(t *testing.T, a attach.Attachment, s attach.Side) attach.Network {
	t.Helper()
	n, err := a.Network(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fetched is what the build environment received for one request.
type fetched struct {
	url    string
	status int
	body   []byte
}

// build is the whole build on env: the relay's health, a name resolved, an
// origin fetched over HTTP and over TLS, the inputs, an artifact, the
// console and the exit. It returns what the build environment received for
// each request whose body the relay records.
func build(t *testing.T, env *buildenv.Env, ca *x509.Certificate, hasScript, hasBootstrap bool) []fetched {
	t.Helper()
	ctx := testCtx(t)
	if err := env.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if as, err := env.Resolve(ctx, originName); err != nil || len(as) != 1 || as[0] != originAddr {
		t.Errorf("DNS for %s: %v, %v", originName, as, err)
	}
	if as, err := env.Resolve(ctx, "artifacts"); err != nil || len(as) != 1 || as[0] != env.Relay() {
		t.Errorf("DNS for artifacts: %v, %v; want %v", as, err, env.Relay())
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cl := env.Client(roots)
	do := func(method, url string, body []byte) (int, []byte, http.Header) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Close = true
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s %s: the body: %v", method, url, err)
		}
		return resp.StatusCode, b, resp.Header
	}
	var out []fetched
	for _, u := range []string{"http://" + originName + "/bytes/1000", "https://" + originName + "/bytes/70000"} {
		status, b, _ := do("GET", u, nil)
		want := upstream.Body(originName, strings.TrimPrefix(strings.TrimPrefix(u, "http://"+originName), "https://"+originName))
		if status != 200 || !bytes.Equal(b, want) {
			t.Errorf("GET %s: %d, %d bytes; want 200 and the origin's %d", u, status, len(b), len(want))
		}
		out = append(out, fetched{u, status, b})
	}
	status, b, _ := do("GET", "http://artifacts/build-script", nil)
	if hasScript != (status == 200) || hasScript && !bytes.Equal(b, script) {
		t.Errorf("the build script: %d %q", status, b)
	}
	if status == 200 {
		out = append(out, fetched{"http://artifacts/build-script", status, b})
	}
	status, b, h := do("GET", "https://artifacts/bootstrap", nil)
	if hasBootstrap != (status == 200) || hasBootstrap && (!bytes.Equal(b, Bootstrap) || h.Get("Content-Type") != "application/json") {
		t.Errorf("the bootstrap config: %d %q", status, b)
	}
	if status == 200 {
		out = append(out, fetched{"https://artifacts/bootstrap", status, b})
	}
	if status, b, _ := do("GET", "http://cwd/", nil); status != 200 || string(b) != "Makefile\nsrc/a.c\n" {
		t.Errorf("the context's listing: %d %q", status, b)
	}
	status, b, _ = do("GET", "http://cwd/src/a.c", nil)
	if status != 200 || !bytes.Equal(b, context0["src/a.c"]) {
		t.Errorf("a context file: %d %q", status, b)
	}
	out = append(out, fetched{"http://cwd/src/a.c", status, b})
	if status, b, _ := do("GET", "http://artifacts/ca.pem", nil); status != 200 || !bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("ca.pem: %d %q", status, b)
	}
	if status, b, _ := do("GET", "http://artifacts/ca.crl", nil); status != 200 {
		t.Errorf("ca.crl: %d", status)
	} else if crl, err := x509.ParseRevocationList(b); err != nil || crl.CheckSignatureFrom(ca) != nil {
		t.Errorf("ca.crl does not verify under the CA: %v", err)
	}
	if status, b, _ := do("POST", "http://artifacts/out/app.bin", []byte("built")); status != 200 || string(b) != "artifact stored: out/app.bin (5 bytes)\n" {
		t.Errorf("the artifact: %d %q", status, b)
	}
	control := "http://" + net.JoinHostPort(env.Relay().String(), strconv.Itoa(relay.PortControl))
	if status, b, _ := do("POST", control+"/v1/output", []byte("console\n")); status != 200 || len(b) != 0 {
		t.Errorf("the console: %d %q", status, b)
	}
	if status, b, _ := do("GET", "http://artifacts/heartbeat", nil); status != 200 || string(b) != "ok\n" {
		t.Errorf("the heartbeat: %d %q", status, b)
	}
	if status, b, _ := do("POST", "http://artifacts/exit?code=3", nil); status != 200 || string(b) != "ok\n" {
		t.Errorf("the exit: %d %q", status, b)
	}
	return out
}

func waitCompletion(t *testing.T, coll *collector.Collector) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := coll.Completion(); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the collector had no completion")
}

// checkCollector checks what the collector holds: the ledger request first
// and ended before the completion, which is last, the artifact, the console,
// the captures of both proxied exchanges, and the exit code.
func checkCollector(t *testing.T, coll *collector.Collector, received []fetched) {
	t.Helper()
	reqs := coll.Requests()
	if len(reqs) == 0 || reqs[0].Path != "/v1/ledger" {
		t.Fatalf("the collector's first request is not the ledger's: %v", reqs)
	}
	last := reqs[len(reqs)-1]
	if last.Path != "/v1/complete" {
		t.Errorf("the collector's last request is %s, not the completion", last.Path)
	}
	if _, _, ended := coll.Ledger(); !ended || reqs[0].End > last.Begin {
		t.Errorf("the ledger had not ended before the completion")
	}
	for _, r := range reqs[1 : len(reqs)-1] {
		if r.End > last.Begin {
			t.Errorf("%s ended after the completion began", r.Path)
		}
	}
	if c, _ := coll.Completion(); c.ExitCode != 3 {
		t.Errorf("the exit code: %d", c.ExitCode)
	}
	if got := coll.Artifacts()["out/app.bin"]; string(got) != "built" {
		t.Errorf("the artifact: %q", got)
	}
	if got := coll.Output(); string(got) != "console\n" {
		t.Errorf("the console: %q", got)
	}
	// Two proxied exchanges, captured in all four parts but the request
	// bodies they have not; the inputs served are not captured.
	if n := len(coll.Captures()); n != 6 {
		t.Errorf("%d captures, want 6", n)
	}
}

// checkLedger verifies the ledger under key, and finds, for each body the
// build environment received, the response's body record whose payload is
// those bytes; the ledger has no channel left open.
func checkLedger(t *testing.T, data []byte, key ed25519.PublicKey, received []fetched) {
	t.Helper()
	l, err := ledger.Verify(data, key)
	if err != nil {
		t.Fatalf("the ledger: %v", err)
	}
	if len(l.Unclosed) > 0 || l.Truncated > 0 {
		t.Errorf("the ledger has open channels %v, or %d bytes cut short", l.Unclosed, l.Truncated)
	}
	var arts int
	for _, r := range l.Records {
		if r.Type == ledger.Artifact {
			arts++
		}
	}
	if arts != 1 {
		t.Errorf("%d artifact records, want 1", arts)
	}
	for _, f := range received {
		found := false
		for _, r := range l.Records {
			if r.Type != ledger.Close {
				continue
			}
			if st, _ := r.Int("status"); st == int64(f.status) && l.CheckPayload(r, f.body) == nil {
				open := l.Records[r.Channel]
				if u, _ := open.Text("url"); u == f.url {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("no record of %s has the hash of the %d bytes the build received", f.url, len(f.body))
		}
	}
}

func TestCollectorInEveryForm(t *testing.T) {
	t.Parallel()
	for name, f := range Forms() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runCollector(t, f)
		})
	}
}

// runCollector runs a whole build with the harness's relay, in host mode,
// driving the in-process collector in form f, and reads back what it
// stored. The collector's claim names the origins' CA, as the disk
// collector's does with --upstream-ca.
func runCollector(t *testing.T, f Form) {
	ctx := testCtx(t)
	upNet := memnet.New()
	up := world(t, upNet.Host(UpstreamHarness))
	f.UpstreamCACerts = []string{string(up.CA.PEM())}
	a := Collector(f)
	defer a.Close()
	d := a.Declared()
	harness, relayEnd := memnet.Frames()
	defer harness.Close()
	defer relayEnd.Close()
	guest, err := relay.NewGuest(relay.GuestConfig{Mode: relay.ModeHost, Frames: relayEnd})
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Start(ctx, relay.Config{
		Net: network(t, a, attach.Claim), Token: "claim-token",
		Upstream: upNet.Host(UpstreamRelay), ResolvConf: []netip.Addr{UpstreamHarness}, Build: guest,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	dir := t.TempDir()
	scriptFile := filepath.Join(dir, "script")
	ctxDir := filepath.Join(dir, "context")
	out := filepath.Join(dir, "out")
	for name, b := range map[string][]byte{scriptFile: script, filepath.Join(ctxDir, "Makefile"): context0["Makefile"], filepath.Join(ctxDir, "src", "a.c"): context0["src/a.c"]} {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	in, err := a.Start(ctx, attach.Params{
		Claim: r.Claim().Address, Token: "claim-token", Out: out,
		Context: ctxDir, Script: scriptFile, Capture: relay.CaptureAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Stop()
	s, err := r.Session(ctx)
	if err != nil {
		t.Fatalf("%v; the collector's log:\n%s", err, in.Log())
	}
	env, err := buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: harness, MAC: guestMAC})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	received := build(t, env, s.CA().Cert, true, !d.Forms.NoBootstrap)
	select {
	case <-s.Done():
	case <-ctx.Done():
		t.Fatal("the session did not complete")
	}
	rb, err := in.ReadBack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(rb, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("the read-back: %v", err)
		}
		return b
	}
	if got := read("artifacts/out/app.bin"); string(got) != "built" {
		t.Errorf("the artifact read back: %q", got)
	}
	if got := read("build-output.log"); string(got) != "console\n" {
		t.Errorf("the console read back: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(rb, "captures"))
	if len(entries) != 6 {
		t.Errorf("%d captures read back, want 6", len(entries))
	}
	checkLedger(t, read("ledger"), s.PublicKey(), received)
}
