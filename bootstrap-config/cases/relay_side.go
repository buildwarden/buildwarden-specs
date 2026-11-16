package cases

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The cases of the relay role claim the relay under test with the harness's
// claimant and the harness's collector behind the tunnel, start the
// harness's build environment on the relay's build link, and have the build
// fetch http://artifacts/bootstrap as an executor does; they then read what
// the collector received and the ledger. What follows is what they share.

// guestMAC is the build environment's Ethernet address on a frame link.
var guestMAC = net.HardwareAddr{0x02, 0, 0, 0, 0xb0, 0x07}

// bootstrapURL is where the build reads the config (BOOTCFG-9).
const bootstrapURL = "http://artifacts/bootstrap"

// collectorPath is where the relay fetches it from the collector
// (BOOTCFG-1).
const collectorPath = "/v1/bootstrap"

// served is the harness's collector as the tunnel serves it, with requests
// to collectorPath answered by override in its place when override is set.
// The collector does not see those, so they are counted here.
type served struct {
	c          *collector.Collector
	override   http.HandlerFunc
	overridden atomic.Int32
}

func (w *served) Done() <-chan struct{} { return w.c.Done() }

func (w *served) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if w.override != nil && r.URL.Path == collectorPath {
		w.overridden.Add(1)
		w.override(rw, r)
		return
	}
	w.c.ServeHTTP(rw, r)
}

// build is a claimed relay under test, its collector and its build
// environment.
type build struct {
	t   *runner.T
	c   *collector.Collector
	w   *served
	ca  *x509.Certificate
	key ed25519.PublicKey
	env *buildenv.Env
}

// claimRelay starts the relay under test and the harness's upstream (a
// resolver at the harness's upstream address), claims the relay with the
// harness's collector in form behind the tunnel, with fault and override in
// front of it, and, once the claim is answered 200, starts the build
// environment on the relay's build link and waits for the relay to serve it.
func claimRelay(t *runner.T, form collector.Form, fault collector.Fault, override http.HandlerFunc) *build {
	ctx := t.Context()
	in := t.Instance(attach.Params{})
	d := t.Declared()
	upNet := t.Network(attach.Upstream)
	addr := upNet.Address()
	up, err := upstream.Start(ctx, upNet, upstream.World{Resolvers: []netip.Addr{addr}})
	if err != nil {
		t.Fatalf("the harness's upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	b := &build{t: t, c: collector.New(form, fault)}
	no := false
	cfg := claimant.Config{
		CollectorToken: form.Token,
		UpstreamDNS:    up.DNS(), UpstreamCACerts: []string{string(up.CA.PEM())}, UpstreamSystemCA: &no,
	}
	if d.BuildLink != nil {
		cfg.BuildLink = &claimant.BuildLink{Prefix: d.BuildLink.Prefix, Relay: d.BuildLink.Relay, Guest: d.BuildLink.Guest}
	}
	cl := claimant.Claimant{Net: t.Network(attach.Claim), Endpoint: in.Claim()}
	b.w = &served{c: b.c, override: override}
	tun, rep, err := cl.Session(ctx, b.w, cfg)
	if tun != nil {
		t.Cleanup(func() { _ = tun.Close() })
	}
	if err != nil {
		t.Fatalf("the tunnel and the claim: %v", err)
	}
	if rep.Status != http.StatusOK {
		t.Fatalf("the claim was answered %d %q, want 200", rep.Status, rep.Body)
	}
	if _, b.ca, b.key, err = rep.Identity(); err != nil {
		t.Fatalf("the claim's 200: %v", err)
	}
	if d.Link == buildenv.Frames {
		link, err := in.Frames()
		if err != nil {
			t.Fatalf("the relay's frame link: %v", err)
		}
		// The instance's Stop closes the frame socket and ends the stack,
		// so the build environment is not closed here as well.
		b.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: link, MAC: guestMAC})
		if err != nil {
			t.Fatalf("the build environment: %v", err)
		}
	} else {
		at := d.Address
		if cfg.BuildLink != nil {
			at = cfg.BuildLink.Relay
		}
		ra, err := netip.ParseAddr(at)
		if err != nil {
			t.Fatalf("the relay's address on its build link is not known before a lease (%q): the target declares neither build_link nor address_by_launcher", at)
		}
		b.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: t.Network(attach.Build), Relay: ra})
		if err != nil {
			t.Fatalf("the build environment: %v", err)
		}
		t.Cleanup(func() { _ = b.env.Close() })
	}
	if err := b.env.Ready(ctx); err != nil {
		t.Fatalf("the relay does not serve its build link: %v", err)
	}
	return b
}

// reply is what the build environment received.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// do sends one request of the build, on a connection of its own, and fails
// the case when it fails.
func (b *build) do(method, u string) reply {
	roots := x509.NewCertPool()
	roots.AddCert(b.ca)
	req, err := http.NewRequestWithContext(b.t.Context(), method, u, nil)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, u, err)
	}
	req.Close = true
	resp, err := b.env.Client(roots).Do(req)
	if err != nil {
		b.t.Fatalf("the build's %s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatalf("the build's %s %s: reading the response: %v", method, u, err)
	}
	return reply{resp.StatusCode, resp.Header, got}
}

// exit completes the build, as the build does, waits for the collector to
// have the completion, and returns the ledger it received, verified under
// the claim's ledger key. The completion is the last thing a case sends:
// nothing the relay would record follows it (D16, D18).
func (b *build) exit() *ledger.Ledger {
	rep := b.do(http.MethodPost, "http://artifacts/exit?code=0")
	if rep.status != http.StatusOK {
		b.t.Errorf("the build's POST http://artifacts/exit was answered %d %q, want 200", rep.status, short(rep.body))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := b.c.Completion(); ok {
			break
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("the collector received no completion within 5s of the build's exit; it received:\n%s", b.requests())
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-b.t.Context().Done():
			b.t.Fatalf("the case's time ran out")
		}
	}
	data, _, ended := b.c.Ledger()
	if !ended {
		b.t.Errorf("the ledger's stream had not ended when the collector received the completion")
	}
	l, err := ledger.Verify(data, b.key)
	if err != nil {
		b.t.Fatalf("the ledger does not verify under the claim's ledger_public_key: %v", err)
	}
	return l
}

// requests renders what the collector received, for a failure.
func (b *build) requests() string {
	var s bytes.Buffer
	for _, r := range b.c.Requests() {
		s.WriteString("  " + r.Method + " " + r.Path + " " + strconv.Itoa(r.Status) + "\n")
	}
	return s.String()
}

// count is how many requests the collector received with method to path.
func (b *build) count(method, path string) int {
	n := 0
	for _, r := range b.c.Requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// servedRecords counts the records of l that record body as the body of a
// GET's response with status 200: a close record on a channel the ledger
// opened for a GET, whose payload is body, into the build (GUEST-49 in
// relay-guest-api, which BOOTCFG-2 refers to). An empty body is a close
// record with no payload; no other GET of the cases is answered 200 with
// none (GUEST-36's /health is answered "ok").
func servedRecords(l *ledger.Ledger, body []byte) int {
	n := 0
	for _, r := range l.Records {
		if r.Type != ledger.Close || r.PayloadSize < 0 || (r.PayloadSize == 0) != (len(body) == 0) {
			continue
		}
		if st, _ := r.Int("status"); st != http.StatusOK || l.CheckPayload(r, body) != nil {
			continue
		}
		if m, _ := l.Records[r.Channel].Text("method"); m == http.MethodGet {
			n++
		}
	}
	return n
}

// bootstrapChannels names the channels of l the ledger opened for a request
// to the path /bootstrap, whatever form the recorded URL takes (an origin
// form or an absolute one).
func bootstrapChannels(l *ledger.Ledger) []string {
	var out []string
	for _, r := range l.Records {
		if r.Type != ledger.Open {
			continue
		}
		raw, _ := r.Text("url")
		if u, err := url.Parse(raw); err == nil && u.Path == "/bootstrap" {
			m, _ := r.Text("method")
			out = append(out, "record "+strconv.Itoa(r.Index)+": "+m+" "+raw)
		}
	}
	return out
}

// strayChannels names the channels of l the ledger opened for a request a
// case of BOOTCFG-3 does not make besides its fetch: any GET but the control
// plane's GET /health that buildenv.Ready polls, and any request at all to
// a path that ends in "bootstrap", whatever its method and host. The build's
// POST http://artifacts/exit, which the relay may record, is neither. A
// relay that records its own exchange with the collector, under
// /v1/bootstrap or any other URL, is named here.
func strayChannels(l *ledger.Ledger) []string {
	var out []string
	for _, r := range l.Records {
		if r.Type != ledger.Open {
			continue
		}
		raw, _ := r.Text("url")
		m, _ := r.Text("method")
		u, err := url.Parse(raw)
		if err != nil {
			out = append(out, "record "+strconv.Itoa(r.Index)+": "+m+" "+strconv.Quote(raw)+" (not a URL)")
			continue
		}
		if strings.HasSuffix(u.Path, "bootstrap") || (m == http.MethodGet && u.Path != "/health") {
			out = append(out, "record "+strconv.Itoa(r.Index)+": "+m+" "+raw)
		}
	}
	return out
}

// short is b for a message, cut at 200 bytes.
func short(b []byte) string {
	if len(b) > 200 {
		return strconv.Quote(string(b[:200])) + "..."
	}
	return strconv.Quote(string(b))
}
