package cases

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The cases of the relay role claim the relay under test with the harness's
// claimant, the harness's collector serving the session on the tunnel, and
// drive the build side with the harness's build environment, as a build
// does; they then read what the collector received. What follows is what
// they share.

// originName is the upstream origin a build reaches through the relay.
const originName = "origin.example"

// guestMAC is the build environment's Ethernet address on a frame link.
var guestMAC = net.HardwareAddr{0x02, 0, 0, 0, 0xb8, 0x0b}

// collectorToken is the collector token of a session that has one.
const collectorToken = "conformance-collector-token"

// served is the harness's collector as the tunnel serves it, with what a
// case adds in front of it: the arrival of the ledger's bytes, timed, and
// a completion that it records and then leaves unanswered.
type served struct {
	c *collector.Collector
	// abortComplete records a completion and resets its stream unanswered,
	// as a collector that closes the session's connection first does
	// (COLLOUT-2).
	abortComplete bool

	mu    sync.Mutex
	marks []mark
}

// mark is a point of the ledger's arrival: by when bytes had arrived.
type mark struct {
	at    time.Time
	bytes int
}

func (w *served) Done() <-chan struct{} { return w.c.Done() }

func (w *served) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/ledger" && r.Method == http.MethodPut {
		r.Body = &tap{rc: r.Body, w: w}
	}
	if w.abortComplete && r.URL.Path == "/v1/complete" {
		w.c.ServeHTTP(httptest.NewRecorder(), r)
		panic(http.ErrAbortHandler)
	}
	w.c.ServeHTTP(rw, r)
}

// arrived is when the ledger's first n bytes had all arrived, and whether
// they had.
func (w *served) arrived(n int) (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range w.marks {
		if m.bytes >= n {
			return m.at, true
		}
	}
	return time.Time{}, false
}

// tap times the ledger's bytes as the collector reads them.
type tap struct {
	rc io.ReadCloser
	w  *served
	n  int
}

func (t *tap) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.n += n
		t.w.mu.Lock()
		t.w.marks = append(t.w.marks, mark{at: time.Now(), bytes: t.n})
		t.w.mu.Unlock()
	}
	return n, err
}

func (t *tap) Close() error { return t.rc.Close() }

// build is a claimed relay under test, its collector and its build
// environment.
type build struct {
	t   *runner.T
	in  attach.Instance
	w   *served
	c   *collector.Collector
	up  *upstream.Upstream
	cfg claimant.Config
	rep *claimant.Reply
	// claimedAt is when the claim's reply had arrived.
	claimedAt time.Time
	ca        *x509.Certificate
	env       *buildenv.Env
}

// buildOpts are what a case changes in the session.
type buildOpts struct {
	form          collector.Form
	fault         collector.Fault
	abortComplete bool
	capture       string
	edit          func(*claimant.Config)
	// anyReply takes the claim's reply whatever it is, and starts no build
	// environment.
	anyReply bool
}

// claimRelay starts the relay under test and the harness's upstream (a
// resolver and an origin at the harness's upstream address), claims it with
// the harness's collector in o's form behind the tunnel, and, once the
// claim is answered 200, starts the build environment on the relay's build
// link and waits for the relay to serve it.
func claimRelay(t *runner.T, o buildOpts) *build {
	ctx := t.Context()
	in := t.Instance(attach.Params{})
	d := t.Declared()
	upNet := t.Network(attach.Upstream)
	addr := upNet.Address()
	up, err := upstream.Start(ctx, upNet, upstream.World{
		Resolvers: []netip.Addr{addr},
		Origins:   []upstream.Origin{{Name: originName, Addr: addr}},
	})
	if err != nil {
		t.Fatalf("the harness's upstream: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	b := &build{t: t, in: in, up: up}
	b.c = collector.New(o.form, o.fault)
	b.w = &served{c: b.c, abortComplete: o.abortComplete}
	no := false
	b.cfg = claimant.Config{
		CollectorToken: o.form.Token, CaptureMode: o.capture,
		UpstreamDNS: up.DNS(), UpstreamCACerts: []string{string(up.CA.PEM())}, UpstreamSystemCA: &no,
	}
	if d.BuildLink != nil {
		b.cfg.BuildLink = &claimant.BuildLink{Prefix: d.BuildLink.Prefix, Relay: d.BuildLink.Relay, Guest: d.BuildLink.Guest}
	}
	if o.edit != nil {
		o.edit(&b.cfg)
	}
	cl := claimant.Claimant{Net: t.Network(attach.Claim), Endpoint: in.Claim()}
	tun, rep, err := cl.Session(ctx, b.w, b.cfg)
	b.claimedAt = time.Now()
	if tun != nil {
		t.Cleanup(func() { _ = tun.Close() })
	}
	if err != nil {
		t.Fatalf("the tunnel and the claim: %v", err)
	}
	b.rep = rep
	if o.anyReply {
		return b
	}
	if rep.Status != http.StatusOK {
		t.Fatalf("the claim was answered %d %q, want 200", rep.Status, rep.Body)
	}
	if _, b.ca, _, err = rep.Identity(); err != nil {
		t.Fatalf("the claim's 200: %v", err)
	}
	if d.Link == buildenv.Frames {
		link, err := in.Frames()
		if err != nil {
			t.Fatalf("the relay's frame link: %v", err)
		}
		b.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: link, MAC: guestMAC})
		if err != nil {
			t.Fatalf("the build environment: %v", err)
		}
	} else {
		at := d.Address
		if b.cfg.BuildLink != nil {
			at = b.cfg.BuildLink.Relay
		}
		ra, err := netip.ParseAddr(at)
		if err != nil {
			t.Fatalf("the relay's address on its build link is not known before a lease (%q): the target declares neither build_link nor address_by_launcher", at)
		}
		b.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: t.Network(attach.Build), Relay: ra})
		if err != nil {
			t.Fatalf("the build environment: %v", err)
		}
	}
	if d.Link != buildenv.Frames {
		// On a frame link the build environment's Close closes the frame
		// socket, which the instance's Stop closes too, and the sandbox's
		// Stop then fails for a socket already closed; the instance's Stop
		// ends the stack instead.
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
func (b *build) do(method, url string, body []byte) reply {
	roots := x509.NewCertPool()
	roots.AddCert(b.ca)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(b.t.Context(), method, url, rd)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, url, err)
	}
	req.Close = true
	resp, err := b.env.Client(roots).Do(req)
	if err != nil {
		b.t.Fatalf("the build's %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatalf("the build's %s %s: reading the response: %v", method, url, err)
	}
	return reply{resp.StatusCode, resp.Header, got}
}

// control is the URL of path on the relay's control plane.
func (b *build) control(path string) string {
	return "http://" + net.JoinHostPort(b.env.Relay().String(), strconv.Itoa(buildenv.ControlPort)) + path
}

// exit completes the build with code, as the build does, and waits for the
// collector to have the completion.
func (b *build) exit(code int) {
	rep := b.do(http.MethodPost, "http://artifacts/exit?code="+strconv.Itoa(code), nil)
	if rep.status != http.StatusOK {
		b.t.Errorf("the build's POST http://artifacts/exit was answered %d %q, want 200", rep.status, rep.body)
	}
	if !waitFor(b.t, 5*time.Second, func() bool { _, ok := b.c.Completion(); return ok }) {
		b.t.Fatalf("the collector received no completion within 5s of the build's exit; it received:\n%s", b.requests())
	}
}

// requests renders what the collector received, for a failure.
func (b *build) requests() string {
	var s bytes.Buffer
	for _, r := range b.c.Requests() {
		s.WriteString("  " + strconv.Itoa(r.Begin) + "-" + strconv.Itoa(r.End) + " " + r.Method + " " + r.Path + " " + strconv.Itoa(r.Status) + "\n")
	}
	return s.String()
}

// first is the first request the collector received to path, and whether
// there was one.
func (b *build) first(method, path string) (collector.Request, bool) {
	for _, r := range b.c.Requests() {
		if r.Method == method && r.Path == path {
			return r, true
		}
	}
	return collector.Request{}, false
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
