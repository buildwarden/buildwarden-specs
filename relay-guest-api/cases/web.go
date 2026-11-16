package cases

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The cases over HTTP claim a relay as the cases below HTTP do, with the
// harness's collector in a form of the case's behind the tunnel, and with
// the harness's origin CA as the claim's only upstream root; they then send
// the build's requests to the relay's ports and read what the build was
// answered, what the collector received, and, after the build's completion,
// the ledger. What follows is what they share.

// controlPort is the control plane's port (GUEST-35).
const controlPort = 8300

// web is a claimed relay that serves its build link, with the harness's
// roles around it, ready for the build's requests.
type web struct {
	*relayRun
	env *buildenv.Env
	tee *tee
	// key is the claim reply's ledger_public_key, caPEM its ca_cert as the
	// relay sent it, and roots a pool of that certificate alone.
	key   ed25519.PublicKey
	caPEM []byte
	roots *x509.CertPool
	// sent is when the claim was sent, and answered when its 200 came.
	sent, answered time.Time
}

// webOpts is how a case wants its relay claimed. The zero value is a
// collector in its zero form, which has no script, no context and no
// bootstrap config, and the harness's origin CA as the one upstream root.
type webOpts struct {
	form  collector.Form
	fault collector.Fault
	// override answers the collector's requests to a path in its place;
	// tee counts them.
	override map[string]http.HandlerFunc
	// upstreamCA is the claim's upstream_ca_certs in place of the
	// harness's origin CA.
	upstreamCA []string
}

// startWeb starts a fresh relay and the default world, claims it as o
// says, and starts the build environment once the relay serves it.
func startWeb(t *runner.T, o webOpts) *web {
	r := startRelay(t)
	r.coll = collector.New(o.form, o.fault)
	roots := o.upstreamCA
	if roots == nil {
		roots = []string{string(r.up.CA.PEM())}
	}
	no := false
	cfg := claimant.Config{
		CollectorToken: o.form.Token, UpstreamDNS: r.listed(),
		UpstreamCACerts: roots, UpstreamSystemCA: &no,
	}
	if l := r.d.BuildLink; l != nil {
		cfg.BuildLink = &claimant.BuildLink{Prefix: l.Prefix, Relay: l.Relay, Guest: l.Guest}
	}
	w := &web{relayRun: r, tee: &tee{c: r.coll, override: o.override, bodies: map[string][][]byte{}}}
	w.sent = time.Now()
	tun, rep, err := r.cl.Session(t.Context(), w.tee, cfg)
	if tun != nil {
		t.Cleanup(func() { _ = tun.Close() })
	}
	if err != nil {
		t.Fatalf("the tunnel and the claim: %v", err)
	}
	w.answered = time.Now()
	if rep.Status != http.StatusOK {
		t.Fatalf("the claim was answered %d %q, want 200", rep.Status, rep.Body)
	}
	id, ca, key, err := rep.Identity()
	if err != nil {
		t.Fatalf("the claim's 200: %v", err)
	}
	r.ca, w.key, w.caPEM = ca, key, []byte(id.CACert)
	w.roots = x509.NewCertPool()
	w.roots.AddCert(ca)
	w.env = r.build(nil)
	return w
}

// tee is the harness's collector as the tunnel serves it. It keeps the body
// of each reply the collector writes, by the request's path, so that a case
// can compare what the relay served with what the collector gave it, and it
// answers the paths of override in the collector's place.
type tee struct {
	c        *collector.Collector
	override map[string]http.HandlerFunc

	mu         sync.Mutex
	bodies     map[string][][]byte
	overridden map[string]int
}

func (s *tee) Done() <-chan struct{} { return s.c.Done() }

func (s *tee) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if h, ok := s.override[r.URL.Path]; ok {
		s.mu.Lock()
		if s.overridden == nil {
			s.overridden = map[string]int{}
		}
		s.overridden[r.URL.Path]++
		s.mu.Unlock()
		h(rw, r)
		return
	}
	k := &keeper{ResponseWriter: rw}
	s.c.ServeHTTP(k, r)
	s.mu.Lock()
	s.bodies[r.URL.EscapedPath()] = append(s.bodies[r.URL.EscapedPath()], k.body.Bytes())
	s.mu.Unlock()
}

// replied is the body of the collector's last reply to a request for path,
// as it was sent, and whether there was one.
func (s *tee) replied(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bs := s.bodies[path]
	if len(bs) == 0 {
		return nil, false
	}
	return bs[len(bs)-1], true
}

// count is how many requests for path override answered.
func (s *tee) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overridden[path]
}

// keeper is a ResponseWriter that keeps what is written.
type keeper struct {
	http.ResponseWriter
	body bytes.Buffer
}

func (k *keeper) Write(b []byte) (int, error) {
	k.body.Write(b)
	return k.ResponseWriter.Write(b)
}

func (k *keeper) Flush() {
	if f, ok := k.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// reply is what the build environment was answered.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// mediaType is the reply's Content-Type without its parameters.
func (r reply) mediaType() string {
	mt, _, err := mime.ParseMediaType(r.header.Get("Content-Type"))
	if err != nil {
		return r.header.Get("Content-Type")
	}
	return mt
}

// String renders the reply for a failure.
func (r reply) String() string {
	return fmt.Sprintf("%d (Content-Type %q) %s", r.status, r.header.Get("Content-Type"), short(r.body))
}

// short is b for a message, cut at 200 bytes.
func short(b []byte) string {
	if len(b) > 200 {
		return strconv.Quote(string(b[:200])) + "..."
	}
	return strconv.Quote(string(b))
}

// conn is a connection of the build environment's to port of the relay's
// address, over TLS with the server name sni when sni is not empty,
// trusting the claim's ca_cert. On a frame link the relay captures the
// connection whatever its address (GUEST-6), so the relay's address serves
// both kinds of link. It is closed when the case ends.
func (w *web) conn(port uint16, sni string) net.Conn {
	t := w.t
	ctx, cancel := context.WithTimeout(t.Context(), within)
	defer cancel()
	c, err := w.env.Network().Dial(ctx, "tcp", netip.AddrPortFrom(w.relayAddr(), port).String())
	if err != nil {
		t.Fatalf("a connection to the relay's %s:%d: %v", w.relayAddr(), port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if sni == "" {
		return c
	}
	tc := tls.Client(c, &tls.Config{RootCAs: w.roots, ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("the TLS handshake with the relay's %s:%d for %s, trusting the claim's ca_cert: %v", w.relayAddr(), port, sni, err)
	}
	return tc
}

// exchange writes req on c and reads one response, its body to its end, in
// the case's bound.
func (w *web) exchange(c net.Conn, br *bufio.Reader, req string) (reply, error) {
	_ = c.SetDeadline(time.Now().Add(within))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(c, req); err != nil {
		return reply{}, err
	}
	method, _, _ := strings.Cut(req, " ")
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, fmt.Errorf("reading the body of a %d: %w", resp.StatusCode, err)
	}
	return reply{resp.StatusCode, resp.Header, b}, nil
}

// send sends req, a whole HTTP/1.x request, on a new connection to port of
// the relay's address (over TLS with sni when it is not empty), and returns
// the response; the case fails when there is none. A request that may be
// answered with a body that ends at the close says Connection: close
// (GUEST-47).
func (w *web) send(port uint16, sni, req string) reply {
	c := w.conn(port, sni)
	defer c.Close()
	rep, err := w.exchange(c, bufio.NewReader(c), req)
	if err != nil {
		w.t.Fatalf("the build's %s on port %d: %v", firstLine(req), port, err)
	}
	return rep
}

// request is an HTTP/1.1 request for host with Connection: close, and the
// body, when there is one, with its length.
func request(method, target, host string, body []byte, fields ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, target, host)
	for _, f := range fields {
		b.WriteString(f + "\r\n")
	}
	if body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// get sends GET target for host on port 80.
func (w *web) get(host, target string) reply {
	return w.send(80, "", request(http.MethodGet, target, host, nil))
}

// post sends POST target for host on port 80 with body.
func (w *web) post(host, target string, body []byte, fields ...string) reply {
	return w.send(80, "", request(http.MethodPost, target, host, body, fields...))
}

// control sends method target to the control plane, with body when it is
// not nil.
func (w *web) control(method, target string, body []byte) reply {
	return w.send(controlPort, "", request(method, target, "control", body))
}

// firstLine is a request's first line, for a message.
func firstLine(req string) string {
	l, _, _ := strings.Cut(req, "\r\n")
	return l
}

// expect checks that what was answered status with Content-Type media type
// ctype (any when empty) and, when body is not nil, that body.
func expect(t *runner.T, what string, rep reply, status int, ctype string, body []byte) {
	if rep.status != status {
		t.Errorf("%s was answered %s, want %d", what, rep, status)
		return
	}
	if ctype != "" && rep.mediaType() != ctype {
		t.Errorf("%s was answered %d with Content-Type %q, want %s", what, status, rep.header.Get("Content-Type"), ctype)
	}
	if body != nil && !bytes.Equal(rep.body, body) {
		t.Errorf("%s was answered %d with the body %s, want %s", what, status, short(rep.body), short(body))
	}
}

// refused checks that what was answered with a refusal of status: as
// GUEST-56 has every refusal, Content-Type text/plain, with or without
// parameters, and a body of at most one line; and, when body is not empty,
// that body.
func refused(t *runner.T, what string, rep reply, status int, body string) {
	if rep.status != status {
		t.Errorf("%s was answered %s, want %d", what, rep, status)
		return
	}
	if rep.mediaType() != "text/plain" {
		t.Errorf("%s was refused %d with Content-Type %q, want text/plain", what, status, rep.header.Get("Content-Type"))
	}
	if line := strings.TrimSuffix(string(rep.body), "\n"); strings.ContainsAny(line, "\r\n") {
		t.Errorf("%s was refused %d with a body of more than one line, %s", what, status, short(rep.body))
	}
	if body != "" && string(rep.body) != body {
		t.Errorf("%s was refused %d with the body %s, want %q", what, status, short(rep.body), body)
	}
}

// requests renders what the collector received, for a failure.
func (w *web) requests() string {
	var s strings.Builder
	for _, r := range w.coll.Requests() {
		fmt.Fprintf(&s, "  %d-%d %s %s %d\n", r.Begin, r.End, r.Method, r.Path, r.Status)
	}
	return s.String()
}

// received are the requests the collector received with method for path,
// or for a path under it when path ends in "/".
func (w *web) received(method, path string) []collector.Request {
	var out []collector.Request
	for _, r := range w.coll.Requests() {
		p, _, _ := strings.Cut(r.Path, "?")
		if r.Method != method {
			continue
		}
		if p == path || strings.HasSuffix(path, "/") && strings.HasPrefix(p, path) {
			out = append(out, r)
		}
	}
	return out
}

// awaitCompletion waits for the collector to have the session's completion,
// and returns it.
func (w *web) awaitCompletion() collector.Completion {
	t := w.t
	deadline := time.Now().Add(within)
	for {
		if c, ok := w.coll.Completion(); ok {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collector received no completion within %s of the build's; it received:\n%s", within, w.requests())
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-t.Context().Done():
			t.Fatalf("the case's time ran out")
		}
	}
}

// completedInOrder checks that the collector's session went as GUEST-21
// has a completion go: the ledger's request answered before the completion
// began, and the completion's exit code want.
func (w *web) completedInOrder(what string, want int64) {
	t := w.t
	c := w.awaitCompletion()
	if c.ExitCode != want {
		t.Errorf("after %s the collector received the exit code %d, want %d", what, c.ExitCode, want)
	}
	led := w.received(http.MethodPut, "/v1/ledger")
	comp := w.received(http.MethodPost, "/v1/complete")
	if len(led) == 0 || len(comp) == 0 {
		t.Fatalf("after %s the collector received %d ledger requests and %d completions:\n%s", what, len(led), len(comp), w.requests())
	}
	if led[0].End > comp[0].Begin {
		t.Errorf("after %s the completion began (event %d) before the ledger's request was answered (event %d):\n%s", what, comp[0].Begin, led[0].End, w.requests())
	}
	if _, _, ended := w.coll.Ledger(); !ended {
		t.Errorf("after %s the ledger's stream had not ended when the collector received the completion", what)
	}
}

// exit completes the build as the build does, with POST
// http://artifacts/exit, checks the reply and that the completion came in
// order, and returns the ledger the collector received, verified under the
// claim's ledger_public_key. It is the last request a case sends: nothing
// the relay would record follows it (GUEST-55; Known divergences, D18).
func (w *web) exit() *ledger.Ledger {
	rep := w.post("artifacts", "/exit?code=0", nil)
	expect(w.t, "POST http://artifacts/exit?code=0", rep, http.StatusOK, "", nil)
	w.completedInOrder("POST http://artifacts/exit?code=0", 0)
	return w.ledger()
}

// ledger is the ledger the collector received, verified under the claim's
// ledger_public_key.
func (w *web) ledger() *ledger.Ledger {
	data, _, _ := w.coll.Ledger()
	l, err := ledger.Verify(data, w.key)
	if err != nil {
		w.t.Fatalf("the ledger does not verify under the claim's ledger_public_key: %v", err)
	}
	return l
}

// channel is one channel of a ledger: its open record and the records on
// it after the open, in order.
type channel struct {
	open ledger.Record
	recs []ledger.Record
}

// channels are l's channels, in the order of their open records.
func channels(l *ledger.Ledger) []channel {
	var out []channel
	at := map[int]int{}
	for _, r := range l.Records {
		if r.Type == ledger.Open {
			at[r.Index] = len(out)
			out = append(out, channel{open: r})
			continue
		}
		if i, ok := at[r.Channel]; ok {
			out[i].recs = append(out[i].recs, r)
		}
	}
	return out
}

func (c channel) method() string {
	m, _ := c.open.Text("method")
	return m
}

func (c channel) rawURL() string {
	u, _ := c.open.Text("url")
	return u
}

// path is the path of the channel's recorded URL, whatever its form.
func (c channel) path() string {
	u, err := url.Parse(c.rawURL())
	if err != nil {
		return ""
	}
	return u.Path
}

// last is the channel's last record, the one that closes it when it is
// closed.
func (c channel) last() (ledger.Record, bool) {
	if len(c.recs) == 0 {
		return ledger.Record{}, false
	}
	return c.recs[len(c.recs)-1], true
}

func (c channel) String() string {
	return fmt.Sprintf("record %d: %s %s, %d records on it", c.open.Index, c.method(), c.rawURL(), len(c.recs))
}

// onPath are the channels of l whose recorded URL has path.
func onPath(l *ledger.Ledger, path string) []channel {
	var out []channel
	for _, c := range channels(l) {
		if c.path() == path {
			out = append(out, c)
		}
	}
	return out
}

// holds says whether rec states payload as its own: its size and its hash
// block. A record with no payload holds only the empty one.
func holds(l *ledger.Ledger, rec ledger.Record, payload []byte) bool {
	return l.CheckPayload(rec, payload) == nil
}

// recordsOf are the records of l whose payload is b, b not empty.
func recordsOf(l *ledger.Ledger, b []byte) []ledger.Record {
	var out []ledger.Record
	for _, r := range l.Records {
		if len(b) > 0 && r.PayloadSize != 0 && holds(l, r, b) {
			out = append(out, r)
		}
	}
	return out
}

// served checks that l records body as the response to one GET for path
// with status 200, into the build, as GUEST-49 has the relay record what it
// serves: a channel opened for a GET of path that its close record ends
// with body, its status 200.
func served(t *runner.T, l *ledger.Ledger, path string, body []byte) {
	var seen []string
	for _, c := range onPath(l, path) {
		seen = append(seen, c.String())
		last, ok := c.last()
		if !ok || c.method() != http.MethodGet || last.Type != ledger.Close || last.PayloadSize < 0 {
			continue
		}
		if st, _ := last.Int("status"); st == http.StatusOK && holds(l, last, body) {
			return
		}
	}
	t.Errorf("the ledger has no GET of %s closed into the build with status 200 and the %d bytes the build received; its channels for the path: %s", path, len(body), strings.Join(seen, "; "))
}

// notRecorded checks that l has no channel for any of paths and no record
// of any of bodies.
func notRecorded(t *runner.T, l *ledger.Ledger, what string, paths []string, bodies ...[]byte) {
	for _, p := range paths {
		for _, c := range onPath(l, p) {
			t.Errorf("%s: the ledger records %s", what, c)
		}
	}
	for _, b := range bodies {
		for _, r := range recordsOf(l, b) {
			t.Errorf("%s: record %d (%s) of the ledger holds the %d bytes the build was answered", what, r.Index, r.Type, len(b))
		}
	}
}

// pattern is n bytes that no other body of a case has: every byte value,
// in an order of seed.
func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	x := uint32(seed)*2654435761 + 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}
