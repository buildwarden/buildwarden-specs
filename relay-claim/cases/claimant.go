package cases

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
	relayclaim "github.com/buildwarden/buildwarden-specs/relay-claim"
)

// configSchema is the schema of a claim's body (CLAIM-17).
const configSchema = "v1.config.schema.json"

// claimantToken is the claim token the harness's relay is started with for a
// collector that claims.
const claimantToken = "conformance-claim-token"

// unusedResolver is the one nameserver of the harness's relay's resolver
// configuration, at which nothing listens: a relay on the tunnel resolves
// no name, and a collector that claims may leave upstream_dns out.
var unusedResolver = netip.MustParseAddr("192.0.2.53")

// claims applies to a collector that is its own claimant.
func claims(d target.Declared) string {
	if d.Attachment != "claims" {
		return "the collector is not its own claimant"
	}
	return ""
}

// seen is one request the recorder read from the claimant, and what the
// relay answered it. Its marks are the recorder's sequence numbers (step),
// which order what the recorder read across its goroutines; a clock does
// not, since two readings on a coarse clock are equal. A mark of 0 is none.
type seen struct {
	method, path string
	header       http.Header
	body         []byte
	// at is when the request, its body included, had been read, before it
	// was passed on.
	at uint64
	// status is the relay's answer, and answered when the recorder had read
	// it, before it passed it on.
	status   int
	answered uint64
	// firstHeaders is, on a tunnel, when the recorder read the claimant's
	// first HTTP/2 HEADERS frame, the start of its first reply to the
	// relay, before it passed it on.
	firstHeaders uint64
}

// recorder stands between a claimant under test and the harness's relay at
// relay: it accepts the claimant's connections on its own address, reads
// each request and each reply, recording what it read and when, and passes
// the bytes on unchanged. With dropFirst it closes the first connection it
// accepts without reading from it, as a relay that is not yet serving may.
type recorder struct {
	t         *runner.T
	n         attach.Network
	relay     string
	ln        net.Listener
	dropFirst bool

	mu      sync.Mutex
	steps   uint64
	conns   int
	reqs    []*seen
	claimed chan struct{}
	once    sync.Once
}

func startRecorder(t *runner.T, n attach.Network, relayAddr string, dropFirst bool) *recorder {
	ln, err := n.Listen(t.Context(), "tcp", netip.AddrPortFrom(n.Address(), 0).String())
	if err != nil {
		t.Fatalf("the recorder's listener: %v", err)
	}
	rec := &recorder{t: t, n: n, relay: relayAddr, ln: ln, dropFirst: dropFirst, claimed: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go rec.accept()
	return rec
}

func (rec *recorder) addr() string { return rec.ln.Addr().String() }

// step is the recorder's next sequence number, from 1. The caller holds mu.
func (rec *recorder) step() uint64 {
	rec.steps++
	return rec.steps
}

func (rec *recorder) accept() {
	for {
		c, err := rec.ln.Accept()
		if err != nil {
			return
		}
		rec.mu.Lock()
		rec.conns++
		first := rec.conns == 1
		rec.mu.Unlock()
		if first && rec.dropFirst {
			_ = c.Close()
			continue
		}
		go rec.serve(c)
	}
}

// requests are the requests read so far, in the order they were read.
func (rec *recorder) requests() []seen {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]seen, 0, len(rec.reqs))
	for _, s := range rec.reqs {
		out = append(out, *s)
	}
	return out
}

func (rec *recorder) connections() int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.conns
}

// serve passes one connection on: its first request and its reply, read
// and recorded before each is passed on, and then on a tunnel the frames of
// both directions, recording when the claimant's first HEADERS frame came.
func (rec *recorder) serve(c net.Conn) {
	defer c.Close()
	ctx := rec.t.Context()
	up, err := rec.n.Dial(ctx, "tcp", rec.relay)
	if err != nil {
		rec.t.Logf("the recorder could not reach the harness's relay: %v", err)
		return
	}
	defer up.Close()
	var in bytes.Buffer
	cr := bufio.NewReader(io.TeeReader(c, &in))
	req, err := http.ReadRequest(cr)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(req.Body)
	s := &seen{method: req.Method, path: req.URL.RequestURI(), header: req.Header, body: body}
	rec.mu.Lock()
	s.at = rec.step()
	rec.reqs = append(rec.reqs, s)
	rec.mu.Unlock()
	// Pass on what was read of the request, and not what the reader has
	// read past it, which is read again below.
	extra := cr.Buffered()
	rest, _ := cr.Peek(extra)
	rest = append([]byte(nil), rest...)
	if _, err := up.Write(in.Bytes()[:in.Len()-extra]); err != nil {
		return
	}
	var out bytes.Buffer
	ur := bufio.NewReader(io.TeeReader(up, &out))
	resp, err := http.ReadResponse(ur, req)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	rec.mu.Lock()
	s.status, s.answered = resp.StatusCode, rec.step()
	rec.mu.Unlock()
	if req.URL.Path == "/v1/claim" && resp.StatusCode == http.StatusOK {
		rec.once.Do(func() { close(rec.claimed) })
	}
	if _, err := c.Write(out.Bytes()); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(c, up)
	}()
	from := io.MultiReader(bytes.NewReader(rest), c)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		rec.frames(s, from, up)
	} else {
		_, _ = io.Copy(up, from)
	}
	_ = up.Close()
	<-done
}

// frames passes on the claimant's HTTP/2 frames, a 9-byte header and its
// payload each, recording when the first HEADERS frame (type 1) was read.
func (rec *recorder) frames(s *seen, from io.Reader, to io.Writer) {
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(from, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(append([]byte{0}, hdr[:3]...)))
		payload := make([]byte, n)
		if _, err := io.ReadFull(from, payload); err != nil {
			return
		}
		if hdr[3] == 1 {
			rec.mu.Lock()
			if s.firstHeaders == 0 {
				s.firstHeaders = rec.step()
			}
			rec.mu.Unlock()
		}
		if _, err := to.Write(append(append([]byte(nil), hdr...), payload...)); err != nil {
			return
		}
	}
}

// claimThrough starts the harness's relay and a recorder in front of it,
// starts the collector under test against the recorder, and waits for the
// relay's claim to succeed and its 200 to have been read by the recorder.
func claimThrough(t *runner.T, dropFirst bool) *recorder {
	n := t.Network(attach.Claim)
	r, err := relay.Start(t.Context(), relay.Config{Net: n, Token: claimantToken, ResolvConf: []netip.Addr{unusedResolver}})
	if err != nil {
		t.Fatalf("the harness's relay: %v", err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	rec := startRecorder(t, n, r.Claim().Address, dropFirst)
	in := t.Instance(attach.Params{Claim: rec.addr(), Token: claimantToken, Out: t.TempDir(), Capture: "none"})
	// A claimant that never completes its claim fails here, within a bound
	// of its own, and not at the runner's limit for a case.
	ctx, cancel := context.WithTimeout(t.Context(), 3*within)
	defer cancel()
	if _, err := r.Session(ctx); err != nil {
		t.Fatalf("the collector's claim, within %s: %v; its log:\n%s", 3*within, err, in.Log())
	}
	select {
	case <-rec.claimed:
	case <-time.After(within):
		t.Fatalf("the recorder did not read the claim's 200 within %s of the relay's claim", within)
	}
	return rec
}

// claimantRequests has a collector that claims claim the harness's relay
// through the recorder, and checks what it sent: the tunnel request and its
// headers, the token on both requests, the claim after the tunnel's 101, its
// Content-Type and its body against the schema, and a reply on the tunnel
// before the claim's 200.
var claimantRequests = runner.Case{
	Name:    "a claimant opens the tunnel, serves on it, and then sends a valid claim, with its token",
	Cites:   []string{"CLAIM-8", "CLAIM-11", "CLAIM-14", "CLAIM-17", "CLAIM-43", "CLAIM-52"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		rec := claimThrough(t, false)
		reqs := rec.requests()
		var tunnel, claimed *seen
		for i := range reqs {
			s := &reqs[i]
			if want := "Bearer " + claimantToken; strings.Join(s.header.Values("Authorization"), ", ") != want {
				t.Errorf("%s %s carried Authorization %q, want %q", s.method, s.path, s.header.Values("Authorization"), want)
			}
			switch {
			case s.path == "/v1/tunnel" && tunnel == nil:
				tunnel = s
			case s.path == "/v1/claim" && s.status == http.StatusOK:
				claimed = s
			}
		}
		if claimed == nil {
			t.Fatalf("no claim answered 200 was read: %d requests", len(reqs))
		}
		if mt, _, err := mime.ParseMediaType(claimed.header.Get("Content-Type")); err != nil || mt != "application/json" {
			t.Errorf("the claim has Content-Type %q, want application/json", claimed.header.Get("Content-Type"))
		}
		if len(claimed.body) > 16<<20 {
			t.Errorf("the claim's body is %d bytes, over 16 MiB", len(claimed.body))
		}
		if err := relayclaim.Spec.Validate(configSchema, claimed.body); err != nil {
			t.Errorf("the claim: %v; its body: %q", err, claimed.body)
		}
		if !bytes.Contains(claimed.body, []byte(`"http://collector.tunnel"`)) {
			// A claimant that selects no tunnel opens none: the rest is
			// for one that does.
			if tunnel != nil {
				t.Errorf("the claimant opened a tunnel and sent a claim that does not select it: %q", claimed.body)
			}
			return
		}
		if tunnel == nil {
			t.Fatalf("the claim selects the tunnel, and no POST /v1/tunnel was read")
		}
		if tunnel.method != http.MethodPost || !hasHeaderToken(tunnel.header, "Connection", "upgrade") ||
			!strings.EqualFold(tunnel.header.Get("Upgrade"), "warden-tunnel") || tunnel.header.Get("Content-Length") != "0" || len(tunnel.body) != 0 {
			t.Errorf("the tunnel request is %s %s with Connection %q, Upgrade %q, Content-Length %q and %d bytes of body; want POST, Upgrade, warden-tunnel, 0 and none",
				tunnel.method, tunnel.path, tunnel.header.Values("Connection"), tunnel.header.Values("Upgrade"), tunnel.header.Values("Content-Length"), len(tunnel.body))
		}
		if tunnel.status != http.StatusSwitchingProtocols || tunnel.answered == 0 || tunnel.answered >= claimed.at {
			t.Errorf("the claim was read at step %d, before the tunnel's 101 had been passed to the claimant (%d at step %d)", claimed.at, tunnel.status, tunnel.answered)
		}
		if tunnel.firstHeaders == 0 || tunnel.firstHeaders >= claimed.answered {
			t.Errorf("the claimant had sent no reply on the tunnel when the relay answered its claim (its first HEADERS frame at step %d, the 200 at step %d)", tunnel.firstHeaders, claimed.answered)
		}
	},
}

// claimantRetries has the recorder close the claimant's first connection
// without reading from it: the claimant connects again and claims.
var claimantRetries = runner.Case{
	Name:    "a claimant retries a connection the relay closed before answering",
	Cites:   []string{"CLAIM-3"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		rec := claimThrough(t, true)
		if n := rec.connections(); n < 2 {
			t.Errorf("the claimant claimed on %d connections, though its first was closed unanswered", n)
		}
	},
}
