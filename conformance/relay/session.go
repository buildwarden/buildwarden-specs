package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/buildwarden/buildwarden-specs/conformance/ledgerwriter"
)

// The relay's own bounds on the collector. They are constants of a harness
// release.
const (
	// SignalTimeout bounds the wait for a signal's reply (COLLIN-33).
	SignalTimeout = 15 * time.Second
	// InputTimeout bounds the fetch of an input.
	InputTimeout = 5 * time.Minute
	// HeartbeatEvery is the heartbeat's beat, and HeartbeatActive how
	// recent the build's last activity must be for a beat to send one
	// (COLLIN-30).
	HeartbeatEvery  = 2 * time.Second
	HeartbeatActive = 4 * time.Second
	// LedgerSettle is how long the relay waits after the ledger request's
	// first bytes have gone before it sends another request.
	LedgerSettle = 50 * time.Millisecond
)

// ErrCompleted is the error for an output or a record after the session's
// completion: nothing is recorded or sent after it.
var ErrCompleted = errors.New("the session has completed")

// Reply is the collector's answer to a request of the session.
type Reply struct {
	Status int
	Header http.Header
	Body   []byte
}

// Session is the relay's side of the collector protocol for the build it
// was claimed for: the client of collector-outputs and collector-inputs,
// and the ledger it signs. The build side and a case that tests
// a collector both drive it through these methods.
type Session struct {
	relay  *Relay
	claim  *Claim
	client *http.Client
	base   string
	key    ed25519.PrivateKey
	ca     *CA

	ledger     *ledgerwriter.Writer
	stream     *stream
	ledgerDone chan struct{}
	ledgerRep  *Reply
	ledgerErr  error

	mu        sync.Mutex
	completed bool
	captures  int
	activity  time.Time
	outputs   sync.WaitGroup
	beat      chan struct{}
	beatDone  chan struct{}
	done      chan struct{}
	beats     int
}

// Claim is the claim the session was started with.
func (s *Session) Claim() *Claim { return s.claim }

// PublicKey is the key the ledger is signed with, which the claim's reply
// names.
func (s *Session) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// CA is the certificate authority the relay created for the build.
func (s *Session) CA() *CA { return s.ca }

// Ledger is the session's ledger writer, for the records of the build side.
func (s *Session) Ledger() *ledgerwriter.Writer { return s.ledger }

// Token is the collector token the relay sends (CLAIM-24).
func (s *Session) Token() string { return s.claim.CollectorToken }

// Done is closed once the session's first completion has been sent.
func (s *Session) Done() <-chan struct{} { return s.done }

// LedgerReply is the collector's reply to PUT /v1/ledger, or the request's
// failure; done is false while it has neither.
func (s *Session) LedgerReply() (rep *Reply, done bool, err error) {
	select {
	case <-s.ledgerDone:
		return s.ledgerRep, true, s.ledgerErr
	default:
		return nil, false, nil
	}
}

// request makes a request of the session: the path appended to the base
// URL, and the token when the claim has one (COLLOUT-4, COLLOUT-9).
func (s *Session) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return nil, err
	}
	if s.claim.CollectorToken != "" {
		r.Header.Set("Authorization", "Bearer "+s.claim.CollectorToken)
	}
	return r, nil
}

func (s *Session) send(r *http.Request) (*Reply, error) {
	resp, err := s.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the reply to %s %s: %w", r.Method, r.URL.Path, err)
	}
	return &Reply{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

// Do sends one request of the caller's own making to the collector, once:
// path is appended to the base URL as it is given, header and trailer are
// sent as they are, and the token is not added. A case that tests a
// collector sends what a relay may not with it.
func (s *Session) Do(ctx context.Context, method, path string, header http.Header, body io.Reader, trailer http.Header) (*Reply, error) {
	r, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return nil, err
	}
	if header != nil {
		r.Header = header.Clone()
	}
	if trailer != nil {
		r.Trailer = trailer.Clone()
		r.ContentLength = -1
	}
	return s.send(r)
}

// escapeName percent-encodes each segment of a name (COLLOUT-12), and
// refuses a name with an empty, "." or ".." segment, which no relay may
// send. keepSlash keeps a trailing "/", which a context path may have.
func escapeName(name string, keepSlash bool) (string, error) {
	trail := ""
	if keepSlash && strings.HasSuffix(name, "/") {
		name, trail = strings.TrimSuffix(name, "/"), "/"
	}
	if name == "" {
		return trail, nil
	}
	segs := strings.Split(name, "/")
	for i, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("the name %q has an empty, . or .. segment, which a relay may not send", name)
		}
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/") + trail, nil
}

// begin starts an output of the session, which Complete waits for.
func (s *Session) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return ErrCompleted
	}
	s.outputs.Add(1)
	return nil
}

// Activity is the build's activity, which keeps the heartbeat beating
// (COLLIN-30).
func (s *Session) Activity() {
	s.mu.Lock()
	s.activity = time.Now()
	s.mu.Unlock()
}

// Completed says whether the build has completed: from then on nothing is
// recorded or sent but a repeated completion (GUEST-55).
func (s *Session) Completed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// Heartbeats is the number of heartbeats sent so far.
func (s *Session) Heartbeats() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beats
}

// Request is a request of the build, as the ledger records its opening and
// its header fields.
type Request struct {
	Method   string
	URL      string
	Protocol string
	// Header is the request's header fields, as raw bytes.
	Header []byte
}

func (r Request) openMeta() map[string]any {
	return map[string]any{"method": r.Method, "url": r.URL, "protocol": r.Protocol}
}

// Artifact streams body to the collector as the artifact name
// (PUT /v1/artifacts/<name>) and records it, for the build's request req:
// the exchange's opening and header fields, then an artifact record once the
// collector has answered 200. When it has not, the channel is closed with no
// payload, so that the ledger has no open channel and nothing is recorded
// as stored (the Go relay leaves the channel open, N25). It returns the
// collector's reply and the number of bytes streamed.
func (s *Session) Artifact(ctx context.Context, req Request, name string, body io.Reader) (*Reply, int64, error) {
	if err := s.begin(); err != nil {
		return nil, 0, err
	}
	defer s.outputs.Done()
	path, err := escapeName(name, false)
	if err != nil {
		return nil, 0, err
	}
	ch, err := s.ledger.Open(ledgerwriter.HTTPOpen, req.openMeta())
	if err != nil {
		return nil, 0, err
	}
	if err := s.ledger.Checkpoint(ch, ledgerwriter.Out(req.Header), ledgerwriter.HTTPHeaders, headerMeta(req.Header)); err != nil {
		return nil, 0, err
	}
	h := ledgerwriter.NewHash()
	r, err := s.request(ctx, http.MethodPut, "/v1/artifacts/"+path, io.TeeReader(body, h))
	if err != nil {
		return nil, 0, err
	}
	r.ContentLength = -1
	rep, err := s.send(r)
	if err == nil && rep.Status == http.StatusOK {
		err = s.ledger.Artifact(ch, h.Payload(true), ledgerwriter.ArtifactMeta, map[string]any{"name": name, "context": map[string]any{}})
		return rep, h.Len(), err
	}
	if cerr := s.ledger.Close(ch, ledgerwriter.Payload{}, ledgerwriter.None, nil); err == nil {
		err = cerr
	}
	return rep, h.Len(), err
}

// Exchange is an exchange the relay proxied for the build: the request,
// its body (nil for none), and the response the build was sent.
type Exchange struct {
	Request
	Body           []byte
	Status         int
	ResponseHeader []byte
	ResponseBody   []byte
}

// CaptureResult is a capture the relay sent, and the collector's answer.
type CaptureResult struct {
	Name  string
	Reply *Reply
	Err   error
}

// Exchange records x as the ledger format's HTTP mapping lays it out (a
// request with a body as the POST's, one without as the GET's), and then
// sends the captures the claim's capture mode asks for (CLAIM-25): the two
// header blocks for headers, the bodies for bodies, and all four for all.
// A capture the collector does not store is the relay's to log
// (COLLOUT-25); it does not fail the exchange.
func (s *Session) Exchange(ctx context.Context, x Exchange) ([]CaptureResult, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.outputs.Done()
	if err := s.record(x); err != nil {
		return nil, err
	}
	type part struct {
		name string
		body []byte
	}
	var parts []part
	mode := s.claim.CaptureMode
	if mode == CaptureHeaders || mode == CaptureAll {
		parts = append(parts, part{"request-headers", x.Header}, part{"response-headers", x.ResponseHeader})
	}
	if mode == CaptureBodies || mode == CaptureAll {
		if x.Body != nil {
			parts = append(parts, part{"request-body", x.Body})
		}
		parts = append(parts, part{"response-body", x.ResponseBody})
	}
	s.mu.Lock()
	s.captures++
	n := s.captures
	s.mu.Unlock()
	var out []CaptureResult
	for _, p := range parts {
		name := fmt.Sprintf("%06d-%s-%s", n, x.Method, p.name)
		rep, err := s.capture(ctx, name, p.body)
		if err == nil && rep.Status != http.StatusOK {
			s.relay.logf("capture %s: the collector answered %d", name, rep.Status)
		} else if err != nil {
			s.relay.logf("capture %s: %v", name, err)
		}
		out = append(out, CaptureResult{Name: name, Reply: rep, Err: err})
	}
	return out, nil
}

// Record records x as Exchange does and sends no capture: what the relay
// serves the build from its collector (the build script, the bootstrap
// config, a file of the context), which is an input recorded as the body of
// a GET's response and not a proxied exchange (relay-guest-api, GUEST-49;
// relay-claim, CLAIM-25).
func (s *Session) Record(x Exchange) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.outputs.Done()
	return s.record(x)
}

// record writes x's records: its opening, its request's header fields and
// body, and its response's header fields, and closes it with the
// response's body.
func (s *Session) record(x Exchange) error {
	l := s.ledger
	ch, err := l.Open(ledgerwriter.HTTPOpen, x.openMeta())
	if err != nil {
		return err
	}
	steps := []func() error{
		func() error {
			return l.Checkpoint(ch, ledgerwriter.Out(x.Header), ledgerwriter.HTTPHeaders, headerMeta(x.Header))
		},
	}
	if x.Body != nil {
		steps = append(steps, func() error {
			return l.Checkpoint(ch, ledgerwriter.Out(x.Body), ledgerwriter.HTTPBody, nil)
		})
	}
	steps = append(steps,
		func() error {
			return l.Checkpoint(ch, ledgerwriter.In(x.ResponseHeader), ledgerwriter.HTTPHeaders, headerMeta(x.ResponseHeader))
		},
		func() error {
			return l.Close(ch, ledgerwriter.In(x.ResponseBody), ledgerwriter.HTTPBody, map[string]any{"status": int64(x.Status)})
		})
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// capture sends one capture: no length in advance, and the trailer
// Warden-Hash, declared, holding the BLAKE2b-256 of the body (COLLOUT-18).
func (s *Session) capture(ctx context.Context, name string, body []byte) (*Reply, error) {
	path, err := escapeName(name, false)
	if err != nil {
		return nil, err
	}
	r, err := s.request(ctx, http.MethodPut, "/v1/captures/"+path, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, err
	}
	sum := blake2b.Sum256(body)
	r.ContentLength = -1
	r.Trailer = http.Header{"Warden-Hash": {hex.EncodeToString(sum[:])}}
	return s.send(r)
}

// Output sends a piece of the build's console (POST /v1/output).
func (s *Session) Output(ctx context.Context, piece []byte) (*Reply, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.outputs.Done()
	r, err := s.request(ctx, http.MethodPost, "/v1/output", bytes.NewReader(piece))
	if err != nil {
		return nil, err
	}
	return s.send(r)
}

// Input is an input the relay fetched for the build. Only a 200 is the
// input; any other status, or Err, is its absence (COLLIN-28).
type Input struct {
	Reply *Reply
	Err   error
	// List is set for a context path the collector answered with a
	// listing (COLLIN-29).
	List bool
}

// OK says whether the collector gave the input.
func (in Input) OK() bool { return in.Err == nil && in.Reply.Status == http.StatusOK }

func (s *Session) input(ctx context.Context, path string) Input {
	ctx, cancel := context.WithTimeout(ctx, InputTimeout)
	defer cancel()
	r, err := s.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return Input{Err: err}
	}
	rep, err := s.send(r)
	if err != nil {
		return Input{Err: err}
	}
	return Input{Reply: rep, List: rep.Status == http.StatusOK && rep.Header.Get("Warden-Context") == "list"}
}

// BuildScript fetches the build script (GET /v1/build-script).
func (s *Session) BuildScript(ctx context.Context) Input { return s.input(ctx, "/v1/build-script") }

// Bootstrap fetches the bootstrap config (GET /v1/bootstrap).
func (s *Session) Bootstrap(ctx context.Context) Input { return s.input(ctx, "/v1/bootstrap") }

// Context fetches a context path, as the build gave it with its trailing
// "/" when it has one (COLLIN-29); the empty path is the root.
func (s *Session) Context(ctx context.Context, path string) Input {
	p, err := escapeName(path, true)
	if err != nil {
		return Input{Err: err}
	}
	return s.input(ctx, "/v1/context/"+p)
}

// signal sends a signal with no body and reads 200 or 204 as delivered
// (COLLIN-33), waiting at most SignalTimeout.
func (s *Session) signal(ctx context.Context, path string, body []byte) (*Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, SignalTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := s.request(ctx, http.MethodPost, path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	rep, err := s.send(r)
	if err == nil && rep.Status != http.StatusOK && rep.Status != http.StatusNoContent {
		err = fmt.Errorf("the collector answered %d", rep.Status)
	}
	if err != nil {
		s.relay.logf("POST %s not delivered: %v", path, err)
	}
	return rep, err
}

// heartbeat beats every HeartbeatEvery and sends a heartbeat when the
// build's last activity is less than HeartbeatActive old. A beat that comes
// while the previous heartbeat's reply is awaited is missed (COLLIN-30).
func (s *Session) heartbeat(ctx context.Context) {
	defer close(s.beatDone)
	t := time.NewTicker(HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-s.beat:
			return
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			active := !s.activity.IsZero() && now.Sub(s.activity) < HeartbeatActive
			s.mu.Unlock()
			if active {
				_, _ = s.signal(ctx, "/v1/heartbeat", nil)
				s.mu.Lock()
				s.beats++
				s.mu.Unlock()
			}
		}
	}
}

// Completion is the body of POST /v1/complete (COLLIN-32).
type Completion struct {
	ExitCode int64  `json:"exit_code"`
	Message  string `json:"message"`
	Error    string `json:"error"`
}

// Complete completes the build. The first call stops the heartbeat, waits
// for every output already begun to be answered, ends the ledger and waits
// for its request's reply or failure, and only then sends the completion
// (COLLOUT-29, COLLIN-35). A later call sends the completion again, which a
// relay may (COLLIN-32). The relay does not depend on the reply
// (COLLIN-34): it is returned for the caller to log.
func (s *Session) Complete(ctx context.Context, c Completion) (*Reply, error) {
	s.mu.Lock()
	first := !s.completed
	s.completed = true
	s.mu.Unlock()
	if first {
		close(s.beat)
		<-s.beatDone
		s.outputs.Wait()
		if err := s.ledger.End(); err != nil {
			s.relay.logf("the ledger: %v", err)
		}
		s.stream.Close()
		select {
		case <-s.ledgerDone:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	rep, err := s.signal(ctx, "/v1/complete", body)
	if first {
		close(s.done)
	}
	return rep, err
}

// openLedger opens PUT /v1/ledger with the ledger's header in its body, and
// returns once the request's header fields have been written, so that it is
// the session's first request (COLLOUT-26), or the request has failed. Its
// reply is not waited for (CLAIM-23).
func (s *Session) openLedger(ctx context.Context, envType string) error {
	s.stream = newStream()
	w, err := ledgerwriter.New(s.stream, s.key, envType)
	if err != nil {
		return err
	}
	s.ledger = w
	r, err := s.request(ctx, http.MethodPut, "/v1/ledger", s.stream)
	if err != nil {
		return err
	}
	r.ContentLength = -1
	wrote := make(chan struct{})
	var once sync.Once
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		WroteHeaders: func() { once.Do(func() { close(wrote) }) },
	}))
	go func() {
		defer close(s.ledgerDone)
		s.ledgerRep, s.ledgerErr = s.send(r)
		if s.ledgerErr == nil && s.ledgerRep.Status != http.StatusOK {
			s.relay.logf("PUT /v1/ledger: the collector answered %d", s.ledgerRep.Status)
		} else if s.ledgerErr != nil {
			s.relay.logf("PUT /v1/ledger: %v", s.ledgerErr)
		}
	}()
	select {
	case <-wrote:
		// The ledger's header fields are on the wire before any other
		// request's. A collector over HTTP/2 starts a handler for each
		// stream on a goroutine of its own, so this relay also lets the
		// header's bytes go and gives the collector LedgerSettle before
		// its next request, so that the ledger request is seen first
		// there too.
		s.stream.drained(ctx, LedgerSettle)
		return nil
	case <-s.ledgerDone:
		if s.ledgerErr != nil {
			return fmt.Errorf("opening the ledger: %w", s.ledgerErr)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// close ends what the session holds when the relay stops.
func (s *Session) close() {
	s.mu.Lock()
	first := !s.completed
	s.completed = true
	s.mu.Unlock()
	if first && s.beat != nil {
		close(s.beat)
	}
	if s.stream != nil {
		s.stream.Close()
	}
	s.client.CloseIdleConnections()
}

// stream is the ledger request's body: what the writer writes is kept until
// the transport reads it, so a write never waits on the collector.
type stream struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newStream() *stream {
	s := &stream{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("the ledger request has ended")
	}
	s.buf = append(s.buf, p...)
	s.cond.Broadcast()
	return len(p), nil
}

func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// drained returns once what was written has been read, or the request has
// ended, and then waits settle; it gives up at ctx's end.
func (s *stream) drained(ctx context.Context, settle time.Duration) {
	for {
		s.mu.Lock()
		empty := len(s.buf) == 0 || s.closed
		s.mu.Unlock()
		if empty {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(settle):
	}
}

// Close ends the body once what was written has been read.
func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cond.Broadcast()
	return nil
}

// standard are the header fields the http-headers metadata leaves out:
// those of the HTTP/1.1 and HTTP/2 base specifications, which are in the
// payload's raw bytes.
var standard = map[string]bool{}

func init() {
	for _, h := range strings.Fields(`Accept Accept-Charset Accept-Encoding Accept-Language Accept-Ranges
		Age Allow Cache-Control Connection Content-Encoding Content-Language Content-Length
		Content-Location Content-Range Content-Type Date ETag Expect Expires From Host If-Match
		If-Modified-Since If-None-Match If-Range If-Unmodified-Since Keep-Alive Last-Modified Location
		Max-Forwards Pragma Proxy-Authenticate Range Referer Retry-After Server TE Trailer
		Transfer-Encoding Upgrade User-Agent Vary Via Warning WWW-Authenticate`) {
		standard[http.CanonicalHeaderKey(h)] = true
	}
}

var redacted = map[string]bool{"Authorization": true, "Cookie": true, "Set-Cookie": true, "Proxy-Authorization": true}

// headerMeta is the http-headers metadata of a raw header block: its
// non-standard fields in order, the credentials' values redacted.
func headerMeta(raw []byte) map[string]any {
	headers := [][]string{}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		line = strings.TrimRight(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			continue
		}
		key := http.CanonicalHeaderKey(strings.TrimSpace(name))
		switch {
		case redacted[key]:
			headers = append(headers, []string{key, "<redacted>"})
		case !standard[key]:
			headers = append(headers, []string{key, strings.TrimSpace(value)})
		}
	}
	return map[string]any{"headers": headers}
}
