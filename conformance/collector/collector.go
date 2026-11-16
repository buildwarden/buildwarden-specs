// Package collector is the harness's collector: the role that tests a relay
// from the collector's side of seam 2, written from the specifications
// collector-outputs and collector-inputs. It serves every endpoint of both
// for one session, stores what the relay sends, and records each request it
// received and when, so that a case can check what the relay sent and in
// what order. It also serves the bootstrap config a relay carries
// (bootstrap-config), byte for byte as it was given.
//
// A Collector is started in one Form, which says what the session has: a
// token, a build script, a build context, a bootstrap config, and whether
// it keeps serving after its completion. Every combination is a form, so
// that the cases a given collector target cannot run (a 404 from
// GET /v1/bootstrap, a collector with no token, GET /v1/status after a
// completion, the first completion winning) run against this one.
//
// Where the two documents leave a collector's answer open, this one answers
// strictly, and says so at the place in the code: a path with an empty,
// "." or ".." segment is answered 400 before anything else; each endpoint
// takes only the method its document names, and answers 405 to the other of
// COLLOUT-23's pairs; a Warden-Hash trailer the request did not declare is
// not read; a completion that lacks a member, has one that is null, has
// more after its object, or names a member twice or in another case is
// answered 400; and /healthz takes only GET. A body over Limit, or an
// environment payload over 1 MiB, is answered 413 and not stored.
//
// The collector serves on the tunnel, as an http.Handler the claimant
// serves there, or at a base URL of its own through Serve.
package collector

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Limits on what the collector stores. They are constants of a harness
// release.
const (
	// Limit is the largest body the collector stores for an artifact, a
	// capture, the ledger or a piece of the console.
	Limit = 64 << 20
	// EnvironmentLimit is the largest environment payload it stores, the
	// size every collector must accept (COLLOUT-31).
	EnvironmentLimit = 1 << 20
)

// Form is what the session the collector serves has. A nil Script, Context
// or Bootstrap is one the session has not; an empty Token is a session with
// no token.
type Form struct {
	Token string
	// Script is the build script's bytes.
	Script []byte
	// Context is the build context: each file's path, relative to the
	// context's root, and its bytes. Directories are the files' parents.
	// A non-nil empty map is a context with no files.
	Context map[string][]byte
	// Bootstrap is the bootstrap config, served byte for byte.
	Bootstrap []byte
	// ServesAfterCompletion keeps the session served after its first
	// completion. Without it every later request is reset unanswered and
	// Done is closed, as a collector that closes the session's connection
	// at its completion does (COLLOUT-2).
	ServesAfterCompletion bool
}

// Request is one request the collector received, in the order of arrival.
type Request struct {
	// Seq numbers the collector's events: a request's arrival and its end
	// each take the next number, so that one request ended before another
	// began when its End is below the other's Begin.
	Begin, End int
	// BeganAt and EndedAt are when it arrived and when its reply was
	// written, or when it was reset.
	BeganAt, EndedAt time.Time
	Proto            string
	Method           string
	// Path is the request's path as it was sent, before percent-decoding,
	// with its query if it had one.
	Path    string
	Header  http.Header
	Trailer http.Header
	// Body is the body the collector read, up to its limit; the ledger's
	// is in Ledger.
	Body []byte
	// Status is the status the collector answered, or 0 for a request it
	// reset unanswered.
	Status int
}

// Capture is a capture the collector stored.
type Capture struct {
	// Sent is the name the relay sent, percent-decoded, and Name the one
	// it was stored under (COLLOUT-16).
	Sent, Name string
	// Hash is the Warden-Hash trailer as the relay sent it, and BodyHash
	// the BLAKE2b-256 of the body the collector received, in lower-case
	// hexadecimal: the two differ when the relay's statement about the
	// body is wrong (COLLOUT-18).
	Hash, BodyHash string
	Body           []byte
}

// Completion is a completion the collector received.
type Completion struct {
	ExitCode   int64     `json:"exit_code"`
	Message    string    `json:"message"`
	Error      string    `json:"error"`
	ReceivedAt time.Time `json:"-"`
}

// Fault, when it returns a status other than 0, is the collector's answer to
// r in place of the endpoint's, once the token has been checked: the body is
// read and dropped, nothing is stored, and the request is recorded with that
// status. A case sets it to answer an input or an output with a status
// other than 200.
type Fault func(r *http.Request) int

// Collector is the harness's collector, serving one session.
type Collector struct {
	form  Form
	fault Fault

	mu          sync.Mutex
	seq         int
	requests    []*Request
	ledger      []byte
	ledgers     int
	ledgerDone  bool
	environment []byte
	envs        int
	artifacts   map[string][]byte
	captures    []Capture
	output      []byte
	completion  *Completion
	ended       bool
	done        chan struct{}
}

// New is a collector serving one session in form f. fault may be nil.
func New(f Form, fault Fault) *Collector {
	return &Collector{form: f, fault: fault, artifacts: map[string][]byte{}, done: make(chan struct{})}
}

// Form is the form the collector was started in.
func (c *Collector) Form() Form { return c.form }

// Done is closed at the session's first completion when the collector does
// not serve after it: whoever holds the session's connection then closes it.
// It is never closed for a collector that serves after its completion.
func (c *Collector) Done() <-chan struct{} { return c.done }

// Serve serves the collector at l, the base URL being http://<l's address>,
// over HTTP/1.1 and HTTP/2 with prior knowledge, until l is closed.
func (c *Collector) Serve(l net.Listener) error {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: c, Protocols: &p, ReadHeaderTimeout: 10 * time.Second}
	served := make(chan struct{})
	defer close(served)
	go func() {
		select {
		case <-c.done:
			// Let the completion's reply go before the connections close.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			_ = srv.Close()
		case <-served:
		}
	}()
	err := srv.Serve(l)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Requests are the requests received so far, in the order of arrival.
func (c *Collector) Requests() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Request, 0, len(c.requests))
	for _, r := range c.requests {
		out = append(out, *r)
	}
	return out
}

// Ledger is the ledger's bytes received so far, the number of ledger
// requests the session sent, and whether the first one's body has ended.
func (c *Collector) Ledger() (data []byte, requests int, ended bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.ledger), c.ledgers, c.ledgerDone
}

// Environment is the environment payload stored, and how many
// PUT /v1/environment requests the session sent.
func (c *Collector) Environment() (payload []byte, requests int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.environment), c.envs
}

// Artifacts are the artifacts stored, by name; a second artifact under a
// name replaces the first.
func (c *Collector) Artifacts() map[string][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]byte, len(c.artifacts))
	for k, v := range c.artifacts {
		out[k] = bytes.Clone(v)
	}
	return out
}

// Captures are the captures stored, in the order their requests ended.
func (c *Collector) Captures() []Capture {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.captures)
}

// Output is the session's console: its pieces in the order their requests
// ended.
func (c *Collector) Output() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.output)
}

// Completion is the session's first completion, and whether it has had one.
func (c *Collector) Completion() (Completion, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.completion == nil {
		return Completion{}, false
	}
	return *c.completion, true
}

// ServeHTTP serves one request of the session.
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := c.begin(r)
	if rec == nil {
		// The session ended with its completion: reset the request
		// unanswered, as a closed connection would leave it.
		panic(http.ErrAbortHandler)
	}
	status, body := c.serve(&drainingWriter{ResponseWriter: w, body: r.Body}, r)
	if c.end(rec, r, status, body) {
		// The first completion, its reply written: the session ends.
		close(c.done)
	}
}

// drainingWriter reads what is left of the request's body, up to Limit,
// before it writes the reply's header. A refusal is then never written
// while the body, and a capture's trailer, are still on their way: the
// HTTP/2 server of a tunnel takes a trailer that arrives on a stream it has
// answered for an error of the whole connection, and ends the tunnel (the
// disk collector's N32 in collector-outputs). Where the handler has read
// the body, nothing is left to read.
type drainingWriter struct {
	http.ResponseWriter
	body    io.Reader
	drained bool
}

func (d *drainingWriter) WriteHeader(status int) {
	if !d.drained {
		d.drained = true
		_, _ = io.Copy(io.Discard, io.LimitReader(d.body, Limit))
	}
	d.ResponseWriter.WriteHeader(status)
}

func (d *drainingWriter) Write(b []byte) (int, error) {
	if !d.drained {
		d.WriteHeader(http.StatusOK)
	}
	return d.ResponseWriter.Write(b)
}

// begin records r's arrival, or returns nil when the session has ended.
func (c *Collector) begin(r *http.Request) *Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := &Request{
		BeganAt: time.Now(), Proto: r.Proto, Method: r.Method, Path: r.URL.RequestURI(),
		Header: r.Header.Clone(),
	}
	c.seq++
	rec.Begin = c.seq
	c.requests = append(c.requests, rec)
	if c.completion != nil && !c.form.ServesAfterCompletion {
		c.seq++
		rec.End, rec.EndedAt = c.seq, rec.BeganAt
		return nil
	}
	return rec
}

// end records the end of rec, and says whether the session ends with it: it
// was the first completion, and the collector does not serve after it.
func (c *Collector) end(rec *Request, r *http.Request, status int, body []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	rec.End, rec.EndedAt, rec.Status, rec.Body = c.seq, time.Now(), status, body
	rec.Trailer = r.Trailer.Clone()
	ends := c.completion != nil && !c.ended && !c.form.ServesAfterCompletion
	if ends {
		c.ended = true
	}
	return ends
}

// serve answers r and returns the status it answered and the body it read.
func (c *Collector) serve(w http.ResponseWriter, r *http.Request) (int, []byte) {
	raw := r.URL.EscapedPath()
	// Not specified (COLLOUT-12): this collector refuses such a path first.
	if !clean(raw) {
		return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "the path has an empty, . or .. segment\n"), nil
	}
	if raw == "/healthz" {
		if r.Method != http.MethodGet {
			return methodNotAllowed(w, http.MethodGet), nil
		}
		return reply(w, http.StatusOK, "text/plain; charset=utf-8", "ok\n"), nil
	}
	if raw == "/v1/status" {
		return c.status(w, r), nil
	}
	if strings.HasPrefix(raw, "/v1/") && !c.authorized(r) {
		return reply(w, http.StatusUnauthorized, "text/plain; charset=utf-8", "unauthorized\n"), nil
	}
	if c.fault != nil {
		if s := c.fault(r); s != 0 {
			b, _ := readAll(r.Body, Limit)
			return reply(w, s, "text/plain; charset=utf-8", http.StatusText(s)+"\n"), b
		}
	}
	switch {
	case strings.HasPrefix(raw, "/v1/artifacts/"):
		return c.artifact(w, r, strings.TrimPrefix(raw, "/v1/artifacts/"))
	case strings.HasPrefix(raw, "/v1/captures/"):
		return c.capture(w, r, strings.TrimPrefix(raw, "/v1/captures/"))
	case raw == "/v1/ledger":
		return c.ledgerRequest(w, r)
	case raw == "/v1/environment":
		return c.environmentRequest(w, r)
	case raw == "/v1/output":
		return c.outputRequest(w, r)
	case raw == "/v1/build-script":
		return c.input(w, r, c.form.Script, "application/octet-stream"), nil
	case raw == "/v1/bootstrap":
		return c.input(w, r, c.form.Bootstrap, "application/json"), nil
	case strings.HasPrefix(raw, "/v1/context/"):
		return c.context(w, r, strings.TrimPrefix(raw, "/v1/context/")), nil
	case raw == "/v1/ready", raw == "/v1/heartbeat":
		if r.Method != http.MethodPost {
			return methodNotAllowed(w, http.MethodPost), nil
		}
		b, _ := readAll(r.Body, Limit)
		return reply(w, http.StatusOK, "", ""), b
	case raw == "/v1/complete":
		return c.complete(w, r)
	}
	return reply(w, http.StatusNotFound, "text/plain; charset=utf-8", "not a path of the collector protocol\n"), nil
}

// clean says that a raw path has no empty, "." or ".." segment, which a
// relay may not send (COLLOUT-12). The empty last segment of a path that
// ends in "/" is not one.
func clean(raw string) bool {
	segs := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	for i, s := range segs {
		switch s {
		case "":
			if i != len(segs)-1 {
				return false
			}
		case ".", "..":
			return false
		}
	}
	return true
}

// authorized applies the session's token (COLLOUT-5, COLLOUT-7, COLLOUT-8,
// COLLOUT-10): exactly "Bearer <token>", compared in constant time.
func (c *Collector) authorized(r *http.Request) bool {
	if c.form.Token == "" {
		return true
	}
	got := r.Header.Get("Authorization")
	want := "Bearer " + c.form.Token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func reply(w http.ResponseWriter, status int, contentType, body string) int {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
	return status
}

func methodNotAllowed(w http.ResponseWriter, allow string) int {
	w.Header().Set("Allow", allow)
	return reply(w, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", allow+" only\n")
}

var errTooLarge = errors.New("the body is over the collector's limit")

// readAll reads a body of at most limit bytes; a longer one is errTooLarge,
// with what was read.
func readAll(body io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return b, fmt.Errorf("reading the body: %w", err)
	}
	if int64(len(b)) > limit {
		return b[:limit], errTooLarge
	}
	return b, nil
}

// failed answers a body that could not be read whole: 413 over the limit,
// and otherwise 400, the request having ended before its body did.
func failed(w http.ResponseWriter, err error) int {
	if errors.Is(err, errTooLarge) {
		return reply(w, http.StatusRequestEntityTooLarge, "text/plain; charset=utf-8", "the body is over the collector's limit\n")
	}
	return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "the body did not arrive whole\n")
}

// safeName reports whether name is a safe name (COLLOUT-11), and each of
// its segments keeps edge: a predicate of its first and last byte.
func safeName(name string, edge func(first, last byte) bool) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	for _, s := range strings.Split(name, "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
		for i := 0; i < len(s); i++ {
			if !nameByte(s[i]) {
				return false
			}
		}
		if !edge(s[0], s[len(s)-1]) {
			return false
		}
	}
	return true
}

func nameByte(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '.' || b == '_' || b == '-'
}

func alnum(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9'
}

func (c *Collector) artifact(w http.ResponseWriter, r *http.Request, raw string) (int, []byte) {
	if r.Method != http.MethodPut {
		return methodNotAllowed(w, http.MethodPut), nil
	}
	name, err := url.PathUnescape(raw)
	if err != nil || !safeName(name, func(f, l byte) bool { return alnum(f) && alnum(l) }) {
		return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "not a safe artifact name\n"), nil
	}
	b, err := readAll(r.Body, Limit)
	if err != nil {
		return failed(w, err), nil
	}
	c.mu.Lock()
	c.artifacts[name] = b
	c.mu.Unlock()
	return reply(w, http.StatusOK, "", ""), b
}

// captureName is a capture's stored name: every byte outside the name bytes,
// "/" among them, replaced by "_" (COLLOUT-16).
func captureName(sent string) string {
	b := []byte(sent)
	for i, x := range b {
		if !nameByte(x) {
			b[i] = '_'
		}
	}
	return string(b)
}

func (c *Collector) capture(w http.ResponseWriter, r *http.Request, raw string) (int, []byte) {
	if r.Method != http.MethodPut {
		return methodNotAllowed(w, http.MethodPut), nil
	}
	sent, err := url.PathUnescape(raw)
	if err != nil || sent == "" || len(sent) > 255 || strings.Trim(sent, ".") == "" {
		return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "not a capture name\n"), nil
	}
	// Before the body is read, r.Trailer holds the trailers the request
	// declared, and only those. Not specified (COLLOUT-15): an undeclared
	// trailer, which net/http adds over HTTP/1.1, is not read.
	_, declared := r.Trailer["Warden-Hash"]
	b, err := readAll(r.Body, Limit)
	if err != nil {
		return failed(w, err), b
	}
	var hash string
	if declared {
		hash = r.Trailer.Get("Warden-Hash")
	}
	if !hex64(hash) {
		return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "no Warden-Hash trailer of 64 hexadecimal digits\n"), b
	}
	sum := blake2b.Sum256(b)
	c.mu.Lock()
	c.captures = append(c.captures, Capture{Sent: sent, Name: captureName(sent), Hash: hash, BodyHash: hex.EncodeToString(sum[:]), Body: b})
	c.mu.Unlock()
	return reply(w, http.StatusOK, "", ""), b
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		x := s[i]
		if !('0' <= x && x <= '9' || 'a' <= x && x <= 'f' || 'A' <= x && x <= 'F') {
			return false
		}
	}
	return true
}

// ledgerRequest stores the ledger as its bytes arrive, so that a case can
// read it while the request is open (COLLOUT-19, COLLOUT-28).
func (c *Collector) ledgerRequest(w http.ResponseWriter, r *http.Request) (int, []byte) {
	if r.Method != http.MethodPut {
		return methodNotAllowed(w, http.MethodPut), nil
	}
	c.mu.Lock()
	c.ledgers++
	first := c.ledgers == 1
	c.mu.Unlock()
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Body.Read(buf)
		if k > 0 && first {
			n += int64(k)
			if n > Limit {
				return failed(w, errTooLarge), nil
			}
			c.mu.Lock()
			c.ledger = append(c.ledger, buf[:k]...)
			c.mu.Unlock()
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return failed(w, err), nil
		}
	}
	if first {
		c.mu.Lock()
		c.ledgerDone = true
		c.mu.Unlock()
	}
	return reply(w, http.StatusOK, "", ""), nil
}

func (c *Collector) environmentRequest(w http.ResponseWriter, r *http.Request) (int, []byte) {
	if r.Method != http.MethodPut {
		return methodNotAllowed(w, http.MethodPut), nil
	}
	b, err := readAll(r.Body, EnvironmentLimit)
	c.mu.Lock()
	c.envs++
	c.mu.Unlock()
	if err != nil {
		return failed(w, err), b
	}
	c.mu.Lock()
	c.environment = b
	c.mu.Unlock()
	return reply(w, http.StatusOK, "", ""), b
}

// outputRequest appends a piece of the console once its body has ended, so
// that a piece whose request began after another's reply follows it
// (COLLOUT-21).
func (c *Collector) outputRequest(w http.ResponseWriter, r *http.Request) (int, []byte) {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, http.MethodPost), nil
	}
	b, err := readAll(r.Body, Limit)
	if err != nil {
		return failed(w, err), b
	}
	c.mu.Lock()
	c.output = append(c.output, b...)
	c.mu.Unlock()
	return reply(w, http.StatusOK, "", ""), b
}

func (c *Collector) input(w http.ResponseWriter, r *http.Request, body []byte, contentType string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, http.MethodGet)
	}
	if body == nil {
		return reply(w, http.StatusNotFound, "text/plain; charset=utf-8", "the session has none\n")
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return http.StatusOK
}

// context serves the build context (COLLIN-15 to COLLIN-19). The context
// is in memory, so it has no symbolic link to lead out of it.
func (c *Collector) context(w http.ResponseWriter, r *http.Request, raw string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, http.MethodGet)
	}
	if c.form.Context == nil {
		return reply(w, http.StatusNotFound, "text/plain; charset=utf-8", "the session has no build context\n")
	}
	p, err := url.PathUnescape(raw)
	if err != nil {
		return reply(w, http.StatusForbidden, "text/plain; charset=utf-8", "not a safe context path\n")
	}
	dir := strings.HasSuffix(p, "/")
	name := strings.TrimSuffix(p, "/")
	if p != "" && !safeContextPath(name) {
		return reply(w, http.StatusForbidden, "text/plain; charset=utf-8", "not a safe context path\n")
	}
	if b, ok := c.form.Context[name]; ok && name != "" {
		if dir {
			return reply(w, http.StatusNotFound, "text/plain; charset=utf-8", "a file, named with a trailing /\n")
		}
		w.Header().Set("Warden-Context", "file")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return http.StatusOK
	}
	prefix := ""
	if name != "" {
		prefix = name + "/"
	}
	var list []string
	for f := range c.form.Context {
		if strings.HasPrefix(f, prefix) && safeContextPath(f) {
			list = append(list, f)
		}
	}
	if name != "" && len(list) == 0 {
		return reply(w, http.StatusNotFound, "text/plain; charset=utf-8", "nothing in the context has that path\n")
	}
	slices.Sort(list)
	var b strings.Builder
	for _, f := range list {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	w.Header().Set("Warden-Context", "list")
	return reply(w, http.StatusOK, "text/plain", b.String())
}

func safeContextPath(p string) bool {
	return safeName(p, func(_, l byte) bool { return alnum(l) })
}

// complete reads a completion as COLLIN-23 states it, and records the first
// (COLLIN-24).
func (c *Collector) complete(w http.ResponseWriter, r *http.Request) (int, []byte) {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, http.MethodPost), nil
	}
	b, err := readAll(r.Body, Limit)
	if err != nil {
		return failed(w, err), b
	}
	comp, err := parseCompletion(b)
	if err != nil {
		return reply(w, http.StatusBadRequest, "text/plain; charset=utf-8", err.Error()+"\n"), b
	}
	c.mu.Lock()
	first := c.completion == nil
	if first {
		comp.ReceivedAt = time.Now()
		c.completion = &comp
	}
	c.mu.Unlock()
	return reply(w, http.StatusOK, "", ""), b
}

var members = []string{"exit_code", "message", "error"}

// parseCompletion reads a completion's body. Beyond what COLLIN-23 requires
// a collector to refuse, it refuses what the document leaves open: a missing
// or null member, a member named twice or in another case, an exit code with
// a fraction or an exponent or outside int64, and anything after the object.
func parseCompletion(b []byte) (Completion, error) {
	var comp Completion
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return comp, fmt.Errorf("the completion is not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return comp, errors.New("the completion is not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return comp, fmt.Errorf("the completion is not JSON: %w", err)
		}
		key, ok := kt.(string)
		if !ok {
			return comp, errors.New("the completion is not JSON")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return comp, fmt.Errorf("the completion is not JSON: %w", err)
		}
		i := slices.IndexFunc(members, func(m string) bool { return strings.EqualFold(m, key) })
		if i < 0 {
			continue
		}
		if key != members[i] {
			return comp, fmt.Errorf("the member %q is %q in another case", key, members[i])
		}
		if seen[key] {
			return comp, fmt.Errorf("the member %q is given twice", key)
		}
		seen[key] = true
		if string(v) == "null" {
			return comp, fmt.Errorf("the member %q is null", key)
		}
		switch key {
		case "exit_code":
			if bytes.ContainsAny(v, ".eE") {
				return comp, errors.New("exit_code has a fraction or an exponent")
			}
			if err := json.Unmarshal(v, &comp.ExitCode); err != nil {
				return comp, fmt.Errorf("exit_code is not an integer of 64 bits: %w", err)
			}
		case "message":
			if err := json.Unmarshal(v, &comp.Message); err != nil {
				return comp, errors.New("message is not a string")
			}
		case "error":
			if err := json.Unmarshal(v, &comp.Error); err != nil {
				return comp, errors.New("error is not a string")
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return comp, fmt.Errorf("the completion is not JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return comp, errors.New("the completion has more after its object")
	}
	for _, m := range members {
		if !seen[m] {
			return comp, fmt.Errorf("the completion has no member %q", m)
		}
	}
	return comp, nil
}

// status serves GET /v1/status (COLLIN-26), which takes no token.
func (c *Collector) status(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, http.MethodGet)
	}
	comp, ok := c.Completion()
	var body []byte
	if !ok {
		body = []byte(`{"state":"running"}`)
	} else {
		body, _ = json.Marshal(struct {
			ExitCode   int64  `json:"exit_code"`
			Message    string `json:"message"`
			Error      string `json:"error"`
			ReceivedAt string `json:"received_at"`
		}{comp.ExitCode, comp.Message, comp.Error, comp.ReceivedAt.UTC().Format(time.RFC3339Nano)})
	}
	return reply(w, http.StatusOK, "application/json", string(body))
}
