// Package relay is the harness's relay, written from the specifications
// relay-claim, collector-outputs, collector-inputs, relay-guest-api and
// bootstrap-config: the relay's side of the claim and of the collector
// protocol, and its build side. It is what tests a collector, a collector
// that claims reaching it at a claim address, and it is itself a role under
// test, which the relay suites run against under go test through the
// harness's in-process attachment (package inprocess), once in each mode.
//
// A Relay serves the claim endpoint with its token, accepts one tunnel and
// one claim, and answers every refusal relay-claim gives. A claim it
// accepts starts a Session: the ledger request first, the environment
// landed and recorded, the build's CA, the build side's start, ready, and
// then the claim's 200 naming the CA and the ledger's key, a key of its own
// for each instance. The Session then sends what the build does (the
// artifacts, the captures of the exchanges it proxies, the console, the
// inputs it asks for, the heartbeat) and, at the completion, ends the
// ledger before it sends the completion.
//
// Where the documents leave a relay's answer open, or let it be lenient,
// this one is strict, and says so at the place in the code:
//
//   - The claim's body is refused 400 for a member named twice, a member
//     named as a field in another case, a member that is null, anything
//     after the object, and line breaks in base64 (CLAIM-18; the Go relay
//     accepts each, N7).
//   - A capture_mode that is none of the four, and an upstream_ca_certs
//     entry that holds no certificate, are refused 400 (the Go relay
//     accepts them, D5).
//   - The environment's metadata must be one CBOR map, untagged, its keys
//     given once (CLAIM-28; the Go relay takes null, undefined, a tag and a
//     repeated key, N8).
//   - A tunnel request without Connection: Upgrade and
//     Upgrade: warden-tunnel is answered 400 and does not use the relay's
//     one tunnel (CLAIM-12; the Go relay answers 101, D7).
//   - The token is accepted only as "Bearer <token>" (CLAIM-8; D8, N26).
//   - A claim's body is read for at most ClaimBodyTimeout, after which it is
//     refused 400 and the claim released (the Go relay waits for as long as
//     the connection lasts, N9).
//   - A collector's redirect is its reply: it is not followed (N13), so only
//     the collector's own 200 is an output stored or an input.
//   - A refused artifact's channel is closed with no payload (N25).
//
// The ledger's reply is not waited for before the claim's 200 (CLAIM-23,
// CLAIM-44), as the Go relay's is not (N5): a collector that refuses the
// ledger still sees the claim answered 200.
//
// The build side is a Guest, which takes the relay's mode as a start
// parameter: host on a frame link, through a network stack of its own that
// captures a connection to any address and port; vm and container on a
// kernel interface, here a network the caller gives, with its ports at its
// own address. It serves the lease, ARP on a frame link, DNS, the reserved
// hosts artifacts and cwd, the control plane, and the proxy and
// interception, and records what relay-guest-api has it record. Where that
// document leaves the answer open, this relay is strict here too:
//
//   - The reserved names are read whatever their case and with a trailing
//     dot (the Go relay matches them exactly, N23); cwd for any method but
//     GET is refused 405, not proxied (D10).
//   - A fixed path of artifacts is served for its one method and answered
//     404 for another (the Go relay serves it whatever the method, D9).
//   - An exit code that is not a signed 64-bit decimal integer is refused
//     400 (the Go relay reads it as 0 or its leading integer, N21).
//   - The output that crosses the 256 MiB limit is answered 413 (D11).
//   - Every response is recorded as the bytes sent: the 502 has a length,
//     and an upstream's header fields are written as recorded (N20).
//   - A response that ends at the close, or says Connection: close, closes
//     the connection after it (N17).
//   - After the completion, a request it would record is refused 409, and
//     nothing is recorded or sent upstream (GUEST-55; D18).
//   - It serves DNS over TCP on a frame link (GUEST-6 lets it; D15), and
//     its lease and its listeners are serving before the claim's 200 in
//     every mode (D19).
//   - A refused claim leaves it claimable in every mode (D17).
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/ledgerwriter"
)

// The relay's bounds on its claim endpoint. They are constants of a harness
// release.
const (
	// HeaderTimeout bounds the reading of a request's header fields.
	HeaderTimeout = 10 * time.Second
	// ClaimBodyTimeout bounds the reading of a claim's body.
	ClaimBodyTimeout = 30 * time.Second
	// LogLimit is how much of the relay's log is kept: the last LogLimit
	// bytes.
	LogLimit = 1 << 20
)

// Build is the relay's build side, which the claim configures and starts.
// The relay calls Configure once a claim's fields are valid and its
// resolvers known, and Start once the session has its ledger, its
// environment and its CA, before ready.
type Build interface {
	// Configure applies the claim's build link. An error made by Refused
	// answers the claim 400 and leaves the relay claimable; any other
	// error fails the start.
	Configure(ctx context.Context, c *Claim) error
	// Start starts the build-facing listeners for s; an error fails the
	// start.
	Start(ctx context.Context, s *Session) error
}

// Config is what a relay is started with.
type Config struct {
	// Net is the claim side, where the claim endpoint listens, at Address
	// (host:port; empty is Net's own address and a port of the network's
	// choosing).
	Net     attach.Network
	Address string
	// Token is the claim token; empty is a relay with none (CLAIM-9).
	Token string
	// Upstream is where the relay dials a collector at a base URL and its
	// resolvers; nil is a relay that has none.
	Upstream attach.Network
	// ResolvConf is what stands for the relay's platform resolver
	// configuration, its nameservers in order (CLAIM-32); nil is one that
	// cannot be read.
	ResolvConf []netip.Addr
	// Own are the relay's own addresses, which its resolvers leave out
	// (CLAIM-32), beside its claim address and its build link's relay.
	Own []netip.Addr
	// Build is the build side; nil is a relay with none, as a relay that
	// tests a collector has.
	Build Build
	// Log, when set, also receives the relay's log.
	Log io.Writer
}

// Relay is one instance of the harness's relay. It implements
// attach.Instance.
type Relay struct {
	cfg      Config
	ln       net.Listener
	srv      *http.Server
	endpoint attach.Endpoint
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	tunnel     *http.Client
	tunnelConn net.Conn
	processing bool
	session    *Session
	exit       string
	claimed    chan struct{}
	done       chan struct{}
	served     chan struct{}
	stopOnce   sync.Once
	log        logBuffer
}

// Start starts a relay and its claim endpoint.
func Start(ctx context.Context, cfg Config) (*Relay, error) {
	if cfg.Net == nil {
		return nil, errors.New("relay: no claim network")
	}
	addr := cfg.Address
	if addr == "" {
		addr = netip.AddrPortFrom(cfg.Net.Address(), 0).String()
	}
	ln, err := cfg.Net.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("relay: the claim endpoint: %w", err)
	}
	rctx, cancel := context.WithCancel(context.Background())
	r := &Relay{
		cfg: cfg, ln: ln, ctx: rctx, cancel: cancel,
		endpoint: attach.Endpoint{Address: ln.Addr().String(), Token: cfg.Token},
		claimed:  make(chan struct{}), done: make(chan struct{}), served: make(chan struct{}),
	}
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: HeaderTimeout}
	go func() {
		defer close(r.served)
		_ = r.srv.Serve(ln)
	}()
	return r, nil
}

// Claim is the relay's claim endpoint and its token.
func (r *Relay) Claim() attach.Endpoint { return r.endpoint }

// Frames is an error: the relay holds its own end of a frame link, and its
// attachment the harness's end (GUEST-6).
func (r *Relay) Frames() (net.Conn, error) {
	return nil, fmt.Errorf("relay: the harness's end of the frame link is its attachment's: %w", attach.ErrNoFrames)
}

// ReadBack is an error: a relay stores nothing to read back.
func (r *Relay) ReadBack(context.Context) (string, error) {
	return "", errors.New("relay: a relay has no read-back")
}

// Log is what the relay logged.
func (r *Relay) Log() []byte { return r.log.Bytes() }

// Exit is how the relay ended, or empty while it runs.
func (r *Relay) Exit() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exit
}

// Done is closed when the relay has ended: stopped, or spent by a start
// that failed (CLAIM-50).
func (r *Relay) Done() <-chan struct{} { return r.done }

// Session waits for the relay's claim to succeed, and returns its session.
func (r *Relay) Session(ctx context.Context) (*Session, error) {
	select {
	case <-r.claimed:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.session, nil
	case <-r.done:
		return nil, fmt.Errorf("relay: ended unclaimed: %s", r.Exit())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Stop ends the relay and what its session holds.
func (r *Relay) Stop() error {
	r.end("stopped")
	r.mu.Lock()
	s := r.session
	r.mu.Unlock()
	if s != nil {
		s.close()
	}
	<-r.served
	return nil
}

// end ends the relay with why, the first time: it accepts no connection and
// no claim after it.
func (r *Relay) end(why string) {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.exit = why
		conn := r.tunnelConn
		r.mu.Unlock()
		r.logf("relay ended: %s", why)
		if conn != nil {
			// A relay that ends closes its tunnel with it.
			_ = conn.Close()
		}
		_ = r.ln.Close()
		_ = r.srv.Close()
		r.cancel()
		close(r.done)
	})
}

func (r *Relay) logf(format string, a ...any) {
	line := time.Now().UTC().Format(time.RFC3339Nano) + " " + fmt.Sprintf(format, a...) + "\n"
	_, _ = r.log.Write([]byte(line))
	if r.cfg.Log != nil {
		_, _ = io.WriteString(r.cfg.Log, line)
	}
}

// refuse answers a refusal as text/plain, its reason on one line (CLAIM-51).
func refuse(w http.ResponseWriter, status int, reason string) {
	reason = strings.NewReplacer("\r", " ", "\n", " ").Replace(reason)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A length, so that a refusal flushed before the relay ends is whole.
	w.Header().Set("Content-Length", strconv.Itoa(len(reason)+1))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, reason+"\n")
}

// ServeHTTP serves the claim endpoint. It looks at a request's method, then
// its token, then the relay's state, and only then its body (CLAIM-42).
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if path != "/v1/tunnel" && path != "/v1/claim" {
		refuse(w, http.StatusNotFound, "404 page not found")
		return
	}
	if req.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if !r.authorized(req) {
		refuse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if path == "/v1/tunnel" {
		r.serveTunnel(w, req)
		return
	}
	r.serveClaim(w, req)
}

// authorized applies the claim token (CLAIM-5, CLAIM-6, CLAIM-8, CLAIM-9):
// exactly "Bearer <token>", compared in constant time.
func (r *Relay) authorized(req *http.Request) bool {
	if r.cfg.Token == "" {
		return true
	}
	got := req.Header.Get("Authorization")
	want := "Bearer " + r.cfg.Token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// hasTunnel says whether the relay has accepted its tunnel.
func (r *Relay) hasTunnel() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tunnel != nil
}

// serveTunnel accepts the relay's one tunnel (CLAIM-12, CLAIM-15).
func (r *Relay) serveTunnel(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if r.tunnel != nil || r.processing || r.session != nil {
		r.mu.Unlock()
		refuse(w, http.StatusConflict, "tunnel already open")
		return
	}
	if !headerHas(req.Header, "Connection", "upgrade") || !strings.EqualFold(req.Header.Get("Upgrade"), "warden-tunnel") {
		r.mu.Unlock()
		// Not specified (CLAIM-12): this relay refuses a request that does
		// not ask for the upgrade, and keeps its tunnel for one that does.
		refuse(w, http.StatusBadRequest, "the tunnel needs Connection: Upgrade and Upgrade: warden-tunnel")
		return
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		r.mu.Unlock()
		refuse(w, http.StatusInternalServerError, "the tunnel could not be taken: "+err.Error())
		return
	}
	r.tunnel, r.tunnelConn = tunnelClient(conn, rw.Reader), conn
	r.mu.Unlock()
	_ = conn.SetDeadline(time.Time{})
	_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: warden-tunnel\r\n\r\n")
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		// The tunnel stays the relay's one: a relay need not notice that
		// its tunnel has closed (CLAIM-15).
		r.logf("the tunnel's 101 was not written: %v", err)
		return
	}
	r.logf("tunnel accepted from %s", conn.RemoteAddr())
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// serveClaim answers one claim (CLAIM-17 to CLAIM-53).
func (r *Relay) serveClaim(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if r.processing || r.session != nil {
		r.mu.Unlock()
		refuse(w, http.StatusConflict, "already claimed")
		return
	}
	r.processing = true
	r.mu.Unlock()
	accepted := false
	defer func() {
		if !accepted {
			r.mu.Lock()
			r.processing = false
			r.mu.Unlock()
		}
	}()

	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(ClaimBodyTimeout))
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxClaim+1))
	if err != nil {
		refuse(w, http.StatusBadRequest, "invalid claim: the body did not arrive whole: "+err.Error())
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	c, err := decode(body, r.hasTunnel())
	var ref *refusal
	if errors.As(err, &ref) {
		r.logf("claim refused: %s", ref.reason)
		refuse(w, http.StatusBadRequest, ref.reason)
		return
	}
	own := append([]netip.Addr{r.cfg.Net.Address()}, r.cfg.Own...)
	if c.BuildLink != nil {
		own = append(own, c.BuildLink.Relay)
	}
	if c.Resolvers, err = resolvers(c, r.cfg.ResolvConf, own); err != nil {
		errors.As(err, &ref)
		r.logf("claim refused: %s", ref.reason)
		refuse(w, http.StatusBadRequest, ref.reason)
		return
	}
	if r.cfg.Build != nil {
		if err := r.cfg.Build.Configure(r.ctx, c); err != nil {
			if errors.As(err, &ref) {
				r.logf("claim refused: %s", ref.reason)
				refuse(w, http.StatusBadRequest, ref.reason)
				return
			}
			r.fail(w, fmt.Errorf("the build link: %w", err))
			return
		}
	}
	accepted = true
	s, err := r.start(c)
	if err != nil {
		r.fail(w, err)
		return
	}
	id, err := json.Marshal(struct {
		CACert          string `json:"ca_cert"`
		LedgerPublicKey string `json:"ledger_public_key"`
	}{string(s.ca.PEM), hex.EncodeToString(s.PublicKey())})
	if err != nil {
		r.fail(w, err)
		return
	}
	r.mu.Lock()
	r.session = s
	r.processing = false
	r.mu.Unlock()
	// The endpoint stops accepting connections once it has answered 200
	// (CLAIM-47); a claim on a connection already open is answered 409
	// (CLAIM-46). The tunnel was taken from the server and stays open.
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(id)
	_ = http.NewResponseController(w).Flush()
	_ = r.ln.Close()
	r.srv.SetKeepAlivesEnabled(false)
	r.logf("claimed: collector %s, capture %s", c.CollectorURL, c.CaptureMode)
	close(r.claimed)
}

// fail answers a start that failed and spends the relay (CLAIM-50).
func (r *Relay) fail(w http.ResponseWriter, err error) {
	w.Header().Set("Connection", "close")
	refuse(w, http.StatusInternalServerError, "relay start failed: "+err.Error())
	_ = http.NewResponseController(w).Flush()
	r.end("spent: relay start failed: " + err.Error())
}

// start starts the session of an accepted claim, in the order of CLAIM-44:
// the ledger request, the environment landed and recorded, the CA, the
// build side, and ready.
func (r *Relay) start(c *Claim) (*Session, error) {
	ctx := r.ctx
	s := &Session{
		relay: r, claim: c, base: TunnelURL,
		ledgerDone: make(chan struct{}), beat: make(chan struct{}), beatDone: make(chan struct{}), done: make(chan struct{}),
	}
	if c.Tunnel() {
		r.mu.Lock()
		s.client = r.tunnel
		r.mu.Unlock()
	} else {
		client, base, err := baseClient(c.CollectorURL, r.cfg.Upstream, c)
		if err != nil {
			return nil, err
		}
		s.client, s.base = client, base
	}
	var envType string
	if c.Environment != nil {
		var err error
		if envType, err = environmentType(c.Environment); err != nil {
			return nil, err
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("the ledger's key: %w", err)
	}
	s.key = key
	if err := s.openLedger(ctx, envType); err != nil {
		return nil, err
	}
	fail := func(err error) (*Session, error) {
		s.close()
		return nil, err
	}
	if env := c.Environment; env != nil {
		if err := s.landEnvironment(ctx, env, envType); err != nil {
			return fail(err)
		}
	}
	if s.ca, err = newCA(); err != nil {
		return fail(err)
	}
	if r.cfg.Build != nil {
		if err := r.cfg.Build.Start(ctx, s); err != nil {
			return fail(fmt.Errorf("the build side: %w", err))
		}
	}
	// A failed ready does not fail the claim (CLAIM-44, COLLIN-33).
	_, _ = s.signal(ctx, "/v1/ready", nil)
	go s.heartbeat(ctx)
	return s, nil
}

// landEnvironment sends the environment payload to the collector, and
// records it once the collector holds it (CLAIM-28, COLLOUT-27).
func (s *Session) landEnvironment(ctx context.Context, env *Environment, envType string) error {
	r, err := s.request(ctx, http.MethodPut, "/v1/environment", strings.NewReader(string(env.Payload)))
	if err != nil {
		return err
	}
	rep, err := s.send(r)
	if err != nil {
		return fmt.Errorf("PUT /v1/environment: %w", err)
	}
	if rep.Status != http.StatusOK {
		return fmt.Errorf("PUT /v1/environment: the collector answered %d", rep.Status)
	}
	ch, err := s.ledger.Open(ledgerwriter.Environment, map[string]any{"type": "environment"})
	if err != nil {
		return err
	}
	return s.ledger.Close(ch, ledgerwriter.Out(env.Payload), ledgerwriter.Environment, map[string]any{"type": envType})
}

// logBuffer keeps the last LogLimit bytes written to it.
type logBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	if over := len(l.b) - LogLimit; over > 0 {
		l.b = append(l.b[:0], l.b[over:]...)
	}
	return len(p), nil
}

func (l *logBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b...)
}

var _ attach.Instance = (*Relay)(nil)
