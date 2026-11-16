// Package claimant is the harness's claimant: the role that claims a relay
// under test, written from the specification relay-claim. It opens the
// tunnel and serves the collector protocol on it, sends the claim, and reads
// the reply; and it sends requests of a case's own making to the claim
// endpoint, which the cases for refusals need.
//
// Every request goes on a connection of its own, which the claimant opens
// through the attachment's network: the relay never opens one to it
// (CLAIM-1). OpenTunnel and Claim retry a connection that fails before the
// relay answers, every RetryEvery until RetryLimit, since a relay may still
// be starting (CLAIM-3); a reply, whatever its status, is final and not
// retried (CLAIM-35). Do sends once.
package claimant

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
)

// TunnelURL is the collector_url that selects the tunnel (CLAIM-22).
const TunnelURL = "http://collector.tunnel"

// The claimant's own numbers for reaching a relay that is still starting
// (CLAIM-3). They are constants of a harness release.
const (
	RetryEvery = 250 * time.Millisecond
	RetryLimit = 30 * time.Second
)

// MaxClaim is the largest claim body a claimant may send (CLAIM-52).
const MaxClaim = 16 << 20

// Config is a claim, as a claimant sends it (relay-claim, Messages and
// fields). Fields with no value are left out (CLAIM-20).
type Config struct {
	CollectorURL     string       `json:"collector_url"`
	CollectorToken   string       `json:"collector_token,omitempty"`
	CaptureMode      string       `json:"capture_mode,omitempty"`
	UpstreamCACerts  []string     `json:"upstream_ca_certs,omitempty"`
	UpstreamSystemCA *bool        `json:"upstream_system_ca,omitempty"`
	Environment      *Environment `json:"environment,omitempty"`
	BuildLink        *BuildLink   `json:"build_link,omitempty"`
	UpstreamDNS      []string     `json:"upstream_dns,omitempty"`
}

// Environment is the claim's environment; its byte strings are written in
// standard base64 with padding.
type Environment struct {
	Type     string `json:"type,omitempty"`
	Payload  []byte `json:"payload"`
	Metadata []byte `json:"metadata"`
}

// BuildLink is the claim's build_link.
type BuildLink struct {
	Prefix string `json:"prefix"`
	Relay  string `json:"relay"`
	Guest  string `json:"guest"`
}

// Claimant claims one relay at its claim endpoint.
type Claimant struct {
	// Net is where the claimant dials, the attachment's claim side.
	Net attach.Network
	// Endpoint is the relay's claim endpoint and the token it was started
	// with; an empty token sends no Authorization header.
	Endpoint attach.Endpoint
}

// Reply is the relay's answer to a request the claimant sent.
type Reply struct {
	Status int
	Header http.Header
	Body   []byte
}

// Identity is a 200 reply's body (CLAIM-33).
type Identity struct {
	CACert          string `json:"ca_cert"`
	LedgerPublicKey string `json:"ledger_public_key"`
}

// Identity reads a 200 reply's identity: the CA certificate it parses and
// the ledger key. A 200 whose ca_cert is absent or empty is a failed claim
// (CLAIM-34), as is one this claimant cannot read; members it does not know
// are ignored.
func (r *Reply) Identity() (Identity, *x509.Certificate, []byte, error) {
	var id Identity
	if r.Status != http.StatusOK {
		return id, nil, nil, fmt.Errorf("the claim was answered %d, not 200: %q", r.Status, r.Body)
	}
	if err := json.Unmarshal(r.Body, &id); err != nil {
		return id, nil, nil, fmt.Errorf("the claim's 200 is not a JSON object of the identity: %w", err)
	}
	if id.CACert == "" {
		return id, nil, nil, errors.New("the claim's 200 has no ca_cert")
	}
	block, _ := pem.Decode([]byte(id.CACert))
	if block == nil || block.Type != "CERTIFICATE" {
		return id, nil, nil, errors.New("the claim's ca_cert holds no PEM certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return id, nil, nil, fmt.Errorf("the claim's ca_cert: %w", err)
	}
	key, err := ledger.ParseKey(id.LedgerPublicKey)
	if err != nil {
		return id, nil, nil, fmt.Errorf("the claim's ledger_public_key: %w", err)
	}
	return id, ca, key, nil
}

func (c Claimant) authorize(h http.Header) {
	if c.Endpoint.Token != "" {
		h.Set("Authorization", "Bearer "+c.Endpoint.Token)
	}
}

// Claim sends cfg as the claim (CLAIM-17).
func (c Claimant) Claim(ctx context.Context, cfg Config) (*Reply, error) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encoding the claim: %w", err)
	}
	return c.ClaimBody(ctx, body)
}

// ClaimBody sends body as the claim, byte for byte, so that a case can send
// one a claimant may not.
func (c Claimant) ClaimBody(ctx context.Context, body []byte) (*Reply, error) {
	h := http.Header{"Content-Type": {"application/json"}}
	c.authorize(h)
	var rep *Reply
	err := c.retry(ctx, func(conn net.Conn) (bool, error) {
		r, answered, err := roundTrip(conn, http.MethodPost, "/v1/claim", h, body)
		rep = r
		return answered, err
	})
	return rep, err
}

// Do sends one request of the case's own making, method and path with the
// header h and body, on a connection of its own, once, and returns the
// relay's reply. The claim token is not added: h carries what the case
// sends.
func (c Claimant) Do(ctx context.Context, method, path string, h http.Header, body []byte) (*Reply, error) {
	conn, err := c.Net.Dial(ctx, "tcp", c.Endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("dialling the claim endpoint %s: %w", c.Endpoint.Address, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	rep, _, err := roundTrip(conn, method, path, h, body)
	return rep, err
}

// retry dials the claim endpoint and runs try on the connection until try
// says the relay answered, or the limit passes. Only a failure before the
// relay answered is retried.
func (c Claimant) retry(ctx context.Context, try func(net.Conn) (answered bool, err error)) error {
	deadline := time.Now().Add(RetryLimit)
	for {
		conn, err := c.Net.Dial(ctx, "tcp", c.Endpoint.Address)
		if err == nil {
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			var answered bool
			answered, err = try(conn)
			stop()
			if answered || err == nil {
				return err
			}
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the claim endpoint %s: %w", c.Endpoint.Address, ctx.Err())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the claim endpoint %s did not answer within %s: %w", c.Endpoint.Address, RetryLimit, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the claim endpoint %s: %w", c.Endpoint.Address, ctx.Err())
		case <-time.After(RetryEvery):
		}
	}
}

// roundTrip writes one HTTP/1.1 request on conn and reads its reply.
// answered is false when the connection failed before any reply arrived.
func roundTrip(conn net.Conn, method, path string, h http.Header, body []byte) (rep *Reply, answered bool, err error) {
	br, err := send(conn, method, path, h, body)
	if err != nil {
		return nil, false, err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, br.Buffered() > 0, fmt.Errorf("reading the reply to %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, fmt.Errorf("reading the reply to %s %s: %w", method, path, err)
	}
	return &Reply{Status: resp.StatusCode, Header: resp.Header, Body: b}, true, nil
}

// send writes a request with a Content-Length, and no other header than h
// and Host, and returns the reader of the connection's replies.
func send(conn net.Conn, method, path string, h http.Header, body []byte) (*bufio.Reader, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, conn.RemoteAddr())
	if h.Get("Content-Length") == "" {
		fmt.Fprintf(&b, "Content-Length: %s\r\n", strconv.Itoa(len(body)))
	}
	if err := h.Write(&b); err != nil {
		return nil, fmt.Errorf("writing %s %s: %w", method, path, err)
	}
	b.WriteString("\r\n")
	b.Write(body)
	if _, err := conn.Write(b.Bytes()); err != nil {
		return nil, fmt.Errorf("writing %s %s: %w", method, path, err)
	}
	return bufio.NewReader(conn), nil
}

// Tunnel is an open tunnel: the connection on which the claimant serves the
// collector protocol to the relay, as the HTTP/2 server (CLAIM-13).
type Tunnel struct {
	srv    *http.Server
	conn   *tunnelConn
	closed chan struct{}
	served chan struct{}
}

// ErrRefused is wrapped by OpenTunnel's error when the relay answered the
// tunnel request other than 101; the error's Reply is that answer.
var ErrRefused = errors.New("the relay refused the tunnel")

// RefusedError is OpenTunnel's error for a relay that answered other than
// 101.
type RefusedError struct{ Reply *Reply }

func (e *RefusedError) Error() string {
	return fmt.Sprintf("%v: %d %q", ErrRefused, e.Reply.Status, e.Reply.Body)
}

// Unwrap makes the error ErrRefused.
func (e *RefusedError) Unwrap() error { return ErrRefused }

// OpenTunnel sends POST /v1/tunnel (CLAIM-11) and, on its 101, serves h on
// the connection as an HTTP/2 server with prior knowledge from then on
// (CLAIM-14). It returns once the 101 has been read (CLAIM-43). An answer
// other than 101 is a *RefusedError.
func (c Claimant) OpenTunnel(ctx context.Context, h http.Handler) (*Tunnel, error) {
	hdr := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"warden-tunnel"}}
	c.authorize(hdr)
	var t *Tunnel
	err := c.retry(ctx, func(conn net.Conn) (bool, error) {
		br, err := send(conn, http.MethodPost, "/v1/tunnel", hdr, nil)
		if err != nil {
			return false, err
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return br.Buffered() > 0, fmt.Errorf("reading the reply to the tunnel: %w", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			_ = conn.Close()
			return true, &RefusedError{Reply: &Reply{Status: resp.StatusCode, Header: resp.Header, Body: b}}
		}
		t = serveTunnel(&tunnelConn{Conn: conn, r: br}, h)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Served is what a tunnel serves for a session: the collector protocol,
// and the end of the session, at which the tunnel closes. The harness's
// collector is one.
type Served interface {
	http.Handler
	// Done is closed when the session's connection is to close.
	Done() <-chan struct{}
}

// OpenTunnelFor opens a tunnel that serves coll, and closes it at coll's
// Done: the session's connection ends with its completion when the
// collector does not serve after it.
func (c Claimant) OpenTunnelFor(ctx context.Context, coll Served) (*Tunnel, error) {
	t, err := c.OpenTunnel(ctx, coll)
	if err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-coll.Done():
			t.shutdown()
		case <-t.closed:
		}
	}()
	return t, nil
}

func serveTunnel(conn *tunnelConn, h http.Handler) *Tunnel {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	t := &Tunnel{
		srv:    &http.Server{Handler: h, Protocols: &p},
		conn:   conn,
		closed: make(chan struct{}),
		served: make(chan struct{}),
	}
	conn.closed = t.closed
	go func() {
		defer close(t.served)
		_ = t.srv.Serve(&oneConn{conn: conn, closed: t.closed, stop: make(chan struct{})})
	}()
	return t
}

// shutdown closes the tunnel once the replies being written have gone, or
// after ShutdownGrace: a request that arrives meanwhile is refused.
func (t *Tunnel) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownGrace)
	defer cancel()
	_ = t.srv.Shutdown(ctx)
	_ = t.Close()
}

// ShutdownGrace is how long a tunnel closed at a session's end gives the
// replies being written.
const ShutdownGrace = 2 * time.Second

// Closed is closed once the tunnel's connection has closed, by either end.
func (t *Tunnel) Closed() <-chan struct{} { return t.closed }

// Close closes the tunnel's connection and waits for its server to stop.
func (t *Tunnel) Close() error {
	err := t.srv.Close()
	_ = t.conn.Close()
	<-t.served
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// tunnelConn is the tunnel's connection, read through the reader that read
// the 101, which may already hold the relay's first HTTP/2 bytes.
type tunnelConn struct {
	net.Conn
	r      *bufio.Reader
	once   sync.Once
	closed chan struct{}
}

func (c *tunnelConn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if err != nil {
		c.markClosed()
	}
	return n, err
}

func (c *tunnelConn) Close() error {
	c.markClosed()
	return c.Conn.Close()
}

func (c *tunnelConn) markClosed() {
	c.once.Do(func() { close(c.closed) })
}

// oneConn is a listener that accepts the tunnel's connection once, and then
// waits until it closes.
type oneConn struct {
	mu     sync.Mutex
	conn   net.Conn
	closed chan struct{}
	stop   chan struct{}
	once   sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	select {
	case <-l.closed:
	case <-l.stop:
	}
	return nil, net.ErrClosed
}

// Close stops Accept, as http.Server.Close waits for it to return.
func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.stop) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tunnel" }
func (dummyAddr) String() string  { return "collector.tunnel" }

// Session is a claimant in front of the harness's collector, as a collector
// target that claims is: it opens the tunnel serving coll, then claims the
// relay with cfg, whose collector_url it sets to the tunnel's.
func (c Claimant) Session(ctx context.Context, coll Served, cfg Config) (*Tunnel, *Reply, error) {
	t, err := c.OpenTunnelFor(ctx, coll)
	if err != nil {
		return nil, nil, err
	}
	cfg.CollectorURL = TunnelURL
	rep, err := c.Claim(ctx, cfg)
	if err != nil {
		_ = t.Close()
		return nil, nil, err
	}
	return t, rep, nil
}
