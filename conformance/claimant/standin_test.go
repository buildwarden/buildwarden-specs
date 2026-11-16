package claimant

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// standIn is a stand-in for a relay's claim endpoint and its tunnel: just
// enough of relay-claim's relay to claim, and of the collector protocol's
// relay side to drive the harness's collector over the tunnel. It is not the
// harness's relay model, which is task 15's, and asserts nothing itself: it
// records what the claimant sent for the tests to check.
type standIn struct {
	t     *testing.T
	token string
	ln    net.Listener
	srv   *http.Server

	mu       sync.Mutex
	tunnelRq *http.Request
	claimRq  *http.Request
	claim    []byte
	tunnel   *http.Client
	claimed  bool
	answer   func(w http.ResponseWriter, r *http.Request) bool
	ledgerW  *io.PipeWriter
	ledgerRp chan error
	ready    chan struct{}
}

// standInKey is the stand-in's ledger key, as a claim's reply names it.
var standInKey = strings.Repeat("ab", 32)

func newStandIn(t *testing.T, token string) *standIn {
	t.Helper()
	ln, err := attach.Host(netip.MustParseAddr("127.0.0.1")).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{t: t, token: token, ln: ln, ready: make(chan struct{})}
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	t.Cleanup(func() {
		s.mu.Lock()
		if s.ledgerW != nil {
			_ = s.ledgerW.Close()
		}
		s.mu.Unlock()
		_ = s.srv.Close()
	})
	return s
}

func (s *standIn) endpoint() attach.Endpoint {
	return attach.Endpoint{Address: s.ln.Addr().String(), Token: s.token}
}

func (s *standIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	answer := s.answer
	s.mu.Unlock()
	if answer != nil && answer(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.token != "" && r.Header.Get("Authorization") != "Bearer "+s.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v1/tunnel":
		s.serveTunnel(w, r)
	case "/v1/claim":
		s.serveClaim(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *standIn) serveTunnel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel != nil || s.claimed {
		http.Error(w, "tunnel already open", http.StatusConflict)
		return
	}
	s.tunnelRq = r.Clone(context.Background())
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.t.Errorf("hijacking the tunnel: %v", err)
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: warden-tunnel\r\n\r\n"); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		s.t.Errorf("writing the 101: %v", err)
		return
	}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	used := false
	var conns sync.Mutex
	s.tunnel = &http.Client{Transport: &http.Transport{
		Protocols: &p,
		// One connection: a request made while it is being set up waits
		// for it rather than dialling another.
		MaxConnsPerHost: 1,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			conns.Lock()
			defer conns.Unlock()
			if used {
				return nil, errors.New("the tunnel is one connection")
			}
			used = true
			return &bufConn{Conn: conn, r: rw.Reader}, nil
		},
	}}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (s *standIn) serveClaim(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.claimed {
		s.mu.Unlock()
		http.Error(w, "already claimed", http.StatusConflict)
		return
	}
	s.claimRq = r.Clone(context.Background())
	tunnel := s.tunnel
	s.mu.Unlock()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid claim: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.claim = body
	s.mu.Unlock()
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		http.Error(w, "invalid claim: "+err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.CollectorURL != TunnelURL || tunnel == nil {
		http.Error(w, "invalid claim: collector_url selects the tunnel, but none is open", http.StatusBadRequest)
		return
	}
	// The relay's side of the session's start: the ledger request first,
	// the environment, then ready before the claim's reply.
	pr, pw := io.Pipe()
	rq, _ := http.NewRequest(http.MethodPut, TunnelURL+"/v1/ledger", pr)
	s.authorize(rq, cfg.CollectorToken)
	done := make(chan error, 1)
	go func() {
		resp, err := tunnel.Do(rq)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("the ledger was answered %d", resp.StatusCode)
			}
		}
		done <- err
	}()
	if _, err := pw.Write([]byte("BLDL\x01")); err != nil {
		http.Error(w, "relay start failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg.Environment != nil {
		if code, err := s.do(tunnel, cfg.CollectorToken, http.MethodPut, "/v1/environment", cfg.Environment.Payload); err != nil || code != http.StatusOK {
			http.Error(w, fmt.Sprintf("relay start failed: environment: %d %v", code, err), http.StatusInternalServerError)
			return
		}
	}
	_, _ = s.do(tunnel, cfg.CollectorToken, http.MethodPost, "/v1/ready", nil)
	s.mu.Lock()
	s.claimed, s.ledgerW, s.ledgerRp = true, pw, done
	s.mu.Unlock()
	close(s.ready)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Identity{CACert: testCA(s.t), LedgerPublicKey: standInKey})
}

func (s *standIn) authorize(r *http.Request, token string) {
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
}

func (s *standIn) do(c *http.Client, token, method, path string, body []byte) (int, error) {
	r, err := http.NewRequest(method, TunnelURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	s.authorize(r, token)
	resp, err := c.Do(r)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// send is a request of the relay's side on the tunnel, once the claim has
// been answered.
func (s *standIn) send(r *http.Request) (*http.Response, []byte, error) {
	<-s.ready
	s.mu.Lock()
	c := s.tunnel
	s.mu.Unlock()
	resp, err := c.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// endLedger ends the ledger request's body and waits for its reply.
func (s *standIn) endLedger(more []byte) error {
	<-s.ready
	s.mu.Lock()
	w, done := s.ledgerW, s.ledgerRp
	s.mu.Unlock()
	if _, err := w.Write(more); err != nil {
		return err
	}
	_ = w.Close()
	return <-done
}

var (
	caOnce sync.Once
	caPEM  string
)

// testCA is a CA certificate for the stand-in's reply. Its key is random,
// and nothing the tests check depends on it.
func testCA(t *testing.T) string {
	caOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stand-in CA"},
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Error(err)
			return
		}
		caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	})
	return caPEM
}
