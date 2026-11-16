package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// Origin is one origin server: the name a build asks for and the address it
// serves at. Several origins may share an address; they are told apart by
// the request's Host and, over TLS, by the name the client sent (SNI).
type Origin struct {
	Name string
	Addr netip.Addr
}

// Exchange is one request an origin was sent and the status it answered.
type Exchange struct {
	// Seq is the exchange's place in the order requests came, from 1.
	Seq int
	At  time.Time
	// Origin is the origin's name that the request's Host named, empty for
	// a Host no origin at that address has.
	Origin string
	// Port is 80 or 443; ServerName is the name the client sent at the TLS
	// handshake, empty over HTTP.
	Port       int
	ServerName string
	From       string
	Method     string
	Host       string
	Target     string
	Proto      string
	Header     http.Header
	Body       []byte
	// Status is what the origin answered. The exchange is recorded when
	// the request arrives, and Status is 0 until the handler returns, which
	// may be after the client has read the response.
	Status int
}

// BytesPath is the path prefix at which an origin's default handler serves
// a body of a chosen length: GET /bytes/<n> answers n bytes (Body).
const BytesPath = "/bytes/"

// Body is what an origin's default handler answers to a request for path:
// for BytesPath followed by a decimal n, n bytes of a pattern of the
// origin's name and n; for any other path, the line "<name> <path>". It is
// a pure function, so a case knows the bytes the build should receive.
func Body(name, path string) []byte {
	if s, ok := strings.CutPrefix(path, BytesPath); ok {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			unit := []byte(fmt.Sprintf("%s %d ", name, n))
			return bytes.Repeat(unit, n/len(unit)+1)[:n]
		}
	}
	return []byte(name + " " + path + "\n")
}

// Origins are the harness's origin servers: HTTP on port 80 and TLS on port
// 443 of each origin's address, with leaves from one CA. By default each
// answers every request 200 with Body; a case can give an origin a handler
// of its own. Each records every exchange.
type Origins struct {
	ca      *CA
	origins []Origin

	mu        sync.Mutex
	handlers  map[string]http.Handler
	exchanges []Exchange
	servers   []*http.Server
}

// StartOrigins starts origins on n, with leaves from ca. Each origin's
// address must be in the documentation ranges (CheckAddress), and no name
// may come twice.
func StartOrigins(ctx context.Context, n attach.Network, ca *CA, origins []Origin) (*Origins, error) {
	o := &Origins{ca: ca, origins: slices.Clone(origins), handlers: map[string]http.Handler{}}
	byAddr := map[netip.Addr][]string{}
	var addrs []netip.Addr
	seen := map[string]bool{}
	for _, or := range origins {
		if err := CheckAddress(or.Addr); err != nil {
			return nil, err
		}
		name := strings.ToLower(or.Name)
		if name == "" || seen[name] {
			return nil, fmt.Errorf("upstream: origin name %q is empty or given twice", or.Name)
		}
		seen[name] = true
		if _, ok := byAddr[or.Addr]; !ok {
			addrs = append(addrs, or.Addr)
		}
		byAddr[or.Addr] = append(byAddr[or.Addr], name)
	}
	for _, a := range addrs {
		if err := o.serve(ctx, n, a, byAddr[a]); err != nil {
			_ = o.Close()
			return nil, err
		}
	}
	return o, nil
}

// serve starts HTTP and TLS at addr for the origins named there.
func (o *Origins) serve(ctx context.Context, n attach.Network, addr netip.Addr, names []string) error {
	certs := map[string]*tls.Certificate{}
	for _, name := range names {
		c, err := o.ca.Leaf(name)
		if err != nil {
			return err
		}
		certs[name] = &c
	}
	for _, port := range []int{80, 443} {
		address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
		ln, err := n.Listen(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("upstream: an origin on %s: %w", address, err)
		}
		// An origin's own errors (a handshake for a name it has not) are what
		// a case observes through the protocols, not through a log.
		srv := &http.Server{Handler: o.handler(port, names), ReadHeaderTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
		if port == 443 {
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if c, ok := certs[strings.ToLower(h.ServerName)]; ok {
						return c, nil
					}
					return nil, fmt.Errorf("upstream: no origin named %q at %s", h.ServerName, addr)
				},
			}
			ln = tls.NewListener(ln, srv.TLSConfig)
		}
		o.mu.Lock()
		o.servers = append(o.servers, srv)
		o.mu.Unlock()
		go func() { _ = srv.Serve(ln) }()
	}
	return nil
}

// Handle gives the origin name a handler of its own in place of the
// default, or the default again for nil. The exchange is recorded either
// way, with the status the handler wrote.
func (o *Origins) Handle(name string, h http.Handler) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if h == nil {
		delete(o.handlers, strings.ToLower(name))
		return
	}
	o.handlers[strings.ToLower(name)] = h
}

// Exchanges returns what the origins were sent, in order.
func (o *Origins) Exchanges() []Exchange {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.exchanges)
}

// Close stops every origin server.
func (o *Origins) Close() error {
	o.mu.Lock()
	servers := o.servers
	o.servers = nil
	o.mu.Unlock()
	var errs []error
	for _, s := range servers {
		errs = append(errs, s.Close())
	}
	return errors.Join(errs...)
}

func (o *Origins) handler(port int, names []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading the body: "+err.Error(), http.StatusBadRequest)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)
		ex := Exchange{
			At: time.Now(), Port: port, From: r.RemoteAddr,
			Method: r.Method, Host: r.Host, Target: r.RequestURI, Proto: r.Proto,
			Header: r.Header.Clone(), Body: body,
		}
		if r.TLS != nil {
			ex.ServerName = r.TLS.ServerName
		}
		if slices.Contains(names, host) {
			ex.Origin = host
		}
		rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		o.mu.Lock()
		h := o.handlers[ex.Origin]
		ex.Seq = len(o.exchanges) + 1
		o.exchanges = append(o.exchanges, ex)
		o.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		switch {
		case ex.Origin == "":
			rec.WriteHeader(http.StatusMisdirectedRequest)
			_, _ = io.WriteString(rec, "no origin "+r.Host+" here\n")
		case h != nil:
			h.ServeHTTP(rec, r)
		default:
			b := Body(ex.Origin, r.URL.Path)
			rec.Header().Set("Content-Type", "application/octet-stream")
			rec.Header().Set("Content-Length", strconv.Itoa(len(b)))
			rec.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = rec.Write(b)
			}
		}
		o.mu.Lock()
		o.exchanges[ex.Seq-1].Status = rec.status
		o.mu.Unlock()
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
