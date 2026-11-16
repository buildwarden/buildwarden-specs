package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IdleTimeout is how long the relay keeps a connection of the build
// environment's with no request on it. It is a constant of a harness
// release.
const IdleTimeout = 60 * time.Second

// response is one response the relay sends the build environment: the bytes
// of its status line and header fields, and its body as the build receives
// it. head is what is written and what is recorded, so that the record is
// what was sent (RELAY-02; the Go relay's differs, N20).
type response struct {
	status  int
	head    []byte
	body    []byte
	chunked bool
	// close says that the connection is closed after the response: the
	// request or the response said so, or the body ends at the close.
	close bool
}

// own is a response of the relay's own making, framed by its length.
func own(req *http.Request, status int, ctype string, body []byte) response {
	h := http.Header{}
	if ctype != "" {
		h.Set("Content-Type", ctype)
	}
	if status != http.StatusNoContent && status != http.StatusNotModified {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if req.Close {
		h.Set("Connection", "close")
	}
	return response{status: status, head: head(status, http.StatusText(status), h), body: body, close: req.Close}
}

// refusal is one of relay-guest-api's refusals: text/plain and a body of one
// line (GUEST-56).
func refusalOf(req *http.Request, status int, line string) response {
	return own(req, status, "text/plain", []byte(line+"\n"))
}

// head is a status line and header fields, the fields in the order of their
// names.
func head(status int, text string, h http.Header) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %03d %s\r\n", status, text)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// write sends rp: its head, then its body, chunked when the upstream's was.
func (rp response) write(w *bufio.Writer, method string) error {
	if _, err := w.Write(rp.head); err != nil {
		return err
	}
	if method != http.MethodHead {
		switch {
		case rp.chunked && len(rp.body) > 0:
			fmt.Fprintf(w, "%x\r\n", len(rp.body))
			_, _ = w.Write(rp.body)
			_, _ = w.WriteString("\r\n0\r\n\r\n")
		case rp.chunked:
			_, _ = w.WriteString("0\r\n\r\n")
		default:
			_, _ = w.Write(rp.body)
		}
	}
	return w.Flush()
}

// serveTLS terminates TLS with a leaf for the name the client sent
// (GUEST-42), and serves the requests inside as on port 80. A client that
// sends no name, which relay-guest-api leaves undefined, fails the
// handshake.
func (g *Guest) serveTLS(c net.Conn) {
	ca := g.session.CA()
	var sni string
	tc := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				return nil, errors.New("the client sent no server name")
			}
			sni = hello.ServerName
			return ca.Leaf(hello.ServerName)
		},
	})
	_ = c.SetDeadline(time.Now().Add(HandshakeTimeout))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	g.serveHTTP(tc, sni)
}

// serveHTTP serves the HTTP/1.x requests of one connection, in origin and
// absolute form (GUEST-41), each routed by its target host (GUEST-17). sni
// is the name the client sent over TLS, and empty over HTTP.
func (g *Guest) serveHTTP(c net.Conn, sni string) {
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(IdleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
				var ne net.Error
				if !errors.As(err, &ne) {
					_ = refusalOf(&http.Request{Close: true}, http.StatusBadRequest, "malformed request").write(bw, "")
				}
			}
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		rp := g.route(req, sni)
		if err := rp.write(bw, req.Method); err != nil {
			return
		}
		// What is left of the request's body is read before the next
		// request; a body too long to drop ends the connection.
		n, _ := io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
		if rp.close || n == 1<<20 {
			return
		}
	}
}

// route serves one request by its target host: artifacts, cwd for a GET,
// and every other host proxied (GUEST-17). Over TLS it is the request that
// decides, not the name sent at the handshake.
func (g *Guest) route(req *http.Request, sni string) response {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch reservedName(host) {
	case "artifacts":
		return g.serveArtifacts(req, schemeOf(sni))
	case "cwd":
		if req.Method == http.MethodGet {
			return g.serveCwd(req, schemeOf(sni))
		}
		// relay-guest-api lets a relay answer cwd for another method as it
		// will; this one refuses it rather than send a reserved name
		// upstream (the Go relay proxies it, D10).
		return refusalOf(req, http.StatusMethodNotAllowed, "GET only")
	}
	return g.proxy(req, sni)
}

// requestHead is the request's header block as the relay read it, which it
// records: its request line, Host, and its fields in the order of their
// names.
func requestHead(req *http.Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", req.Method, req.RequestURI, req.Proto)
	h := req.Header.Clone()
	if req.Host != "" {
		h.Set("Host", req.Host)
	}
	if len(req.TransferEncoding) > 0 {
		h.Set("Transfer-Encoding", strings.Join(req.TransferEncoding, ", "))
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// recorded is the request as the ledger's open record names it: its
// absolute URL and its protocol.
func recorded(req *http.Request, scheme string) Request {
	u := req.URL.String()
	if !req.URL.IsAbs() {
		u = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	return Request{Method: req.Method, URL: u, Protocol: req.Proto, Header: requestHead(req)}
}

func schemeOf(sni string) string {
	if sni != "" {
		return "https"
	}
	return "http"
}

// hopByHop are the header fields that concern one connection and are not
// sent upstream (RFC 9110, section 7.6.1).
var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// proxy sends req to its host and answers with the upstream's response
// unchanged (GUEST-41, GUEST-43, GUEST-44), or 502 (GUEST-46), and records
// the exchange as sent (GUEST-49). Over TLS it goes to the name the client
// sent, over HTTPS on port 443, with the request's Host unchanged; over HTTP
// to the host and port the request names, port 80 when it names none.
func (g *Guest) proxy(req *http.Request, sni string) response {
	s := g.session
	s.Activity()
	if s.Completed() {
		return refusalOf(req, http.StatusConflict, "the build has completed")
	}
	if req.Method == http.MethodConnect {
		// Not defined by relay-guest-api; this relay opens no tunnel.
		return refusalOf(req, http.StatusMethodNotAllowed, "CONNECT is not served")
	}
	var body []byte
	if req.ContentLength != 0 {
		b, err := io.ReadAll(io.LimitReader(req.Body, RequestBodyLimit+1))
		if err != nil {
			rp := refusalOf(req, http.StatusBadRequest, "the request's body did not arrive whole")
			rp.close = true
			return rp
		}
		if len(b) > RequestBodyLimit {
			rp := refusalOf(req, http.StatusRequestEntityTooLarge, "request body too large")
			rp.close = true
			return rp
		}
		body = b
	}
	scheme, hostport := "http", req.Host
	switch {
	case sni != "":
		scheme, hostport = "https", net.JoinHostPort(sni, "443")
	case req.URL.IsAbs():
		scheme = req.URL.Scheme
		if scheme != "http" && scheme != "https" {
			return refusalOf(req, http.StatusBadRequest, "the target's scheme is neither http nor https")
		}
	}
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		hostport = net.JoinHostPort(strings.Trim(hostport, "[]"), port)
	}
	out := &http.Request{
		Method: req.Method,
		URL: &url.URL{Scheme: scheme, Host: hostport, Path: req.URL.Path, RawPath: req.URL.RawPath,
			RawQuery: req.URL.RawQuery},
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        req.Header.Clone(),
		Host:          req.Host,
		ContentLength: int64(len(body)),
	}
	for _, f := range req.Header.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			out.Header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHop {
		out.Header.Del(name)
	}
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
	}
	ctx, cancel := context.WithTimeout(g.ctx, UpstreamTimeout)
	defer cancel()
	rp, err := g.roundTrip(out.WithContext(ctx), req)
	if err != nil {
		s.relay.logf("proxy %s %s: %v", req.Method, hostport, err)
		rp = refusalOf(req, http.StatusBadGateway, "upstream unreachable")
	}
	x := Exchange{Request: recorded(req, schemeOf(sni)), Body: body, Status: rp.status, ResponseHeader: rp.head, ResponseBody: rp.body}
	if _, err := s.Exchange(g.ctx, x); err != nil {
		if errors.Is(err, ErrCompleted) {
			return refusalOf(req, http.StatusConflict, "the build has completed")
		}
		s.relay.logf("recording %s %s: %v", req.Method, x.URL, err)
	}
	return rp
}

// roundTrip makes the upstream exchange and reads its whole response: the
// header fields and body as the upstream sent them, the framing kept as it
// was where the body has a length or is chunked.
func (g *Guest) roundTrip(out, req *http.Request) (response, error) {
	resp, err := g.upstream.RoundTrip(out)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, ResponseBodyLimit+1))
	if err != nil {
		return response{}, fmt.Errorf("the upstream's body: %w", err)
	}
	if len(body) > ResponseBodyLimit {
		return response{}, fmt.Errorf("the upstream's body is over %d bytes", ResponseBodyLimit)
	}
	h := resp.Header.Clone()
	rp := response{status: resp.StatusCode, body: body}
	noBody := req.Method == http.MethodHead || resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified
	switch {
	case noBody:
	case len(resp.TransferEncoding) > 0:
		h.Set("Transfer-Encoding", "chunked")
		h.Del("Content-Length")
		rp.chunked = true
	case resp.ContentLength >= 0:
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	default:
		// The body ends at the close: the relay closes the connection
		// after it, as RFC 9112 has it (the Go relay keeps it open, N17).
		rp.close = true
	}
	if req.Close || headerHas(h, "Connection", "close") {
		rp.close = true
	}
	if rp.close && !headerHas(h, "Connection", "close") {
		// relay-guest-api lets the relay add it (GUEST-44, GUEST-47).
		h.Add("Connection", "close")
	}
	text := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	rp.head = head(resp.StatusCode, text, h)
	return rp, nil
}
