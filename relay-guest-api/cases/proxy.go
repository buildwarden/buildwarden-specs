package cases

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The cases of the proxy and interception (GUEST-41 to GUEST-47), the
// certificate authority (GUEST-48), what the relay records (GUEST-49,
// GUEST-50) and the refusals' form (GUEST-56). Each claims a relay of its
// own.

// crlURL is the CRL distribution point every leaf names (GUEST-42).
const crlURL = "http://artifacts/ca.crl"

// exchangesFor are the origin's exchanges whose request named target.
func exchangesFor(up *upstream.Upstream, target string) []upstream.Exchange {
	var out []upstream.Exchange
	for _, x := range up.Origins.Exchanges() {
		if x.Target == target {
			out = append(out, x)
		}
	}
	return out
}

// proxiedHTTP: on port 80 a request for another host, in origin form or
// absolute form, over HTTP/1.1 or HTTP/1.0, is proxied to that host over
// HTTP on port 80, and the build gets the origin's answer.
var proxiedHTTP = runner.Case{
	Name:  "on port 80 a request for another host, in origin or absolute form, over HTTP/1.1 or HTTP/1.0, is proxied to it over HTTP",
	Cites: []string{"GUEST-41"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		body := pattern(20000, 51)
		for _, c := range []struct{ what, target, req string }{
			{"an origin-form GET", "/origin-form", request(http.MethodGet, "/origin-form", originName, nil)},
			{"a GET for " + originName + ":80", "/with-port", request(http.MethodGet, "/with-port", originName+":80", nil)},
			{"an absolute-form GET", "/absolute", request(http.MethodGet, "http://"+originName+"/absolute", "elsewhere.example", nil)},
			{"an HTTP/1.0 GET", "/one-oh", "GET /one-oh HTTP/1.0\r\nHost: " + originName + "\r\n\r\n"},
			{"a POST with a body", "/posted?x=1", request(http.MethodPost, "/posted?x=1", originName, body, "Content-Type: application/octet-stream")},
		} {
			rep := w.send(80, "", c.req)
			path, _, _ := strings.Cut(c.target, "?")
			expect(t, c.what, rep, http.StatusOK, "", upstream.Body(originName, path))
			xs := exchangesFor(w.up, c.target)
			if len(xs) != 1 {
				t.Errorf("%s: the origin received %d requests for %s, want 1", c.what, len(xs), c.target)
				continue
			}
			x := xs[0]
			if x.Port != 80 || x.ServerName != "" || x.Origin != originName {
				t.Errorf("%s reached the origin on port %d (TLS name %q) for %q, want port 80 over HTTP for %s", c.what, x.Port, x.ServerName, x.Host, originName)
			}
			if strings.HasPrefix(c.req, http.MethodPost) && (x.Method != http.MethodPost || !bytes.Equal(x.Body, body)) {
				t.Errorf("%s reached the origin as %s with a body of %d bytes, want POST with the build's %d", c.what, x.Method, len(x.Body), len(body))
			}
		}
	},
}

// leafChecked checks the chain the relay presented for sni against
// GUEST-42: the leaf signed by ca and followed by it, sni its one subject
// alternative name, server authentication, the CRL distribution point, and
// valid with ca from the claim's 200 until 24 hours after it was sent.
func leafChecked(t *runner.T, w *web, sni string, chain []*x509.Certificate) {
	if len(chain) < 2 {
		t.Errorf("the relay presented %d certificates for %s, want the leaf and then its CA", len(chain), sni)
		return
	}
	leaf := chain[0]
	if !chain[1].Equal(w.ca) {
		t.Errorf("the certificate after the leaf for %s is %q, not the claim's ca_cert", sni, chain[1].Subject)
	}
	if err := leaf.CheckSignatureFrom(w.ca); err != nil {
		t.Errorf("the leaf for %s is not signed by the claim's ca_cert: %v", sni, err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != sni || len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) > 0 {
		t.Errorf("the leaf for %s names %v, %v, %v and %v, want %s as its one DNS name", sni, leaf.DNSNames, leaf.IPAddresses, leaf.URIs, leaf.EmailAddresses, sni)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Errorf("the leaf for %s does not allow server authentication: %v", sni, leaf.ExtKeyUsage)
	}
	if !slices.Equal(leaf.CRLDistributionPoints, []string{crlURL}) {
		t.Errorf("the leaf for %s names the CRL distribution points %q, want %s", sni, leaf.CRLDistributionPoints, crlURL)
	}
	// A certificate's times are in whole seconds, so the end is allowed one
	// second before 24 hours after the claim was sent.
	until := w.sent.Add(24*time.Hour - time.Second)
	for _, when := range []time.Time{w.answered, until} {
		roots := x509.NewCertPool()
		roots.AddCert(w.ca)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: roots, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("the leaf for %s does not verify with the claim's ca_cert at %s: %v", sni, when.Format(time.RFC3339), err)
		}
	}
}

// intercepted: on port 443 the relay terminates TLS with a leaf for the
// name the client sent, which GUEST-42 shapes, and serves the requests
// inside as on port 80, routed by their host.
var intercepted = runner.Case{
	Name:  "on port 443 the relay presents a leaf for the name sent, signed by its CA and naming its CRL, and serves the requests inside",
	Cites: []string{"GUEST-42"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		for _, sni := range []string{originName, "not-an-origin.example", "artifacts"} {
			c := w.conn(443, sni).(*tls.Conn)
			leafChecked(t, w, sni, c.ConnectionState().PeerCertificates)
			_ = c.Close()
		}
		rep := w.send(443, originName, request(http.MethodGet, "/inside", originName, nil))
		expect(t, "GET https://"+originName+"/inside", rep, http.StatusOK, "", upstream.Body(originName, "/inside"))
		rep = w.send(443, originName, request(http.MethodGet, "/ca.pem", "artifacts", nil))
		expect(t, "GET /ca.pem for artifacts inside TLS for "+originName, rep, http.StatusOK, "application/x-pem-file", w.caPEM)
	},
}

// caCertificate: the claim's ca_cert is a CA certificate, of path length
// 0, for certificate and CRL signing, valid when the claim is answered.
var caCertificate = runner.Case{
	Name:  "the relay's CA is a CA certificate of path length 0 for certificate and CRL signing, valid at the claim",
	Cites: []string{"GUEST-48"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		ca := w.ca
		if !ca.BasicConstraintsValid || !ca.IsCA {
			t.Errorf("the claim's ca_cert has basic constraints %v with CA %v, want CA true", ca.BasicConstraintsValid, ca.IsCA)
		}
		if ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
			t.Errorf("the claim's ca_cert has a path length of %d (zero stated: %v), want 0", ca.MaxPathLen, ca.MaxPathLenZero)
		}
		if ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.KeyUsage&x509.KeyUsageCRLSign == 0 {
			t.Errorf("the claim's ca_cert has key usage %b, want certificate signing and CRL signing", ca.KeyUsage)
		}
		if w.answered.Before(ca.NotBefore) || w.answered.After(ca.NotAfter) {
			t.Errorf("the claim's ca_cert is valid from %s to %s, which does not hold the claim's answer at %s", ca.NotBefore, ca.NotAfter, w.answered)
		}
	},
}

// checkCRL checks the CRL der against GUEST-24: signed by ca, revoking
// nothing, and due for its next update no sooner than ca expires.
func checkCRL(t *runner.T, der []byte, ca *x509.Certificate) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Errorf("http://artifacts/ca.crl is not a DER certificate revocation list: %v", err)
		return
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("the CRL is not signed by the claim's ca_cert: %v", err)
	}
	if n := len(crl.RevokedCertificateEntries); n > 0 {
		t.Errorf("the CRL revokes %d certificates, want none", n)
	}
	if crl.NextUpdate.Before(ca.NotAfter) {
		t.Errorf("the CRL's next update is %s, before the claim's ca_cert expires at %s", crl.NextUpdate, ca.NotAfter)
	}
}

// proxiedTLS: a request inside TLS is proxied to the name the client sent,
// over HTTPS on port 443, with its Host unchanged, verifying the origin's
// certificate against the claim's upstream root.
var proxiedTLS = runner.Case{
	Name:  "a request inside TLS is proxied to the name sent, over HTTPS on port 443, with its Host unchanged",
	Cites: []string{"GUEST-43"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		rep := w.send(443, originName, request(http.MethodGet, "/over-tls", originName, nil))
		expect(t, "GET https://"+originName+"/over-tls", rep, http.StatusOK, "", upstream.Body(originName, "/over-tls"))
		const other = "other-host.example"
		rep = w.send(443, originName, request(http.MethodGet, "/other-host", other, nil))
		for _, c := range []struct{ target, host string }{{"/over-tls", originName}, {"/other-host", other}} {
			xs := exchangesFor(w.up, c.target)
			if len(xs) != 1 {
				t.Errorf("the origin received %d requests for %s, want 1", len(xs), c.target)
				continue
			}
			if x := xs[0]; x.Port != 443 || x.ServerName != originName || x.Host != c.host {
				t.Errorf("the request for %s reached the origin on port %d with the TLS name %q and Host %q, want port 443, %s and %s", c.target, x.Port, x.ServerName, x.Host, originName, c.host)
			}
		}
		if x := exchangesFor(w.up, "/other-host"); len(x) == 1 && rep.status != x[0].Status {
			t.Errorf("the build was answered %d for /other-host, where the origin answered %d", rep.status, x[0].Status)
		}
	},
}

// untrustedUpstream: with a claim whose one upstream root is not the one
// that signed the origin's certificate, a request inside TLS is answered
// 502 and reaches no origin.
var untrustedUpstream = runner.Case{
	Name:  "an upstream whose certificate the claim's roots do not verify is answered 502",
	Cites: []string{"GUEST-43", "GUEST-46"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		other, err := upstream.NewCA()
		if err != nil {
			t.Fatalf("a CA the origin does not use: %v", err)
		}
		w := startWeb(t, webOpts{upstreamCA: []string{string(other.PEM())}})
		rep := w.send(443, originName, request(http.MethodGet, "/untrusted", originName, nil))
		refused(t, "GET https://"+originName+"/untrusted with the origin's CA not trusted", rep, http.StatusBadGateway, "upstream unreachable\n")
		if xs := exchangesFor(w.up, "/untrusted"); len(xs) > 0 {
			t.Errorf("the origin received the request, which the relay was not to send to a server it does not trust")
		}
	},
}

// unchanged: the response reaches the build as the origin sent it: its
// status, its fields with their values and its body, a body the origin
// encoded among them, which the relay neither decodes nor asks for when the
// build did not.
var unchanged = runner.Case{
	Name:  "the build receives the upstream's status, fields and body unchanged, and no encoding it did not ask for",
	Cites: []string{"GUEST-44"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(bytes.Repeat([]byte("compressed by the origin "), 400))
		_ = zw.Close()
		sent := http.Header{
			"Content-Type":     {"application/x-test; q=1"},
			"Content-Encoding": {"gzip"},
			"X-Multi":          {"one", "two"},
			"Cache-Control":    {"no-store"},
			"Etag":             {`"v1"`},
		}
		w.up.Origins.Handle(originName, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			for k, vs := range sent {
				rw.Header()[k] = vs
			}
			rw.Header()["x-lower"] = []string{"Case Kept"}
			rw.Header().Set("Content-Length", strconv.Itoa(gz.Len()))
			rw.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = rw.Write(gz.Bytes())
		}))
		for _, c := range []struct {
			what, sni, target string
			fields            []string
		}{
			{"over HTTP, asking for gzip", "", "/gz-http", []string{"Accept-Encoding: gzip"}},
			{"over TLS, asking for gzip", originName, "/gz-tls", []string{"Accept-Encoding: gzip"}},
			{"over HTTP, asking for no encoding", "", "/plain-http", nil},
			{"over TLS, asking for no encoding", originName, "/plain-tls", nil},
		} {
			port := uint16(80)
			if c.sni != "" {
				port = 443
			}
			rep := w.send(port, c.sni, request(http.MethodGet, c.target, originName, nil, c.fields...))
			if rep.status != http.StatusNonAuthoritativeInfo {
				t.Errorf("%s: the build was answered %s, where the origin answered 203", c.what, rep)
				continue
			}
			if !bytes.Equal(rep.body, gz.Bytes()) {
				t.Errorf("%s: the build received a body of %d bytes, not the %d the origin sent", c.what, len(rep.body), gz.Len())
			}
			want := sent.Clone()
			want["X-Lower"] = []string{"Case Kept"}
			want["Content-Length"] = []string{strconv.Itoa(gz.Len())}
			for k, vs := range want {
				if got := rep.header.Values(k); !slices.Equal(got, vs) {
					t.Errorf("%s: the build received %s as %q, where the origin sent %q", c.what, k, got, vs)
				}
			}
			if rep.header.Get("Date") == "" {
				t.Errorf("%s: the build received no Date, which the origin sent", c.what)
			}
			for k := range rep.header {
				if _, ok := want[k]; !ok && k != "Date" && k != "Connection" {
					t.Errorf("%s: the build received the field %s, which the origin did not send", c.what, k)
				}
			}
			xs := exchangesFor(w.up, c.target)
			if len(xs) != 1 {
				t.Errorf("%s: the origin received %d requests, want 1", c.what, len(xs))
				continue
			}
			if got, want := xs[0].Header.Get("Accept-Encoding"), strings.TrimPrefix(strings.Join(c.fields, ""), "Accept-Encoding: "); got != want {
				t.Errorf("%s: the origin was asked with Accept-Encoding %q, where the build asked %q", c.what, got, want)
			}
		}
	},
}

// resolvedUpstream: the relay resolves an upstream's name through the
// claim's resolvers in list order, the first alone while it answers and
// the second when the first has not answered in 5 s, and never through a
// resolver the claim does not list; an IP address in place of a name is
// dialed as it is, with no query.
var resolvedUpstream = runner.Case{
	Name:  "an upstream's name is resolved through the listed resolvers in order, the next after 5 s, and an address used as it is",
	Cites: []string{"GUEST-45"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		expect(t, "GET / for "+originName, w.get(originName, "/first"), http.StatusOK, "", upstream.Body(originName, "/first"))
		asked := askedFor(w.up, originName)
		if len(asked[0]) == 0 || len(asked[1]) != 0 || len(asked[2]) != 0 {
			t.Errorf("the resolvers received %d, %d and %d queries for %s while the first answered, want at least 1, 0 and 0", len(asked[0]), len(asked[1]), len(asked[2]), originName)
		}
		if !slices.ContainsFunc(asked[0], func(q upstream.Query) bool { return q.Type == dns.TypeA }) {
			t.Errorf("the relay asked the first resolver for no A record of %s", originName)
		}
		lit := originAddr.String()
		rep := w.get(lit, "/literal")
		if xs := exchangesFor(w.up, "/literal"); len(xs) != 1 || xs[0].Host != lit {
			t.Errorf("GET /literal with Host %s, answered %s, did not reach the origin's address once with that Host", lit, rep)
		}
		for i, qs := range askedFor(w.up, lit) {
			if len(qs) > 0 {
				t.Errorf("the relay asked the resolver %s for %s, an address", w.up.Resolvers[i].Address(), lit)
			}
		}
		const later = "later.example"
		for _, res := range w.up.Resolvers {
			res.Set(later, originAddr)
		}
		if err := w.up.Resolvers[0].SetMode(t.Context(), upstream.Silent); err != nil {
			t.Fatalf("making the first resolver silent: %v", err)
		}
		c := w.conn(80, "")
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.WriteString(c, request(http.MethodGet, "/later", later, nil)); err != nil {
			t.Fatalf("GET /later: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("GET /later for %s with the first resolver silent: %v", later, err)
		}
		_ = resp.Body.Close()
		if xs := exchangesFor(w.up, "/later"); len(xs) != 1 {
			t.Errorf("GET /later for %s with the first resolver silent was answered %d, and reached the origin %d times, want once", later, resp.StatusCode, len(xs))
		}
		asked = askedFor(w.up, later)
		if len(asked[0]) == 0 || len(asked[1]) == 0 || len(asked[2]) != 0 {
			t.Fatalf("the resolvers received %d, %d and %d queries for %s, want at least 1, at least 1 and 0", len(asked[0]), len(asked[1]), len(asked[2]), later)
		}
		if gap := asked[1][0].At.Sub(asked[0][0].At); gap < failover {
			t.Errorf("the relay asked the second resolver for %s %s after the first, which had not answered; it gives a resolver 5 s", later, gap)
		}
	},
}

// unreachableUpstream: a name that does not resolve and an address where
// nothing accepts the connection are each answered 502, text/plain,
// "upstream unreachable", and each 502 is recorded as its exchange's
// response.
var unreachableUpstream = runner.Case{
	Name:  "an upstream the relay cannot reach is answered 502 upstream unreachable, recorded as the exchange's response",
	Cites: []string{"GUEST-46", "GUEST-49"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		var bodies [][]byte
		for _, c := range []struct{ what, host, target string }{
			{"a name no resolver has", "no-such-name.example", "/no-name"},
			{"a port where nothing listens", originName + ":81", "/no-port"},
		} {
			rep := w.get(c.host, c.target)
			refused(t, "GET "+c.target+" for "+c.what, rep, http.StatusBadGateway, "upstream unreachable\n")
			bodies = append(bodies, rep.body)
		}
		l := w.exit()
		for i, p := range []string{"/no-name", "/no-port"} {
			cs := onPath(l, p)
			if len(cs) != 1 {
				t.Errorf("the ledger has %d channels for %s, want the one exchange", len(cs), p)
				continue
			}
			last, ok := cs[0].last()
			st, _ := last.Int("status")
			if !ok || last.Type != ledger.Close || st != http.StatusBadGateway || !holds(l, last, bodies[i]) {
				t.Errorf("the ledger's %s does not end with the 502 and the body the build received", cs[0])
			}
		}
	},
}

// keptAlive: after an HTTP/1.1 request the connection is kept for the next,
// over HTTP and TLS, after a proxied request as after a reserved host's,
// and after an HTTP/1.0 request when it says keep-alive. Each connection's
// last request says Connection: close, or is HTTP/1.0 without keep-alive,
// and so does its response; what a relay does after such a response is not
// defined by GUEST-47, so the case checks nothing after it and closes the
// connection itself.
var keptAlive = runner.Case{
	Name:  "a connection is kept after an HTTP/1.1 request, and after an HTTP/1.0 request that says keep-alive",
	Cites: []string{"GUEST-47"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		hb11 := "GET /heartbeat HTTP/1.1\r\nHost: artifacts\r\n\r\n"
		proxied11 := "GET /kept HTTP/1.1\r\nHost: " + originName + "\r\n\r\n"
		hb10 := "GET /heartbeat HTTP/1.0\r\nHost: artifacts\r\n\r\n"
		kept10 := "GET /heartbeat HTTP/1.0\r\nHost: artifacts\r\nConnection: keep-alive\r\n\r\n"
		close11 := request(http.MethodGet, "/heartbeat", "artifacts", nil)
		for _, c := range []struct {
			what string
			port uint16
			sni  string
			reqs []string
		}{
			{"HTTP/1.1 on port 80", 80, "", []string{hb11, proxied11, hb11, close11}},
			{"HTTP/1.1 on port 443", 443, originName, []string{hb11, proxied11, close11}},
			{"HTTP/1.0 with keep-alive", 80, "", []string{kept10, kept10, hb10}},
		} {
			conn := w.conn(c.port, c.sni)
			br := bufio.NewReader(conn)
			for i, req := range c.reqs {
				rep, err := w.exchange(conn, br, req)
				if err != nil {
					t.Errorf("%s: request %d of %d on one connection, %s: %v", c.what, i+1, len(c.reqs), firstLine(req), err)
					break
				}
				if rep.status != http.StatusOK {
					t.Errorf("%s: request %d, %s, was answered %s", c.what, i+1, firstLine(req), rep)
				}
			}
			_ = conn.Close()
		}
	},
}

// roundTrip is the RELAY-02 round trip: the build fetches and sends bodies
// through every path the relay records (proxied over HTTP and TLS, served
// inputs and context files, an artifact), and the ledger verifier checks,
// for each, that the ledger states the bytes the build received and the
// bytes it sent, with the request's header fields recorded out of the
// build and the response's into it.
var roundTrip = runner.Case{
	Name:  "the ledger states the hash of every body the build received and sent, for each exchange the relay recorded",
	Cites: []string{"GUEST-49"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		script := pattern(3000, 61)
		file := pattern(9000, 62)
		w := startWeb(t, webOpts{form: collector.Form{Script: script, Context: map[string][]byte{"src/main.c": file}}})
		type sent struct {
			what, method, path string
			body               []byte
			rep                reply
		}
		var all []sent
		do := func(what, method, path string, port uint16, sni string, body []byte) {
			rep := w.send(port, sni, request(method, path, originName, body))
			if rep.status != http.StatusOK {
				t.Errorf("%s was answered %s", what, rep)
			}
			all = append(all, sent{what, method, path, body, rep})
		}
		do("GET over HTTP", http.MethodGet, "/bytes/100000", 80, "", nil)
		do("GET over TLS", http.MethodGet, "/bytes/70001", 443, originName, nil)
		do("POST over HTTP", http.MethodPost, "/post-http", 80, "", pattern(5000, 63))
		do("POST over TLS", http.MethodPost, "/post-tls", 443, originName, pattern(6000, 64))
		do("an empty GET", http.MethodGet, "/bytes/0", 80, "", nil)
		expect(t, "GET http://artifacts/build-script", w.get("artifacts", "/build-script"), http.StatusOK, "", script)
		expect(t, "GET http://cwd/src/main.c", w.get("cwd", "/src/main.c"), http.StatusOK, "", file)
		art := pattern(12000, 65)
		expect(t, "POST http://artifacts/out.bin", w.post("artifacts", "/out.bin", art), http.StatusOK, "", nil)
		l := w.exit()
		for _, s := range all {
			cs := onPath(l, s.path)
			if len(cs) != 1 {
				t.Errorf("%s: the ledger has %d channels for %s, want 1", s.what, len(cs), s.path)
				continue
			}
			checkExchange(t, l, s.what, cs[0], s.method, s.body, s.rep)
		}
		served(t, l, "/build-script", script)
		served(t, l, "/src/main.c", file)
		if !artifactRecorded(l, "out.bin", art) {
			t.Errorf("the ledger has no artifact record out.bin with the %d bytes the build sent", len(art))
		}
	},
}

// nothingAfterCompletion: once the build has completed, the relay records
// nothing more: in the seconds after the completion the collector receives
// no more of the ledger, no second ledger request and no other output. The
// build sends nothing after its completion (GUEST-55), and a relay's
// replies to what it would send are not defined, so the case sends nothing:
// it checks what the relay does by itself, after a build that had proxied,
// served and stored before its completion. It checks only that: a relay
// that would record a request the build sent after its completion is not
// seen, since no case sends one (Known divergences, D18).
var nothingAfterCompletion = runner.Case{
	Name:  "once the build has completed, the relay records nothing more and sends its collector no more of the ledger",
	Cites: []string{"GUEST-55"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		// The collector serves after the completion, so that whatever the
		// relay sends then reaches it.
		w := startWeb(t, webOpts{form: collector.Form{Script: []byte("script\n"), ServesAfterCompletion: true}})
		expect(t, "GET / for "+originName, w.get(originName, "/before"), http.StatusOK, "", nil)
		expect(t, "GET http://artifacts/build-script", w.get("artifacts", "/build-script"), http.StatusOK, "", nil)
		expect(t, "POST http://artifacts/before.bin", w.post("artifacts", "/before.bin", []byte("stored\n")), http.StatusOK, "", nil)
		w.exit()
		at, _, _ := w.coll.Ledger()
		n := len(w.coll.Requests())
		sleep(t, 3*time.Second)
		data, ledgers, ended := w.coll.Ledger()
		if !bytes.Equal(data, at) || !ended || ledgers != 1 {
			t.Errorf("after the completion the collector's ledger went from %d to %d bytes in %d requests (ended: %v), want it unchanged in the one request", len(at), len(data), ledgers, ended)
		}
		for _, r := range w.coll.Requests()[n:] {
			if r.Path != "/v1/heartbeat" {
				t.Errorf("after the completion the relay sent the collector %s %s", r.Method, r.Path)
			}
		}
	},
}

// checkExchange checks that c records a proxied exchange as the ledger
// format lays it out: the request's method, its header fields out of the
// build, its body out of the build when it had one, the response's header
// fields into the build, and a close with the response's status and the
// body the build received.
func checkExchange(t *runner.T, l *ledger.Ledger, what string, c channel, method string, body []byte, rep reply) {
	if c.method() != method {
		t.Errorf("%s: %s records the method %q, want %s", what, c, c.method(), method)
	}
	last, ok := c.last()
	if !ok || last.Type != ledger.Close {
		t.Errorf("%s: %s is not closed", what, c)
		return
	}
	if st, _ := last.Int("status"); st != int64(rep.status) {
		t.Errorf("%s: %s closes with the status %d, where the build was answered %d", what, c, st, rep.status)
	}
	if last.PayloadSize < 0 || !holds(l, last, rep.body) {
		t.Errorf("%s: the close of %s does not state the %d bytes the build received (it states %d bytes)", what, c, len(rep.body), last.PayloadSize)
	}
	var out, in, bodies int
	for _, r := range c.recs[:len(c.recs)-1] {
		switch {
		case r.Type != ledger.Checkpoint:
		case r.Schema == ledger.SchemaHTTPHeaders && r.PayloadSize < 0:
			out++
		case r.Schema == ledger.SchemaHTTPHeaders && r.PayloadSize > 0:
			in++
		case r.Schema == ledger.SchemaHTTPBody && r.PayloadSize < 0 && holds(l, r, body):
			bodies++
		}
	}
	if out != 1 || in != 1 {
		t.Errorf("%s: %s has %d checkpoints of request header fields out of the build and %d of response header fields into it, want 1 and 1", what, c, out, in)
	}
	if len(body) > 0 && bodies != 1 {
		t.Errorf("%s: %s has %d checkpoints stating the %d bytes of the request's body, want 1", what, c, bodies, len(body))
	}
}

// refusalsPlain: every refusal of this API that a build can provoke without
// completing is text/plain with a body of at most one line.
var refusalsPlain = runner.Case{
	Name:  "each refusal is text/plain with a body of at most one line",
	Cites: []string{"GUEST-56"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		fault := func(r *http.Request) int {
			if strings.HasPrefix(r.URL.Path, "/v1/artifacts/") || r.URL.Path == "/v1/output" {
				return http.StatusServiceUnavailable
			}
			return 0
		}
		w := startWeb(t, webOpts{fault: fault, form: collector.Form{Context: map[string][]byte{}}})
		for _, c := range []struct {
			what   string
			port   uint16
			req    string
			status int
		}{
			{"an artifact with a name that breaks the rule", 80, request(http.MethodPost, "/.bad", "artifacts", []byte("x")), http.StatusBadRequest},
			{"an artifact the collector does not store", 80, request(http.MethodPost, "/kept.bin", "artifacts", []byte("x")), http.StatusInternalServerError},
			{"no such path of artifacts", 80, request(http.MethodGet, "/nothing", "artifacts", nil), http.StatusNotFound},
			{"no build script", 80, request(http.MethodGet, "/build-script", "artifacts", nil), http.StatusNotFound},
			{"no bootstrap config", 80, request(http.MethodGet, "/bootstrap", "artifacts", nil), http.StatusNotFound},
			{"a cwd path that breaks the rule", 80, request(http.MethodGet, "/../x", "cwd", nil), http.StatusForbidden},
			{"no such cwd path", 80, request(http.MethodGet, "/missing", "cwd", nil), http.StatusNotFound},
			{"/v1/output by GET", controlPort, request(http.MethodGet, "/v1/output", "control", nil), http.StatusMethodNotAllowed},
			{"output the collector does not take", controlPort, request(http.MethodPost, "/v1/output", "control", []byte("x")), http.StatusInternalServerError},
			{"no such path of the control plane", controlPort, request(http.MethodGet, "/nothing", "control", nil), http.StatusNotFound},
			{"an upstream that cannot be reached", 80, request(http.MethodGet, "/", "no-such-name.example", nil), http.StatusBadGateway},
		} {
			refused(t, fmt.Sprintf("%s (port %d)", c.what, c.port), w.send(c.port, "", c.req), c.status, "")
		}
	},
}
