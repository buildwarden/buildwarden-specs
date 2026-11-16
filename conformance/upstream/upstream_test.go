package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
)

var (
	resolverA  = netip.MustParseAddr("192.0.2.53")
	resolverB  = netip.MustParseAddr("198.51.100.53")
	originAddr = netip.MustParseAddr("203.0.113.10")
	client     = netip.MustParseAddr("203.0.113.1")
)

// world starts two resolvers and two origins at one address on a fresh
// in-memory network, and returns the network as a client at 203.0.113.1
// sees it.
func world(t *testing.T) (*Upstream, attach.Network) {
	t.Helper()
	n := memnet.New()
	u, err := Start(context.Background(), n.Host(resolverA), World{
		Resolvers: []netip.Addr{resolverA, resolverB},
		Origins: []Origin{
			{Name: "origin.example", Addr: originAddr},
			{Name: "Other.Example", Addr: originAddr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u, n.Host(client)
}

func query(ctx context.Context, n attach.Network, transport string, server netip.Addr, name string, qtype uint16) (*dns.Msg, error) {
	c, err := n.Dial(ctx, transport, net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	cl := &dns.Client{Net: transport, Timeout: 2 * time.Second}
	r, _, err := cl.ExchangeWithConnContext(ctx, m, &dns.Conn{Conn: c})
	return r, err
}

func TestResolverAnswers(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	ctx := context.Background()
	tests := []struct {
		name      string
		transport string
		qname     string
		qtype     uint16
		rcode     int
		answers   int
	}{
		{"an origin over UDP", "udp", "origin.example", dns.TypeA, dns.RcodeSuccess, 1},
		{"an origin over TCP", "tcp", "origin.example", dns.TypeA, dns.RcodeSuccess, 1},
		{"a name in another case", "udp", "ORIGIN.example", dns.TypeA, dns.RcodeSuccess, 1},
		{"an origin given in upper case", "udp", "other.example", dns.TypeA, dns.RcodeSuccess, 1},
		{"another type", "udp", "origin.example", dns.TypeAAAA, dns.RcodeSuccess, 0},
		{"a name not in the zone", "udp", "absent.example", dns.TypeA, dns.RcodeNameError, 0},
	}
	t.Run("queries", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				r, err := query(ctx, n, tt.transport, resolverB, tt.qname, tt.qtype)
				if err != nil {
					t.Fatal(err)
				}
				if r.Rcode != tt.rcode || len(r.Answer) != tt.answers {
					t.Fatalf("rcode %s with %d answers, want %s with %d", dns.RcodeToString[r.Rcode], len(r.Answer), dns.RcodeToString[tt.rcode], tt.answers)
				}
				if tt.answers == 1 {
					a := r.Answer[0].(*dns.A)
					if !a.A.Equal(originAddr.AsSlice()) || a.Hdr.Ttl != TTL || a.Hdr.Name != dns.Fqdn(tt.qname) {
						t.Errorf("answer %v, want %s for %s with TTL %d", a, originAddr, tt.qname, TTL)
					}
				}
			})
		}
	})
	if q := u.Resolvers[1].Queries(); len(q) != len(tests) {
		t.Errorf("the resolver recorded %d queries, want %d", len(q), len(tests))
	}
}

func TestResolverRecordsQueries(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	ctx := context.Background()
	for _, name := range []string{"first.example", "second.example"} {
		if _, err := query(ctx, n, "udp", resolverA, name, dns.TypeA); err != nil {
			t.Fatal(err)
		}
	}
	q := u.Resolvers[0].Queries()
	if len(q) != 2 || q[0].Name != "first.example." || q[1].Name != "second.example." || q[0].Seq != 1 || q[1].Seq != 2 ||
		q[0].Transport != "udp" || !strings.HasPrefix(q[0].From, "203.0.113.1:") || !q[0].Answered {
		t.Errorf("queries = %+v, want first.example then second.example, answered, from 203.0.113.1", q)
	}
	if q := u.Resolvers[1].Queries(); len(q) != 0 {
		t.Errorf("the second resolver was sent %d queries, want none", len(q))
	}
}

func TestResolverModes(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	ctx := context.Background()
	r := u.Resolvers[0]

	if err := r.SetMode(ctx, Silent); err != nil {
		t.Fatal(err)
	}
	if _, err := query(ctx, n, "udp", resolverA, "origin.example", dns.TypeA); !errors.Is(err, os.ErrDeadlineExceeded) {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("a silent resolver: %v, want a timeout", err)
		}
	}
	if q := r.Queries(); len(q) != 1 || q[0].Answered {
		t.Errorf("queries = %+v, want one, not answered", q)
	}

	if err := r.SetMode(ctx, Failing); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"udp", "tcp"} {
		if _, err := query(ctx, n, transport, resolverA, "origin.example", dns.TypeA); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("a failing resolver over %s: %v, want ECONNREFUSED", transport, err)
		}
	}
	if q := r.Queries(); len(q) != 1 {
		t.Errorf("a failing resolver recorded %d queries, want only the silent one", len(q))
	}

	if err := r.SetMode(ctx, Answering); err != nil {
		t.Fatal(err)
	}
	if m, err := query(ctx, n, "udp", resolverA, "origin.example", dns.TypeA); err != nil || len(m.Answer) != 1 {
		t.Errorf("answering again: %v, %v; want one answer", m, err)
	}
}

func TestResolverSet(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	ctx := context.Background()
	r := u.Resolvers[0]
	r.Set("new.example", resolverA, resolverB)
	m, err := query(ctx, n, "udp", resolverA, "new.example", dns.TypeA)
	if err != nil || len(m.Answer) != 2 {
		t.Fatalf("%v, %v; want two answers", m, err)
	}
	r.Set("new.example")
	if m, err = query(ctx, n, "udp", resolverA, "new.example", dns.TypeA); err != nil || m.Rcode != dns.RcodeNameError {
		t.Errorf("%v, %v; want NXDOMAIN", m, err)
	}
}

// dialer connects every request to the origins' address, at the port of
// the URL.
func dialer(n attach.Network) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		return n.Dial(ctx, network, net.JoinHostPort(originAddr.String(), port))
	}
}

func TestOrigins(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	c := &http.Client{Transport: &http.Transport{DialContext: dialer(n), TLSClientConfig: &tls.Config{RootCAs: u.CA.Pool()}}}
	tests := []struct {
		url    string
		status int
		body   string
	}{
		{"http://origin.example/a/path?q=1", 200, "origin.example /a/path\n"},
		{"https://origin.example/a/path", 200, "origin.example /a/path\n"},
		{"https://other.example/", 200, "other.example /\n"},
		{"http://other.example/bytes/23", 200, "other.example 23 other."},
		{"http://absent.example/", http.StatusMisdirectedRequest, "no origin absent.example here\n"},
	}
	for i, tt := range tests {
		resp, err := c.Get(tt.url)
		if err != nil {
			t.Fatalf("GET %s: %v", tt.url, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tt.status || string(b) != tt.body {
			t.Errorf("GET %s: %d %q, want %d %q", tt.url, resp.StatusCode, b, tt.status, tt.body)
		}
		ex := u.Origins.Exchanges()
		if len(ex) != i+1 {
			t.Fatalf("%d exchanges, want %d", len(ex), i+1)
		}
		e := ex[i]
		if e.Seq != i+1 || e.Method != "GET" || (strings.HasPrefix(tt.url, "https:")) != (e.Port == 443) {
			t.Errorf("exchange %+v for GET %s", e, tt.url)
		}
		if e.Port == 443 && e.ServerName != e.Origin {
			t.Errorf("server name %q, want %q", e.ServerName, e.Origin)
		}
	}
	if got := Body("x", "/bytes/0"); len(got) != 0 {
		t.Errorf("Body of /bytes/0 = %q, want none", got)
	}
}

func TestOriginHandler(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	u.Origins.Handle("origin.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	c := &http.Client{Transport: &http.Transport{DialContext: dialer(n)}}
	resp, err := c.Post("http://origin.example/upload", "text/plain", strings.NewReader("sent"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status %d, want 418", resp.StatusCode)
	}
	ex := u.Origins.Exchanges()
	if len(ex) != 1 || string(ex[0].Body) != "sent" || ex[0].Method != "POST" {
		t.Errorf("exchanges = %+v, want the POST with its body", ex)
	}
}

func TestOriginTLSRefusesAnUnknownName(t *testing.T) {
	t.Parallel()
	u, n := world(t)
	c, err := n.Dial(context.Background(), "tcp", net.JoinHostPort(originAddr.String(), "443"))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "absent.example", RootCAs: u.CA.Pool()})
	defer tc.Close()
	if err := tc.Handshake(); err == nil {
		t.Error("the handshake for a name no origin has succeeded")
	}
}

func TestCA(t *testing.T) {
	t.Parallel()
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ca.PEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("PEM holds no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || !cert.MaxPathLenZero || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("the CA certificate is not a CA of path length 0 that signs certificates")
	}
	leaf, err := ca.Leaf("origin.example", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"origin.example", "203.0.113.10"} {
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: ca.Pool()}); err != nil {
			t.Errorf("the leaf does not verify for %s: %v", name, err)
		}
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "origin.example"}); err == nil {
		t.Error("the leaf verifies against the system roots, want only against the CA")
	}
}

func TestCheckAddress(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"192.0.2.1", "198.51.100.255", "203.0.113.0"} {
		if err := CheckAddress(netip.MustParseAddr(a)); err != nil {
			t.Errorf("CheckAddress(%s): %v", a, err)
		}
	}
	for _, a := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "8.8.8.8", "2001:db8::1"} {
		if err := CheckAddress(netip.MustParseAddr(a)); err == nil {
			t.Errorf("CheckAddress(%s) accepted it", a)
		}
	}
	n := memnet.New()
	if _, err := StartResolver(context.Background(), n.Host(client), netip.MustParseAddr("10.0.0.53"), nil); err == nil {
		t.Error("a resolver started on 10.0.0.53")
	}
	if _, err := StartOrigins(context.Background(), n.Host(client), nil, []Origin{{Name: "a", Addr: originAddr}, {Name: "A", Addr: originAddr}}); err == nil {
		t.Error("two origins of one name started")
	}
}
