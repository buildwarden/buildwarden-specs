package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// ResolveTimeout is how long the relay waits for one resolver before it
// asks the next, when it resolves a name of its own.
const ResolveTimeout = 5 * time.Second

// tunnelClient is the relay's HTTP/2 client on the tunnel's connection,
// which the claimant opened: the relay sends the connection preface
// (CLAIM-13). The connection is dialled once; a request after it has closed
// fails.
func tunnelClient(conn net.Conn, r *bufio.Reader) *http.Client {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	var mu sync.Mutex
	used := false
	return &http.Client{
		Transport: &http.Transport{
			Protocols: &p,
			// One connection: a request made while it is being set up
			// waits for it rather than dialling another.
			MaxConnsPerHost: 1,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				mu.Lock()
				defer mu.Unlock()
				if used {
					return nil, errors.New("the tunnel has closed")
				}
				used = true
				return &bufConn{Conn: conn, r: r}, nil
			},
		},
		CheckRedirect: noRedirect,
	}
}

// noRedirect makes a collector's redirect its reply: the relay reads only
// the collector's own 200 as an output stored or an input (COLLOUT-25,
// COLLIN-28), where the Go relay follows redirects (N13).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// baseClient is the relay's client of a collector at a base URL of its own
// (CLAIM-23): it dials on the upstream network, resolving a name through the
// claim's resolvers in their order (CLAIM-31). An https base URL is verified
// against the system's roots and the claim's upstream_ca_certs, which is
// this model's reading: relay-claim names no roots for the collector.
func baseClient(raw string, up attach.Network, c *Claim) (*http.Client, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("collector_url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, "", fmt.Errorf("collector_url %q is not an http or https base URL", raw)
	}
	if up == nil {
		return nil, "", errors.New("the relay has no upstream network to reach a collector_url on")
	}
	base := strings.TrimRight(raw, "/")
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, r := range c.Roots {
		pool.AddCert(r)
	}
	var p http.Protocols
	p.SetHTTP1(true)
	if u.Scheme == "https" {
		p.SetHTTP2(true)
	}
	tr := &http.Transport{
		Protocols:       &p,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addrs, err := lookup(ctx, up, c.Resolvers, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, a := range addrs {
				conn, err := up.Dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}, base, nil
}

// lookup is host's IPv4 addresses: host itself when it is an address, and
// otherwise the answer of the first of servers that answers, each asked over
// UDP for at most ResolveTimeout, in their order.
func lookup(ctx context.Context, up attach.Network, servers []netip.Addr, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{a}, nil
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	query, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	var last error = errors.New("no resolver")
	for _, s := range servers {
		ans, err := ask(ctx, up, s, query, q.Id)
		if err != nil {
			last = err
			continue
		}
		if ans.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("resolving %s: %s answered %s", host, s, dns.RcodeToString[ans.Rcode])
		}
		var out []netip.Addr
		for _, rr := range ans.Answer {
			if a, ok := rr.(*dns.A); ok {
				if addr, ok := netip.AddrFromSlice(a.A.To4()); ok {
					out = append(out, addr)
				}
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("resolving %s: %s gave no address", host, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("resolving %s: %w", host, last)
}

func ask(ctx context.Context, up attach.Network, server netip.Addr, query []byte, id uint16) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	conn, err := up.Dial(ctx, "udp", netip.AddrPortFrom(server, 53).String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", server, err)
		}
		ans := new(dns.Msg)
		if ans.Unpack(buf[:n]) == nil && ans.Id == id && ans.Response {
			return ans, nil
		}
	}
}
