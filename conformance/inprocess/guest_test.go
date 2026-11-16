package inprocess

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The tests below check the relay model's build side behaviour by
// behaviour, against the harness's other roles, in the modes where it
// differs.

type claimed struct {
	a    attach.Attachment
	in   attach.Instance
	up   *upstream.Upstream
	coll *collector.Collector
	ca   *x509.Certificate
	env  *buildenv.Env
}

// claim starts a relay in mode, claims it as the attachment declares with
// edit applied to the claim, and starts the build environment, which has
// waited for the relay's health.
func claim(t *testing.T, mode string, edit func(*claimant.Config)) *claimed {
	t.Helper()
	ctx := testCtx(t)
	a, err := Relay(mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	c := &claimed{a: a, up: world(t, network(t, a, attach.Upstream))}
	if c.in, err = a.Start(ctx, attach.Params{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.in.Stop() })
	c.coll = collector.New(collector.Form{Context: map[string][]byte{"a": []byte("a")}}, nil)
	d := a.Declared()
	cfg := claimant.Config{UpstreamDNS: c.up.DNS(), UpstreamCACerts: []string{string(c.up.CA.PEM())}, UpstreamSystemCA: new(bool)}
	if d.BuildLink != nil {
		cfg.BuildLink = &claimant.BuildLink{Prefix: d.BuildLink.Prefix, Relay: d.BuildLink.Relay, Guest: d.BuildLink.Guest}
	}
	if edit != nil {
		edit(&cfg)
	}
	cl := claimant.Claimant{Net: network(t, a, attach.Claim), Endpoint: c.in.Claim()}
	tun, rep, err := cl.Session(ctx, c.coll, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	if _, c.ca, _, err = rep.Identity(); err != nil {
		t.Fatalf("the claim: %d %s: %v", rep.Status, rep.Body, err)
	}
	if d.Link == buildenv.Frames {
		link, err := c.in.Frames()
		if err != nil {
			t.Fatal(err)
		}
		c.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.Frames, Frames: link, MAC: guestMAC})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		addr := d.Address
		if cfg.BuildLink != nil {
			addr = cfg.BuildLink.Relay
		} else if d.Mode == relay.ModeVM {
			addr = VMInterface.Addr().String()
		}
		c.env, err = buildenv.Start(ctx, buildenv.Config{Link: buildenv.IP, Network: network(t, a, attach.Build), Relay: netip.MustParseAddr(addr)})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = c.env.Close() })
	if err := c.env.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	return c
}

// do sends one request with Connection: close and returns what came back.
func (c *claimed) do(t *testing.T, method, url string, body []byte) (int, http.Header, string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(c.ca)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(testCtx(t), method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	resp, err := c.env.Client(roots).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// doHost sends a GET to url with Host host.
func (c *claimed) doHost(t *testing.T, url, host string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(testCtx(t), "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host, req.Close = host, true
	resp, err := c.env.Client(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s with Host %s: %v", url, host, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestModeRefusals(t *testing.T) {
	t.Parallel()
	link := &claimant.BuildLink{Prefix: "10.100.0.0/30", Relay: "10.100.0.1", Guest: "10.100.0.2"}
	for _, tc := range []struct {
		name, mode string
		link       *claimant.BuildLink
	}{
		{"container with a build_link", relay.ModeContainer, link},
		{"vm with a build_link another interface holds", relay.ModeVM, &claimant.BuildLink{Prefix: "198.51.100.0/29", Relay: "198.51.100.2", Guest: "198.51.100.3"}},
		{"vm with a build_link holding another interface's route", relay.ModeVM, &claimant.BuildLink{Prefix: "172.30.0.0/15", Relay: "172.30.0.1", Guest: "172.30.0.2"}},
		{"vm with a build_link that is another interface's route", relay.ModeVM, &claimant.BuildLink{Prefix: "172.31.0.0/16", Relay: "172.31.0.1", Guest: "172.31.0.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := testCtx(t)
			a, err := Relay(tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			in, err := a.Start(ctx, attach.Params{})
			if err != nil {
				t.Fatal(err)
			}
			defer in.Stop()
			cl := claimant.Claimant{Net: network(t, a, attach.Claim), Endpoint: in.Claim()}
			rep, err := cl.Claim(ctx, claimant.Config{CollectorURL: "http://192.0.2.10", UpstreamDNS: []string{"192.0.2.53"}, BuildLink: tc.link})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Status != 400 || !strings.HasPrefix(string(rep.Body), "claim refused: build_link") {
				t.Errorf("answered %d %q, want 400 claim refused: build_link ...", rep.Status, rep.Body)
			}
		})
	}
	t.Run("a vm claim with a build_link that strictly lies within a route is accepted", func(t *testing.T) {
		t.Parallel()
		// The default route strictly contains every prefix, and is no use
		// of it (CLAIM-36): the attachment's own link is accepted.
		c := claim(t, relay.ModeVM, nil)
		if c.env.Relay() != netip.MustParseAddr(BuildLink.Relay) {
			t.Errorf("the relay is at %v", c.env.Relay())
		}
	})
	t.Run("a vm claim without a build_link keeps the interface's address", func(t *testing.T) {
		t.Parallel()
		c := claim(t, relay.ModeVM, func(cfg *claimant.Config) { cfg.BuildLink = nil })
		if status, _, body := c.do(t, "GET", "http://artifacts/heartbeat", nil); status != 200 || body != "ok\n" {
			t.Errorf("the heartbeat at %v: %d %q", VMInterface.Addr(), status, body)
		}
	})
	t.Run("a host claim without a build_link takes the default segment", func(t *testing.T) {
		t.Parallel()
		c := claim(t, relay.ModeHost, func(cfg *claimant.Config) { cfg.BuildLink = nil })
		if l, _ := c.env.Lease(); l.Address != netip.PrefixFrom(relay.DefaultSegment.Guest, 30) || l.Server != relay.DefaultSegment.Relay {
			t.Errorf("the lease: %v from %v", l.Address, l.Server)
		}
	})
}

func TestDNS(t *testing.T) {
	t.Parallel()
	for _, mode := range Modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			c := claim(t, mode, nil)
			ctx := testCtx(t)
			q := new(dns.Msg)
			q.SetQuestion("cwd.", dns.TypeAAAA)
			r, err := c.env.Exchange(ctx, "udp", q)
			if err != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || r.Id != q.Id {
				t.Errorf("AAAA for cwd: %v, %v", r, err)
			}
			q.SetQuestion("artifacts.", dns.TypeA)
			r, err = c.env.Exchange(ctx, "tcp", q)
			if err != nil || len(r.Answer) != 1 || r.Answer[0].Header().Ttl != 0 || r.Answer[0].(*dns.A).A.String() != c.env.Relay().String() {
				t.Errorf("A for artifacts over TCP: %v, %v", r, err)
			}
			q.SetQuestion("missing.example.", dns.TypeA)
			if r, err = c.env.Exchange(ctx, "udp", q); err != nil || r.Rcode != dns.RcodeNameError || r.Id != q.Id {
				t.Errorf("a name the upstream has not: %v, %v", r, err)
			}
			if err := c.up.Resolvers[0].SetMode(ctx, upstream.Failing); err != nil {
				t.Fatal(err)
			}
			q.SetQuestion(originName+".", dns.TypeA)
			if r, err = c.env.Exchange(ctx, "udp", q); err != nil || r.Rcode != dns.RcodeServerFailure || r.Id != q.Id {
				t.Errorf("with no resolver answering: %v, %v; want SERVFAIL", r, err)
			}
		})
	}
}

func TestDNSFailover(t *testing.T) {
	t.Parallel()
	second := netip.MustParseAddr("198.51.100.53")
	var silent *upstream.Resolver
	c := claim(t, relay.ModeHost, func(cfg *claimant.Config) {
		cfg.UpstreamDNS = append(cfg.UpstreamDNS, second.String())
	})
	r2, err := upstream.StartResolver(testCtx(t), network(t, c.a, attach.Upstream), second, map[string][]netip.Addr{originName: {originAddr}})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	silent = c.up.Resolvers[0]
	if err := silent.SetMode(testCtx(t), upstream.Silent); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	as, err := c.env.Resolve(testCtx(t), originName)
	if err != nil || len(as) != 1 || as[0] != originAddr {
		t.Fatalf("resolving through the second resolver: %v, %v", as, err)
	}
	if d := time.Since(start); d < relay.ResolveTimeout {
		t.Errorf("the second resolver was asked after %s, before the first's %s", d, relay.ResolveTimeout)
	}
	if len(silent.Queries()) != 1 || len(r2.Queries()) != 1 {
		t.Errorf("queries: first %d, second %d", len(silent.Queries()), len(r2.Queries()))
	}
}

func TestReplies(t *testing.T) {
	t.Parallel()
	c := claim(t, relay.ModeContainer, nil)
	control := "http://" + c.env.Relay().String() + ":8300"
	for _, tc := range []struct {
		method, url string
		status      int
		body        string
	}{
		{"POST", "http://artifacts/-bad", 400, "invalid artifact name\n"},
		{"POST", "http://artifacts/a//b", 400, "invalid artifact name\n"},
		{"GET", "http://artifacts/exit", 404, "not found\n"},
		{"GET", "http://artifacts/health", 404, "not found\n"},
		{"GET", "http://artifacts/build-script", 404, "build script unavailable\n"},
		{"GET", "http://artifacts/bootstrap", 404, "no bootstrap config\n"},
		{"GET", "http://cwd/%2e%2e/x", 403, "forbidden\n"},
		{"GET", "http://cwd/missing", 404, "not found: missing\n"},
		{"POST", "http://cwd/a", 405, "GET only\n"},
		{"GET", control + "/v1/output", 405, "POST only\n"},
		{"GET", control + "/v1/complete", 405, "POST only\n"},
		{"GET", control + "/nothing", 404, "not found\n"},
		{"GET", control + "/health", 200, "ok"},
		{"POST", "http://artifacts/exit?code=7x", 400, "invalid exit code \"7x\"\n"},
		{"GET", "http://unknown.example/", 502, "upstream unreachable\n"},
	} {
		status, h, body := c.do(t, tc.method, tc.url, []byte{})
		if status != tc.status || body != tc.body {
			t.Errorf("%s %s: %d %q, want %d %q", tc.method, tc.url, status, body, tc.status, tc.body)
		}
		if status >= 400 && !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
			t.Errorf("%s %s: Content-Type %q", tc.method, tc.url, h.Get("Content-Type"))
		}
	}
	if status, _, body := c.do(t, "POST", "http://artifacts/", []byte("x")); status != 200 || body != "artifact stored: unnamed (1 bytes)\n" {
		t.Errorf("an artifact with no name: %d %q", status, body)
	}
	if status, _, body := c.do(t, "GET", "http://cwd/a", nil); status != 200 || body != "a" {
		t.Errorf("a file of the context: %d %q", status, body)
	}
}

func TestRefusedUpstreams(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode, host string
	}{
		{relay.ModeHost, "10.1.2.3"},
		{relay.ModeHost, "127.0.0.1"},
		{relay.ModeHost, "169.254.169.254"},
		{relay.ModeHost, "100.100.100.200"},
		{relay.ModeHost, "10.100.0.2"},
		{relay.ModeVM, "10.100.0.2"},
	} {
		t.Run(tc.mode+" "+tc.host, func(t *testing.T) {
			t.Parallel()
			c := claim(t, tc.mode, nil)
			// The address is served upstream, so that only the relay's
			// refusal stops the request.
			ln, err := network(t, c.a, attach.Upstream).Listen(testCtx(t), "tcp", tc.host+":80")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					_, _ = http.ReadRequest(bufio.NewReader(conn))
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
					_ = conn.Close()
				}
			}()
			// The request goes to an address the build can reach, and names
			// the refused one as its Host, which the relay proxies to.
			if status, _, body := c.doHost(t, "http://"+originAddr.String()+"/", tc.host); status != 502 || body != "upstream unreachable\n" {
				t.Errorf("%d %q, want 502 upstream unreachable", status, body)
			}
		})
	}
	t.Run("host a name that resolves to a refused address", func(t *testing.T) {
		t.Parallel()
		c := claim(t, relay.ModeHost, nil)
		c.up.Resolvers[0].Set("inside.example", originAddr, netip.MustParseAddr("192.168.1.1"))
		if status, _, body := c.doHost(t, "http://"+originAddr.String()+"/", "inside.example"); status != 502 || body != "upstream unreachable\n" {
			t.Errorf("%d %q, want 502 upstream unreachable", status, body)
		}
		if n := len(c.up.Origins.Exchanges()); n != 0 {
			t.Errorf("the origin was sent %d requests", n)
		}
	})
	t.Run("container mode refuses none", func(t *testing.T) {
		t.Parallel()
		c := claim(t, relay.ModeContainer, nil)
		ln, err := network(t, c.a, attach.Upstream).Listen(testCtx(t), "tcp", "10.1.2.3:80")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = http.ReadRequest(bufio.NewReader(conn))
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nx-lower: 1\r\n\r\n")
			_ = conn.Close()
		}()
		if status, h, _ := c.do(t, "GET", "http://10.1.2.3/", nil); status != 204 || h.Get("X-Lower") != "1" {
			t.Errorf("%d %v, want the upstream's 204; the relay's log:\n%s", status, h, c.in.Log())
		}
	})
}

func TestNothingRecordedAfterCompletion(t *testing.T) {
	t.Parallel()
	c := claim(t, relay.ModeHost, nil)
	if status, _, _ := c.do(t, "POST", "http://artifacts/exit", nil); status != 200 {
		t.Fatalf("the exit: %d", status)
	}
	waitCompletion(t, c.coll)
	before, _, _ := c.coll.Ledger()
	for _, url := range []string{"http://" + originName + "/", "http://cwd/a"} {
		if status, _, _ := c.do(t, "GET", url, nil); status != 409 {
			t.Errorf("GET %s after the completion: %d, want 409", url, status)
		}
	}
	if status, _, _ := c.do(t, "POST", "http://artifacts/late", []byte("x")); status != 409 {
		t.Errorf("an artifact after the completion: %d, want 409", status)
	}
	if status, _, body := c.do(t, "GET", "http://artifacts/heartbeat", nil); status != 200 || body != "ok\n" {
		t.Errorf("the heartbeat after the completion: %d %q", status, body)
	}
	if after, _, _ := c.coll.Ledger(); !bytes.Equal(before, after) {
		t.Error("the ledger grew after the completion")
	}
	if n := len(c.up.Origins.Exchanges()); n != 0 {
		t.Errorf("the origin was sent %d requests after the completion", n)
	}
}

func TestLeaf(t *testing.T) {
	t.Parallel()
	c := claim(t, relay.ModeHost, nil)
	roots := x509.NewCertPool()
	roots.AddCert(c.ca)
	conn, err := c.env.Dial(testCtx(t), "tcp", originName+":443")
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: originName, RootCAs: roots})
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) != 2 || !chain[1].Equal(c.ca) {
		t.Fatalf("the chain is %d certificates, not the leaf and the CA", len(chain))
	}
	leaf := chain[0]
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != originName || len(leaf.IPAddresses) != 0 {
		t.Errorf("the leaf names %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("the leaf's extended key usage: %v", leaf.ExtKeyUsage)
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != relay.CRLURL {
		t.Errorf("the leaf's CRL distribution points: %v", leaf.CRLDistributionPoints)
	}
}

// TestARP checks the frame link below IP: an ARP request for the relay's
// address is answered with its MAC, one for any other address is not, and
// a frame of another EtherType is not answered.
func TestARP(t *testing.T) {
	t.Parallel()
	ctx := testCtx(t)
	a, err := Relay(relay.ModeHost)
	if err != nil {
		t.Fatal(err)
	}
	up := world(t, network(t, a, attach.Upstream))
	in, err := a.Start(ctx, attach.Params{})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Stop()
	cl := claimant.Claimant{Net: network(t, a, attach.Claim), Endpoint: in.Claim()}
	tun, _, err := cl.Session(ctx, collector.New(collector.Form{}, nil), claimant.Config{UpstreamDNS: up.DNS(),
		BuildLink: &claimant.BuildLink{Prefix: BuildLink.Prefix, Relay: BuildLink.Relay, Guest: BuildLink.Guest}})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	link, _ := in.Frames()
	ask := func(target string) []byte {
		fr := make([]byte, 42)
		copy(fr[0:6], netstack.BroadcastMAC)
		copy(fr[6:12], guestMAC)
		binary.BigEndian.PutUint16(fr[12:14], netstack.EtherTypeARP)
		binary.BigEndian.PutUint16(fr[14:16], 1)
		binary.BigEndian.PutUint16(fr[16:18], netstack.EtherTypeIPv4)
		fr[18], fr[19] = 6, 4
		binary.BigEndian.PutUint16(fr[20:22], 1)
		copy(fr[22:28], guestMAC)
		g := netip.MustParseAddr(BuildLink.Guest).As4()
		copy(fr[28:32], g[:])
		tgt := netip.MustParseAddr(target).As4()
		copy(fr[38:42], tgt[:])
		return fr
	}
	// replyTo reads frames for a while and returns the ARP reply addressed
	// to the guest's MAC, if one comes; the relay's gratuitous ARP is
	// broadcast and is not one.
	replyTo := func(wait time.Duration) []byte {
		buf := make([]byte, 2048)
		deadline := time.Now().Add(wait)
		for {
			_ = link.SetReadDeadline(deadline)
			n, err := link.Read(buf)
			if err != nil {
				return nil
			}
			fr := buf[:n]
			if n >= 42 && bytes.Equal(fr[0:6], guestMAC) && binary.BigEndian.Uint16(fr[12:14]) == netstack.EtherTypeARP {
				return append([]byte(nil), fr...)
			}
		}
	}
	if _, err := link.Write(ask("10.100.0.3")); err != nil {
		t.Fatal(err)
	}
	other := []byte{0x02, 0, 0, 0, 0, 0x0f, 0x02, 0, 0, 0, 0, 0x0e, 0x86, 0xdd, 0, 0, 0, 0}
	_, _ = link.Write(other)
	if fr := replyTo(500 * time.Millisecond); fr != nil {
		t.Errorf("an ARP request for another address, or a frame of another EtherType, was answered: % x", fr)
	}
	if _, err := link.Write(ask(BuildLink.Relay)); err != nil {
		t.Fatal(err)
	}
	fr := replyTo(5 * time.Second)
	if fr == nil {
		t.Fatal("no ARP reply for the relay's address")
	}
	if !bytes.Equal(fr[22:28], relay.RelayMAC) || binary.BigEndian.Uint16(fr[20:22]) != 2 {
		t.Errorf("the ARP reply: % x", fr)
	}
}

// TestFirstMAC: the relay sends its frames to the source of the first frame
// it received, whatever later frames come from (GUEST-4).
func TestFirstMAC(t *testing.T) {
	t.Parallel()
	ctx := testCtx(t)
	a, err := Relay(relay.ModeHost)
	if err != nil {
		t.Fatal(err)
	}
	up := world(t, network(t, a, attach.Upstream))
	in, err := a.Start(ctx, attach.Params{})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Stop()
	cl := claimant.Claimant{Net: network(t, a, attach.Claim), Endpoint: in.Claim()}
	tun, _, err := cl.Session(ctx, collector.New(collector.Form{}, nil), claimant.Config{UpstreamDNS: up.DNS(),
		BuildLink: &claimant.BuildLink{Prefix: BuildLink.Prefix, Relay: BuildLink.Relay, Guest: BuildLink.Guest}})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	link, _ := in.Frames()
	first := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	// The first frame, of an EtherType the relay drops, from first.
	if _, err := link.Write([]byte{0x02, 0, 0, 0, 0, 0x0f, 0x02, 0, 0, 0, 0, 0x0a, 0x86, 0xdd, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	// Then an ARP request for the relay's address from guestMAC.
	fr := make([]byte, 42)
	copy(fr[0:6], netstack.BroadcastMAC)
	copy(fr[6:12], guestMAC)
	binary.BigEndian.PutUint16(fr[12:14], netstack.EtherTypeARP)
	binary.BigEndian.PutUint16(fr[14:16], 1)
	binary.BigEndian.PutUint16(fr[16:18], netstack.EtherTypeIPv4)
	fr[18], fr[19] = 6, 4
	binary.BigEndian.PutUint16(fr[20:22], 1)
	copy(fr[22:28], guestMAC)
	g := netip.MustParseAddr(BuildLink.Guest).As4()
	copy(fr[28:32], g[:])
	r := netip.MustParseAddr(BuildLink.Relay).As4()
	copy(fr[38:42], r[:])
	if _, err := link.Write(fr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = link.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, err := link.Read(buf)
		if err != nil {
			t.Fatalf("no ARP reply for the relay's address: %v", err)
		}
		got := buf[:n]
		if n < 42 || got[0]&1 != 0 || binary.BigEndian.Uint16(got[12:14]) != netstack.EtherTypeARP {
			continue
		}
		if !bytes.Equal(got[0:6], first) {
			t.Errorf("the ARP reply went to %s, want %s, the first frame's source", net.HardwareAddr(got[0:6]), first)
		}
		return
	}
}

// TestStopClosesBuildSide: an instance's Stop returns only once its build
// side listens no more, so that the next instance on the same addresses
// does not meet the last one's listeners.
func TestStopClosesBuildSide(t *testing.T) {
	for _, mode := range []string{relay.ModeVM, relay.ModeContainer} {
		t.Run(mode, func(t *testing.T) {
			c := claim(t, mode, nil)
			addr := ContainerRelay.Addr()
			if mode == relay.ModeVM {
				addr = netip.MustParseAddr(BuildLink.Relay)
			}
			n := network(t, c.a, attach.Build)
			ctx := testCtx(t)
			conn, err := n.Dial(ctx, "tcp", netip.AddrPortFrom(addr, relay.PortControl).String())
			if err != nil {
				t.Fatalf("before Stop: %v", err)
			}
			_ = conn.Close()
			if err := c.in.Stop(); err != nil {
				t.Fatal(err)
			}
			for _, port := range []uint16{relay.PortControl, relay.PortDNS} {
				if conn, err := n.Dial(ctx, "tcp", netip.AddrPortFrom(addr, port).String()); err == nil {
					_ = conn.Close()
					t.Errorf("after Stop the build side accepted a connection to %s:%d", addr, port)
				}
			}
		})
	}
}
