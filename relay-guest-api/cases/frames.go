package cases

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// arpAnswered: an ARP request for the relay's address is answered with an
// ARP reply that gives the relay's MAC address; requests for other
// addresses, on the link and off it, are not answered.
var arpAnswered = runner.Case{
	Name:    "on a frame link, ARP for the relay's address is answered with its MAC address, and ARP for any other is not",
	Cites:   []string{"GUEST-3"},
	Role:    "relay",
	Ends:    true,
	Applies: onFrames,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		p := newParty(t, r.frames(), guestMAC, r.guestAddr())
		relay := r.relayAddr()
		from := p.mark()
		p.send(arpFrame(guestMAC, netstack.BroadcastMAC, arp{Op: arpRequest, SenderMAC: guestMAC, SenderIP: p.ip, TargetMAC: make(net.HardwareAddr, 6), TargetIP: relay}))
		f, ok := p.await(from, within, func(b []byte) bool {
			m, ok := parseARP(b)
			return ok && m.Op == arpReply && m.SenderIP == relay && m.TargetIP == p.ip
		})
		if !ok {
			t.Fatalf("no ARP reply to the request for the relay's address %s within %s", relay, within)
		}
		m, _ := parseARP(f.Bytes)
		if len(m.SenderMAC) != 6 || bytes.Equal(m.SenderMAC, netstack.BroadcastMAC) || bytes.Equal(m.SenderMAC, make(net.HardwareAddr, 6)) || m.SenderMAC[0]&1 != 0 {
			t.Errorf("the ARP reply gives %s as the relay's MAC address, which is not a unicast address", m.SenderMAC)
		}
		if src := net.HardwareAddr(f.Bytes[6:12]); !bytes.Equal(src, m.SenderMAC) {
			t.Errorf("the ARP reply gives the MAC address %s, and its frame came from %s", m.SenderMAC, src)
		}
		if !bytes.Equal(m.TargetMAC, guestMAC) {
			t.Errorf("the ARP reply's target MAC address is %s, want the requester's %s", m.TargetMAC, guestMAC)
		}

		var others []netip.Addr
		for a := r.linkPrefix().Masked().Addr(); r.linkPrefix().Contains(a); a = a.Next() {
			if a != relay && a != p.ip {
				others = append(others, a)
			}
		}
		others = append(others, originAddr, netip.MustParseAddr("203.0.113.99"), netip.MustParseAddr("8.8.8.8"))
		from = p.mark()
		for _, a := range others {
			p.send(arpFrame(guestMAC, netstack.BroadcastMAC, arp{Op: arpRequest, SenderMAC: guestMAC, SenderIP: p.ip, TargetMAC: make(net.HardwareAddr, 6), TargetIP: a}))
		}
		// A last request for the relay's address, whose reply comes after
		// any the relay would give to the others.
		p.send(arpFrame(guestMAC, netstack.BroadcastMAC, arp{Op: arpRequest, SenderMAC: guestMAC, SenderIP: p.ip, TargetMAC: make(net.HardwareAddr, 6), TargetIP: relay}))
		if _, ok := p.await(from, within, func(b []byte) bool {
			m, ok := parseARP(b)
			return ok && m.Op == arpReply && m.SenderIP == relay && m.TargetIP == p.ip
		}); !ok {
			t.Fatalf("no ARP reply to a second request for the relay's address within %s", within)
		}
		time.Sleep(quiet)
		for _, f := range p.since(from) {
			m, ok := parseARP(f.Bytes)
			if !ok || m.Op != arpReply {
				continue
			}
			for _, a := range others {
				if m.SenderIP == a {
					t.Errorf("the relay answered the ARP request for %s, which is not its address, giving %s", a, m.SenderMAC)
				}
			}
		}
	},
}

// macLearned: the build environment's stack is given the frame link
// through a tap, takes its lease, and sends DNS, the readiness poll and a
// captured connection. Every frame the relay sent before the build
// environment's first is to the broadcast address, and every IPv4 frame
// after it to the build environment's MAC address.
var macLearned = runner.Case{
	Name:    "on a frame link, the relay sends to the MAC address of the first frame it receives, and before it to the broadcast address",
	Cites:   []string{"GUEST-4"},
	Role:    "relay",
	Ends:    true,
	Applies: onFrames,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		// Frames the relay sent before the build environment's first: the
		// stack is given the link a moment after the claim, so that the
		// announcement of GUEST-5 is among them.
		time.Sleep(600 * time.Millisecond)
		link := &tap{Conn: r.frames()}
		env := r.build(link)
		if _, err := env.Resolve(t.Context(), "artifacts"); err != nil {
			t.Fatalf("the build's DNS: %v", err)
		}
		if status, _, err := heartbeatAt(t.Context(), env, netip.MustParseAddrPort("192.0.2.201:80")); err != nil || status != http.StatusOK {
			t.Fatalf("GET http://artifacts/heartbeat over a connection to 192.0.2.201:80: %d, %v", status, err)
		}
		sent, after := false, 0
		for _, f := range link.all() {
			switch {
			case f.Out:
				sent = true
			case !sent:
				if !bytes.Equal(dstMAC(f.Bytes), netstack.BroadcastMAC) {
					t.Errorf("before the build environment's first frame the relay sent a frame of EtherType %#04x to %s, not to the broadcast address", etherType(f.Bytes), dstMAC(f.Bytes))
				}
			case etherType(f.Bytes) == netstack.EtherTypeIPv4:
				after++
				if !bytes.Equal(dstMAC(f.Bytes), guestMAC) {
					t.Errorf("after the build environment's first frame, from %s, the relay sent an IPv4 frame to %s", guestMAC, dstMAC(f.Bytes))
				}
			}
		}
		if after == 0 {
			t.Errorf("the relay sent no IPv4 frame after the build environment's first frame")
		}
	},
}

// announced: from the claim's 200 on, the relay broadcasts gratuitous ARP
// for its address, more than once.
var announced = runner.Case{
	Name:    "on a frame link, the relay announces its address with gratuitous ARP, broadcast, from the start of the link",
	Cites:   []string{"GUEST-5"},
	Role:    "relay",
	Ends:    true,
	Applies: onFrames,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		claimed := time.Now()
		p := newParty(t, r.frames(), guestMAC, r.guestAddr())
		relay := r.relayAddr()
		// Two announcements within this bound: the Go relay's is every
		// 500 ms (relay-guest-api, GUEST-5).
		const bound = 3 * time.Second
		f1, i, ok := p.awaitAt(0, bound, func(b []byte) bool { return gratuitous(b, relay) })
		if !ok {
			t.Fatalf("no gratuitous ARP for %s within %s of the claim's 200", relay, bound)
		}
		f2, ok := p.await(i+1, bound-time.Since(claimed), func(b []byte) bool { return gratuitous(b, relay) })
		if !ok {
			t.Fatalf("one gratuitous ARP for %s and no second within %s of the claim's 200", relay, bound)
		}
		for _, f := range []frame{f1, f2} {
			m, _ := parseARP(f.Bytes)
			if src := net.HardwareAddr(f.Bytes[6:12]); !bytes.Equal(src, m.SenderMAC) {
				t.Errorf("a gratuitous ARP gives the MAC address %s, and its frame came from %s", m.SenderMAC, src)
			}
		}
		mac := p.relayMAC(relay)
		if m, _ := parseARP(f1.Bytes); !bytes.Equal(m.SenderMAC, mac) {
			t.Errorf("the gratuitous ARP gives %s as the relay's MAC address, and its ARP reply %s", m.SenderMAC, mac)
		}
	},
}

// heartbeatAt sends GET /heartbeat with Host: artifacts, and Connection:
// close, over a connection the build environment makes to at, and returns
// the status and body.
func heartbeatAt(ctx context.Context, env *buildenv.Env, at netip.AddrPort) (int, []byte, error) {
	return httpAt(ctx, env, at, nil, "", "GET /heartbeat HTTP/1.1\r\nHost: artifacts\r\nConnection: close\r\n\r\n")
}

// httpAt sends the request req over a connection the build environment
// makes to at, over TLS with serverName when roots is given, and returns
// the response's status and body.
func httpAt(ctx context.Context, env *buildenv.Env, at netip.AddrPort, roots *x509.CertPool, serverName, req string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	c, err := env.Network().Dial(ctx, "tcp", at.String())
	if err != nil {
		return 0, nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if roots != nil {
		tc := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, nil, fmt.Errorf("the TLS handshake: %w", err)
		}
		c = tc
	}
	if _, err := io.WriteString(c, req); err != nil {
		return 0, nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// captured: the build environment connects to addresses and ports that
// are not the relay's, and each connection is served by its port: 443 is
// TLS interception, 8300 the control plane, and the others the HTTP proxy,
// which serves the reserved host artifacts.
var captured = runner.Case{
	Name:    "on a frame link, a TCP connection to any address and port is accepted and served by its port alone",
	Cites:   []string{"GUEST-6"},
	Role:    "relay",
	Ends:    true,
	Applies: onFrames,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		ctx := t.Context()
		roots := x509.NewCertPool()
		roots.AddCert(r.ca)
		relay := r.relayAddr().String()
		for _, at := range []string{"203.0.113.99:443", relay + ":443", "192.0.2.201:443"} {
			status, b, err := httpAt(ctx, env, netip.MustParseAddrPort(at), roots, "artifacts", "GET /heartbeat HTTP/1.1\r\nHost: artifacts\r\nConnection: close\r\n\r\n")
			if err != nil || status != http.StatusOK || string(b) != "ok\n" {
				t.Errorf("GET https://artifacts/heartbeat over TLS to %s: %d %q, %v; want the reserved host's 200 through interception", at, status, b, err)
			}
		}
		for _, at := range []string{"198.51.100.77:8300", relay + ":8300", "192.0.2.201:8300"} {
			status, b, err := httpAt(ctx, env, netip.MustParseAddrPort(at), nil, "", "GET /health HTTP/1.1\r\nHost: control\r\nConnection: close\r\n\r\n")
			if err != nil || status != http.StatusOK || string(b) != "ok" {
				t.Errorf("GET /health over a connection to %s: %d %q, %v; want the control plane's 200 ok", at, status, b, err)
			}
		}
		for _, at := range []string{"192.0.2.201:80", "203.0.113.99:12345", relay + ":8080", "198.51.100.77:22"} {
			status, b, err := heartbeatAt(ctx, env, netip.MustParseAddrPort(at))
			if err != nil || status != http.StatusOK || string(b) != "ok\n" {
				t.Errorf("GET http://artifacts/heartbeat over a connection to %s: %d %q, %v; want the proxy's port, which serves the reserved host", at, status, b, err)
			}
		}
	},
}

// udpOnly: on a frame link, a DNS query to port 53 of the relay's address
// is answered; a query to port 53 of an upstream resolver's address is
// neither answered nor forwarded there; UDP to another port, of the
// relay's address or another, is not answered; and frames of other
// EtherTypes are not answered. ICMP is not defined by the specification
// and is let through.
var udpOnly = runner.Case{
	Name:    "on a frame link, UDP is served only at port 53 of the relay's address, and a frame neither ARP nor IPv4 is not answered",
	Cites:   []string{"GUEST-7"},
	Role:    "relay",
	Ends:    true,
	Applies: onFrames,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		p := newParty(t, r.frames(), guestMAC, r.guestAddr())
		relay := r.relayAddr()
		mac := p.relayMAC(relay)
		query := func(name string, id uint16) []byte {
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(name), dns.TypeA)
			q.Id = id
			b, err := q.Pack()
			if err != nil {
				t.Fatalf("a DNS query: %v", err)
			}
			return b
		}
		// The control: a query to the relay's own port 53 is answered.
		from := p.mark()
		p.udp(mac, 40053, netip.AddrPortFrom(relay, 53), query("artifacts", 0x5301))
		if _, ok := p.await(from, within, udpTo(40053)); !ok {
			t.Fatalf("no answer to a DNS query to %s:53 within %s", relay, within)
		}

		from = p.mark()
		p.udp(mac, 40054, netip.AddrPortFrom(firstResolver, 53), query(originName, 0x5302))
		p.udp(mac, 40055, netip.AddrPortFrom(relay, 5353), query(originName, 0x5303))
		p.udp(mac, 40056, netip.AddrPortFrom(originAddr, 9999), []byte("conformance"))
		p.udp(mac, 40057, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.99"), 53), query("artifacts", 0x5304))
		ipv6 := make([]byte, ethHeader+40+8)
		copy(ipv6[0:6], mac)
		copy(ipv6[6:12], guestMAC)
		ipv6[12], ipv6[13] = 0x86, 0xdd
		ipv6[ethHeader] = 0x60
		ipv6[ethHeader+5] = 8  // payload length
		ipv6[ethHeader+6] = 17 // UDP
		ipv6[ethHeader+7] = 64
		p.send(ipv6)
		other := make([]byte, 60)
		copy(other[0:6], netstack.BroadcastMAC)
		copy(other[6:12], guestMAC)
		other[12], other[13] = 0x88, 0xb5 // local experimental
		p.send(other)
		// A last query to the relay, whose answer comes after any the relay
		// would give to the others.
		p.udp(mac, 40058, netip.AddrPortFrom(relay, 53), query("cwd", 0x5305))
		if _, ok := p.await(from, within, udpTo(40058)); !ok {
			t.Fatalf("no answer to a second DNS query to %s:53 within %s", relay, within)
		}
		time.Sleep(quiet)
		for _, f := range p.since(from) {
			switch etherType(f.Bytes) {
			case netstack.EtherTypeARP:
			case netstack.EtherTypeIPv4:
				u, ok := netstack.ParseUDPFrame(f.Bytes)
				if ok && u.Dst.Port() >= 40054 && u.Dst.Port() <= 40057 {
					t.Errorf("the relay answered the datagram to port %d with a datagram from %s", u.Dst.Port(), u.Src)
				}
			default:
				t.Errorf("the relay sent a frame of EtherType %#04x", etherType(f.Bytes))
			}
		}
		for _, q := range r.up.Resolvers[0].Queries() {
			t.Errorf("the resolver at %s received the query for %s sent to its address on the build link: the relay forwarded the build's datagram", firstResolver, q.Name)
		}
	},
}
