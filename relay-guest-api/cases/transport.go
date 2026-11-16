package cases

import (
	"context"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// ownAddress: the relay serves the build at its own address on the build
// link: on a frame link the build environment, which learns the relay's
// address from the lease, reaches it at the build_link's relay address,
// and on either kind of link DNS asked of the relay answers the reserved
// names with that address. The lease's fields themselves are GUEST-9's,
// checked by leaseAnswered; on a kernel interface the case gives the build
// environment the declared address, so there is nothing to compare.
var ownAddress = runner.Case{
	Name:  "the relay serves the build environment over IPv4 at its own address on the build link",
	Cites: []string{"GUEST-1"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		relay := r.relayAddr()
		if r.d.Link == buildenv.Frames && env.Relay() != relay {
			t.Errorf("the build environment reaches the relay at %s, the lease's server identifier, want %s", env.Relay(), relay)
		}
		as, err := env.Resolve(t.Context(), "artifacts")
		if err != nil {
			t.Fatalf("A artifacts from the build, asked of %s: %v", env.DNSServer(), err)
		}
		if len(as) != 1 || as[0] != relay || !as[0].Is4() {
			t.Errorf("artifacts resolves to %v, want the relay's IPv4 address %s", as, relay)
		}
	},
}

// interfacePorts: on a kernel interface the relay serves, at its own
// address, DNS on UDP and TCP port 53, the proxy on 80, interception on
// 443 and the control plane on 8300. Each is reached with a request it
// answers; what the answers hold is the cases' of each service.
var interfacePorts = runner.Case{
	Name:    "on a kernel interface, the relay serves DNS on UDP and TCP port 53, the proxy on 80, interception on 443 and the control plane on 8300",
	Cites:   []string{"GUEST-2"},
	Role:    "relay",
	Ends:    true,
	Applies: onInterface,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		ctx := t.Context()
		relay := r.relayAddr()
		for i, tr := range []string{"udp", "tcp"} {
			if _, err := env.Exchange(ctx, tr, question("cwd", dns.TypeA, uint16(0x0201+i))); err != nil {
				t.Errorf("DNS over %s at %s:53: %v", tr, relay, err)
			}
		}
		if status, _, err := heartbeatAt(ctx, env, netip.AddrPortFrom(relay, 80)); err != nil || status == 0 {
			t.Errorf("an HTTP request to %s:80 was not answered: %v", relay, err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(r.ca)
		if status, _, err := httpAt(ctx, env, netip.AddrPortFrom(relay, 443), roots, "artifacts", "GET /heartbeat HTTP/1.1\r\nHost: artifacts\r\nConnection: close\r\n\r\n"); err != nil || status == 0 {
			t.Errorf("an HTTP request over TLS to %s:443, trusting the claim's ca_cert, was not answered: %v", relay, err)
		}
		if status, _, err := httpAt(ctx, env, netip.AddrPortFrom(relay, 8300), nil, "", "GET /health HTTP/1.1\r\nHost: control\r\nConnection: close\r\n\r\n"); err != nil || status == 0 {
			t.Errorf("an HTTP request to %s:8300 was not answered: %v", relay, err)
		}
	},
}

// beforeClaim: before the claim nothing on the build link is answered: a
// DISCOVER, an ARP request and a DNS query on a frame link; a DISCOVER on
// a kernel interface with a build_link; and on one whose address the
// launcher gives, DNS and the TCP ports at that address. On a frame link,
// once the claim has been answered, each of those is answered at the first
// asking, and on a kernel interface with a build_link the lease: a relay
// on a kernel interface may still be binding its other ports (D19).
var beforeClaim = runner.Case{
	Name:  "the relay serves nothing on the build link before its claim, and the lease, and on a frame link every service, once it answers the claim",
	Cites: []string{"GUEST-51"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		switch {
		case r.d.Link == buildenv.Frames:
			beforeClaimFrames(t, r)
		case r.d.BuildLink != nil:
			beforeClaimLease(t, r)
		default:
			beforeClaimAddress(t, r)
		}
	},
}

func beforeClaimFrames(t *runner.T, r *relayRun) {
	p := newParty(t, r.frames(), guestMAC, r.guestAddr())
	relay := r.relayAddr()
	s := leaseOnFrames(t, p)
	arpFor := func() []byte {
		return arpFrame(guestMAC, netstack.BroadcastMAC, arp{Op: arpRequest, SenderMAC: guestMAC, SenderIP: p.ip, TargetMAC: make([]byte, 6), TargetIP: relay})
	}
	dnsQuery := func(id uint16) []byte {
		b, err := question("artifacts", dns.TypeA, id).Pack()
		if err != nil {
			t.Fatalf("a DNS query: %v", err)
		}
		return b
	}
	s.send(clientMessage(dhcp.Discover, newXID(), guestMAC).Marshal())
	p.send(arpFor())
	p.udp(netstack.BroadcastMAC, 40100, netip.AddrPortFrom(relay, 53), dnsQuery(0x5101))
	time.Sleep(quiet)
	if fs := p.since(0); len(fs) > 0 {
		t.Errorf("before its claim the relay sent %d frames on its frame link, the first of EtherType %#04x", len(fs), etherType(fs[0].Bytes))
	}
	r.claim()
	from := p.mark()
	xid := newXID()
	s.send(clientMessage(dhcp.Discover, xid, guestMAC).Marshal())
	p.send(arpFor())
	if _, ok := p.await(from, within, func(b []byte) bool {
		m, ok := parseARP(b)
		return ok && m.Op == arpReply && m.SenderIP == relay && m.TargetIP == p.ip
	}); !ok {
		t.Errorf("the ARP request for %s sent once after the claim's 200 was not answered within %s", relay, within)
	}
	if _, ok := s.awaitXID(xid, within); !ok {
		t.Errorf("the DISCOVER sent once after the claim's 200 was not answered within %s", within)
	}
	mac := p.relayMAC(relay)
	p.udp(mac, 40101, netip.AddrPortFrom(relay, 53), dnsQuery(0x5102))
	if _, ok := p.await(from, within, udpTo(40101)); !ok {
		t.Errorf("the DNS query sent once after the claim's 200 was not answered within %s", within)
	}
}

func beforeClaimLease(t *runner.T, r *relayRun) {
	pc, err := t.Network(attach.Build).ListenPacket(t.Context(), "udp", unassigned.String())
	if err != nil {
		t.Fatalf("the DHCP client's port on the build link: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	s := packetLease(t, pc)
	s.send(clientMessage(dhcp.Discover, newXID(), guestMAC).Marshal())
	time.Sleep(quiet)
	if reps := s.all(); len(reps) > 0 {
		t.Errorf("before its claim the relay answered a DISCOVER with %d bytes from %s", len(reps[0].Raw), reps[0].Src)
	}
	r.claim()
	xid := newXID()
	s.send(clientMessage(dhcp.Discover, xid, guestMAC).Marshal())
	if _, ok := s.awaitXID(xid, within); !ok {
		t.Errorf("the DISCOVER sent once after the claim's 200 was not answered within %s", within)
	}
}

func beforeClaimAddress(t *runner.T, r *relayRun) {
	relay := r.relayAddr()
	n := t.Network(attach.Build)
	ctx, cancel := context.WithTimeout(t.Context(), quiet)
	defer cancel()
	for _, port := range []uint16{53, 80, 443, 8300} {
		if c, err := n.Dial(ctx, "tcp", netip.AddrPortFrom(relay, port).String()); err == nil {
			_ = c.Close()
			t.Errorf("before its claim the relay accepted a TCP connection to %s:%d", relay, port)
		}
	}
	env, err := buildenv.Start(t.Context(), buildenv.Config{Link: buildenv.IP, Network: n, Relay: relay})
	if err != nil {
		t.Fatalf("the build environment: %v", err)
	}
	t.Cleanup(func() { _ = env.Close() })
	qctx, qcancel := context.WithTimeout(t.Context(), quiet)
	defer qcancel()
	if ans, err := env.Exchange(qctx, "udp", question("artifacts", dns.TypeA, 0x5103)); err == nil {
		t.Errorf("before its claim the relay answered DNS at %s:53: %v", relay, ans.Answer)
	}
	r.claim()
	if err := env.Ready(t.Context()); err != nil {
		t.Errorf("after its claim: %v", err)
	}
}
