package cases

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

var (
	limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	toServer         = netip.AddrPortFrom(limitedBroadcast, dhcp.ServerPort)
	unassigned       = netip.AddrPortFrom(netip.IPv4Unspecified(), dhcp.ClientPort)
)

// leaseReply is one datagram the relay sent to the client's port 68.
type leaseReply struct {
	Raw []byte
	// Src is where it came from. Dst is where it was sent, on a frame
	// link; on a kernel interface the socket does not say, and it is not
	// valid.
	Src, Dst netip.AddrPort
}

// xid is the transaction ID of a BOOTP message's bytes, or false for one
// too short to have one.
func (r leaseReply) xid() (uint32, bool) {
	if len(r.Raw) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint32(r.Raw[4:8]), true
}

// leaseSide is the client's end of the address lease, on either kind of
// link: on a frame link it sends each message in a broadcast frame from
// 0.0.0.0:68 to 255.255.255.255:67 and reads the replies off the party;
// on a kernel interface it is a datagram socket on port 68 of the build
// environment's network, which sends to 255.255.255.255:67.
type leaseSide struct {
	t    *runner.T
	send func([]byte)

	mu      sync.Mutex
	replies []leaseReply
	kick    chan struct{}
}

// leaseOnFrames is the lease's client side on the party p.
func leaseOnFrames(t *runner.T, p *party) *leaseSide {
	s := &leaseSide{t: t, kick: make(chan struct{}, 1)}
	s.send = func(msg []byte) {
		p.send(netstack.UDPFrame{
			SrcMAC: p.mac, DstMAC: netstack.BroadcastMAC,
			Src: unassigned, Dst: toServer, Payload: msg,
		}.Marshal())
	}
	go func() {
		from := 0
		for {
			f, i, ok := p.awaitAt(from, time.Hour, udpTo(dhcp.ClientPort))
			if !ok {
				return
			}
			from = i + 1
			u, _ := netstack.ParseUDPFrame(f.Bytes)
			s.add(leaseReply{Raw: u.Payload, Src: u.Src, Dst: u.Dst})
		}
	}()
	return s
}

// leaseOnInterface is the lease's client side on the build environment's
// network of a kernel interface.
func leaseOnInterface(t *runner.T, env *buildenv.Env) *leaseSide {
	pc, err := env.Network().ListenPacket(t.Context(), "udp", unassigned.String())
	if err != nil {
		t.Fatalf("the DHCP client's port on the build link: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return packetLease(t, pc)
}

// packetLease is the lease's client side on pc, a datagram socket bound
// to port 68.
func packetLease(t *runner.T, pc net.PacketConn) *leaseSide {
	s := &leaseSide{t: t, kick: make(chan struct{}, 1)}
	s.send = func(msg []byte) {
		if _, err := pc.WriteTo(msg, net.UDPAddrFromAddrPort(toServer)); err != nil {
			t.Fatalf("sending to %s: %v", toServer, err)
		}
	}
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			src, _ := netip.ParseAddrPort(from.String())
			s.add(leaseReply{Raw: append([]byte(nil), buf[:n]...), Src: src})
		}
	}()
	return s
}

func (s *leaseSide) add(r leaseReply) {
	s.mu.Lock()
	s.replies = append(s.replies, r)
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// all is every reply so far.
func (s *leaseSide) all() []leaseReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]leaseReply(nil), s.replies...)
}

// ask sends m, again every dhcp.Retransmit as a client does, until a reply
// with m's xid comes after the first sending, for at most within, and
// returns the reply and the message it holds; it fails the case when none
// comes or the reply cannot be read.
func (s *leaseSide) ask(what string, m dhcp.Message) (leaseReply, dhcp.Message) {
	t := s.t
	deadline := time.Now().Add(within)
	start := s.count()
	msg := m.Marshal()
	for {
		s.send(msg)
		next := time.NewTimer(dhcp.Retransmit)
		for {
			if r, ok := s.findFrom(start, m.Xid); ok {
				next.Stop()
				got, err := dhcp.Parse(r.Raw)
				if err != nil {
					t.Fatalf("the reply to %s: %v", what, err)
				}
				return r, got
			}
			select {
			case <-s.kick:
				continue
			case <-next.C:
			case <-t.Context().Done():
				t.Fatalf("waiting for the reply to %s: %v", what, t.Context().Err())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reply to %s within %s", what, within)
		}
	}
}

// awaitXID waits for at most d for a reply with xid, sending nothing.
func (s *leaseSide) awaitXID(xid uint32, d time.Duration) (leaseReply, bool) {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		if r, ok := s.find(xid); ok {
			return r, true
		}
		select {
		case <-s.kick:
		case <-deadline.C:
			return leaseReply{}, false
		case <-s.t.Context().Done():
			return leaseReply{}, false
		}
	}
}

// count is the number of replies so far.
func (s *leaseSide) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.replies)
}

// find is the first reply with xid.
func (s *leaseSide) find(xid uint32) (leaseReply, bool) { return s.findFrom(0, xid) }

// findFrom is the first reply with xid from index from on.
func (s *leaseSide) findFrom(from int, xid uint32) (leaseReply, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.replies[min(from, len(s.replies)):] {
		if x, ok := r.xid(); ok && x == xid {
			return r, true
		}
	}
	return leaseReply{}, false
}

// lease is the client's side of the address lease on the relay's build
// link, after the claim: on a frame link a party, on a kernel interface the
// build environment's socket once the relay serves GET /health.
func (r *relayRun) lease() *leaseSide {
	if r.d.Link == buildenv.Frames {
		return leaseOnFrames(r.t, newParty(r.t, r.frames(), guestMAC, r.guestAddr()))
	}
	return leaseOnInterface(r.t, r.build(nil))
}

// clientMessage is a client's message of type typ, for chaddr, with opts
// after option 53.
func clientMessage(typ byte, xid uint32, chaddr net.HardwareAddr, opts ...dhcp.Option) dhcp.Message {
	return dhcp.Message{
		Op: dhcp.BootRequest, HType: 1, HLen: 6, Xid: xid, Flags: 0x8000,
		Chaddr:  chaddr,
		Options: append([]dhcp.Option{{Code: dhcp.OptMessageType, Data: []byte{typ}}}, opts...),
	}
}

// newXID is a transaction ID for one exchange.
func newXID() uint32 { return rand.Uint32() }

// checkLease checks a reply to a client's message m against GUEST-8 and
// GUEST-9: from the relay's address at port 67 (and, on a frame link, to
// 255.255.255.255:68), a BOOTREPLY of type want for m's xid and chaddr,
// with the lease of the claim's build_link.
func (r *relayRun) checkLease(what string, rep leaseReply, got dhcp.Message, m dhcp.Message, want byte) {
	t := r.t
	relay, guest, prefix := r.relayAddr(), r.guestAddr(), r.linkPrefix()
	if rep.Src != netip.AddrPortFrom(relay, dhcp.ServerPort) {
		t.Errorf("%s came from %s, want %s", what, rep.Src, netip.AddrPortFrom(relay, dhcp.ServerPort))
	}
	if rep.Dst.IsValid() && rep.Dst != netip.AddrPortFrom(limitedBroadcast, dhcp.ClientPort) {
		t.Errorf("%s was sent to %s, want 255.255.255.255:68", what, rep.Dst)
	}
	if got.Op != dhcp.BootReply || got.HType != 1 || got.HLen != 6 {
		t.Errorf("%s has op %d, htype %d, hlen %d; want 2, 1, 6", what, got.Op, got.HType, got.HLen)
	}
	if got.Xid != m.Xid {
		t.Errorf("%s has xid %#x, want the request's %#x", what, got.Xid, m.Xid)
	}
	if got.Yiaddr != guest {
		t.Errorf("%s has yiaddr %s, want the build_link's guest %s", what, got.Yiaddr, guest)
	}
	if got.Siaddr != relay {
		t.Errorf("%s has siaddr %s, want the relay's %s", what, got.Siaddr, relay)
	}
	if !bytes.Equal(got.Chaddr, m.Chaddr[:6]) {
		t.Errorf("%s has chaddr %s, want the request's %s", what, got.Chaddr, m.Chaddr)
	}
	if typ := got.Type(); typ != want {
		t.Errorf("%s has message type (option 53) %d, want %d", what, typ, want)
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	r4 := relay.As4()
	for _, o := range []struct {
		code byte
		name string
		want []byte
	}{
		{dhcp.OptServerID, "server identifier", r4[:]},
		{dhcp.OptLeaseTime, "lease time", []byte{0xff, 0xff, 0xff, 0xff}},
		{dhcp.OptSubnetMask, "subnet mask", mask},
		{dhcp.OptRouter, "router", r4[:]},
		{dhcp.OptDNS, "domain name server", r4[:]},
	} {
		d, ok := got.Option(o.code)
		switch {
		case !ok:
			t.Errorf("%s has no %s (option %d)", what, o.name, o.code)
		case !bytes.Equal(d, o.want):
			t.Errorf("%s has %s (option %d) %v, want %v", what, o.name, o.code, d, o.want)
		}
	}
}

// leaseAnswered: a DISCOVER is answered with an OFFER, and the REQUEST for
// what it offered with an ACK, each giving the lease of the claim's
// build_link.
var leaseAnswered = runner.Case{
	Name:    "a DISCOVER is answered with an OFFER and a REQUEST with an ACK, each giving the build_link's lease",
	Cites:   []string{"GUEST-8", "GUEST-9"},
	Role:    "relay",
	Ends:    true,
	Applies: servesLease,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		s := r.lease()
		xid := newXID()
		disc := clientMessage(dhcp.Discover, xid, guestMAC, dhcp.Option{Code: dhcp.OptParams, Data: []byte{dhcp.OptSubnetMask, dhcp.OptRouter, dhcp.OptDNS}})
		rep, offer := s.ask("the DISCOVER", disc)
		r.checkLease("the reply to the DISCOVER", rep, offer, disc, dhcp.Offer)
		relay := r.relayAddr().As4()
		req := clientMessage(dhcp.Request, xid, guestMAC,
			dhcp.Option{Code: dhcp.OptRequestedIP, Data: offer.Yiaddr.AsSlice()},
			dhcp.Option{Code: dhcp.OptServerID, Data: relay[:]})
		rep, ack := s.ask("the REQUEST", req)
		r.checkLease("the reply to the REQUEST", rep, ack, req, dhcp.Ack)
	},
}

// leaseStateless: DISCOVERs and REQUESTs that ask for other addresses and
// name other clients and servers are each answered with the same lease,
// and no REQUEST with a NAK.
var leaseStateless = runner.Case{
	Name:    "every DISCOVER and REQUEST is given the same lease, whatever it asks for, and no REQUEST a NAK",
	Cites:   []string{"GUEST-10"},
	Role:    "relay",
	Ends:    true,
	Applies: servesLease,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		s := r.lease()
		// other is an address the lease does not give: the first of the
		// build link's after its network address that is neither the
		// relay's nor the guest's, or else one outside it.
		other := netip.MustParseAddr("192.0.2.9")
		for a := r.linkPrefix().Masked().Addr().Next(); r.linkPrefix().Contains(a); a = a.Next() {
			if a != r.relayAddr() && a != r.guestAddr() {
				other = a
				break
			}
		}
		requested := func(a netip.Addr) dhcp.Option { return dhcp.Option{Code: dhcp.OptRequestedIP, Data: a.AsSlice()} }
		serverID := func(a netip.Addr) dhcp.Option { return dhcp.Option{Code: dhcp.OptServerID, Data: a.AsSlice()} }
		macs := []net.HardwareAddr{guestMAC, {0x02, 0, 0, 0, 0x0c, 0x04}, {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}}
		for i, mac := range macs {
			for _, v := range []struct {
				what string
				typ  byte
				want byte
				opts []dhcp.Option
			}{
				{"a DISCOVER", dhcp.Discover, dhcp.Offer, nil},
				{"a DISCOVER that asks for " + other.String(), dhcp.Discover, dhcp.Offer, []dhcp.Option{requested(other)}},
				{"a REQUEST for " + other.String(), dhcp.Request, dhcp.Ack, []dhcp.Option{requested(other), serverID(r.relayAddr())}},
				{"a REQUEST that names the server " + other.String(), dhcp.Request, dhcp.Ack, []dhcp.Option{requested(r.guestAddr()), serverID(other)}},
				{"a REQUEST with neither a requested address nor a server", dhcp.Request, dhcp.Ack, nil},
			} {
				m := clientMessage(v.typ, newXID(), mac, v.opts...)
				what := v.what + " from " + mac.String()
				if i == 0 && v.typ == dhcp.Request {
					// A client that renews sends from its address.
					m.Ciaddr = other
					what += " with ciaddr " + other.String()
				}
				rep, got := s.ask(what, m)
				if got.Type() == dhcp.Nak {
					t.Errorf("%s was answered with a DHCPNAK", what)
					continue
				}
				r.checkLease("the reply to "+what, rep, got, m, v.want)
			}
		}
	},
}

// leaseIgnores: the relay answers no DHCP or BOOTP message but a DISCOVER
// and a REQUEST. Each is sent once with an xid of its own, then a DISCOVER,
// whose OFFER shows that the relay is serving; no reply may carry the
// others' xids.
var leaseIgnores = runner.Case{
	Name:    "a BOOTREPLY, a DECLINE, RELEASE or INFORM, and a message that is short, truncated or lacks the cookie or option 53 are not answered",
	Cites:   []string{"GUEST-11"},
	Role:    "relay",
	Ends:    true,
	Applies: servesLease,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		s := r.lease()
		// The OFFER to a first DISCOVER shows the client's side works
		// before anything is sent that must not be answered.
		s.ask("a first DISCOVER", clientMessage(dhcp.Discover, newXID(), guestMAC))
		ignored := map[uint32]string{}
		send := func(what string, xid uint32, b []byte) {
			ignored[xid] = what
			s.send(b)
		}
		for _, v := range []struct {
			what string
			typ  byte
		}{{"a DHCPDECLINE", dhcp.Decline}, {"a DHCPRELEASE", dhcp.Release}, {"a DHCPINFORM", dhcp.Inform}, {"a DHCPOFFER sent as a request", dhcp.Offer}, {"a DHCPACK sent as a request", dhcp.Ack}} {
			x := newXID()
			send(v.what, x, clientMessage(v.typ, x, guestMAC).Marshal())
		}
		x := newXID()
		reply := clientMessage(dhcp.Discover, x, guestMAC)
		reply.Op = dhcp.BootReply
		send("a BOOTREPLY of type DISCOVER", x, reply.Marshal())

		x = newXID()
		b := clientMessage(dhcp.Discover, x, guestMAC).Marshal()
		copy(b[dhcp.MinLen-4:dhcp.MinLen], []byte{0, 0, 0, 0})
		send("a DISCOVER without the magic cookie", x, b)

		x = newXID()
		send("a message without option 53", x, dhcp.Message{
			Op: dhcp.BootRequest, HType: 1, HLen: 6, Xid: x, Chaddr: guestMAC,
			Options: []dhcp.Option{{Code: 12, Data: []byte("conformance")}},
		}.Marshal())

		x = newXID()
		b = clientMessage(dhcp.Discover, x, guestMAC).Marshal()[:dhcp.MinLen-1]
		send("a DISCOVER of 239 bytes", x, b)

		x = newXID()
		b = clientMessage(dhcp.Discover, x, guestMAC).Marshal()[:dhcp.MinLen]
		// Option 53, then option 12 whose length runs past the end.
		b = append(b, dhcp.OptMessageType, 1, dhcp.Discover, 12, 200, 'b', 'w')
		send("a DISCOVER whose options are truncated", x, b)

		s.ask("a DISCOVER after them", clientMessage(dhcp.Discover, newXID(), guestMAC))
		time.Sleep(quiet)
		for _, rep := range s.all() {
			if x, ok := rep.xid(); ok {
				if what, bad := ignored[x]; bad {
					t.Errorf("%s was answered with %d bytes from %s", what, len(rep.Raw), rep.Src)
				}
			}
		}
	},
}
