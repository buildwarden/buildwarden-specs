package relay

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
)

// The gratuitous ARP of a frame link (GUEST-5): the Go relay's timing.
const (
	AnnounceEvery = 500 * time.Millisecond
	AnnounceFor   = 60 * time.Second
)

const (
	ethHeader = 14
	arpLen    = 28
)

// frameLink is the relay's end of a frame link as its network stack sees
// it. Before a frame reaches the stack it serves the address lease itself
// (GUEST-8 to GUEST-11), drops an ARP request for any address but the
// relay's, which the stack would answer since it takes every address as its
// own (GUEST-3), and drops a frame that is neither ARP nor IPv4 (GUEST-7).
// It also sends the gratuitous ARP of GUEST-5.
type frameLink struct {
	net.Conn
	ctx   context.Context
	g     *Guest
	relay netip.Addr

	wmu sync.Mutex
	buf []byte
}

func newFrameLink(ctx context.Context, c net.Conn, g *Guest) *frameLink {
	return &frameLink{Conn: c, ctx: ctx, g: g, relay: g.link.Addr(), buf: make([]byte, 1<<16)}
}

// Read returns the next frame the stack is to see.
func (f *frameLink) Read(p []byte) (int, error) {
	for {
		n, err := f.Conn.Read(f.buf)
		if err != nil {
			return 0, err
		}
		fr := f.buf[:n]
		if n < ethHeader {
			continue
		}
		switch binary.BigEndian.Uint16(fr[12:14]) {
		case netstack.EtherTypeARP:
			if n < ethHeader+arpLen {
				continue
			}
			arp := fr[ethHeader:]
			if binary.BigEndian.Uint16(arp[6:8]) == 1 {
				target, _ := netip.AddrFromSlice(arp[24:28])
				if target != f.relay {
					continue
				}
			}
		case netstack.EtherTypeIPv4:
			if u, ok := netstack.ParseUDPFrame(fr); ok && u.Dst.Port() == portLease {
				if u.Dst.Addr() == f.relay || u.Dst.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
					f.lease(u)
				}
				continue
			}
		default:
			continue
		}
		return copy(p, fr), nil
	}
}

// Write sends one frame; the stack, the lease and the announcement share
// the link.
func (f *frameLink) Write(p []byte) (int, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return f.Conn.Write(p)
}

// lease answers a DHCP message in a frame, to the request's chaddr
// (GUEST-9, the Go relay's addressing).
func (f *frameLink) lease(u netstack.UDPFrame) {
	m, ok := f.g.leaseReply(u.Payload)
	if !ok {
		return
	}
	dst := net.HardwareAddr(m.Chaddr)
	if len(dst) != 6 {
		dst = netstack.BroadcastMAC
	}
	out := netstack.UDPFrame{
		SrcMAC: RelayMAC, DstMAC: dst,
		Src:     netip.AddrPortFrom(f.relay, portLease),
		Dst:     netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), portClient),
		Payload: m.Marshal(),
	}
	_, _ = f.Write(out.Marshal())
}

// announce broadcasts a gratuitous ARP reply for the relay's address every
// AnnounceEvery for AnnounceFor, from the start of the link (GUEST-5).
func (f *frameLink) announce() {
	fr := make([]byte, ethHeader+arpLen)
	copy(fr[0:6], netstack.BroadcastMAC)
	copy(fr[6:12], RelayMAC)
	binary.BigEndian.PutUint16(fr[12:14], netstack.EtherTypeARP)
	arp := fr[ethHeader:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], netstack.EtherTypeIPv4)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	a := f.relay.As4()
	copy(arp[8:14], RelayMAC)
	copy(arp[14:18], a[:])
	copy(arp[18:24], netstack.BroadcastMAC)
	copy(arp[24:28], a[:])
	go func() {
		t := time.NewTicker(AnnounceEvery)
		defer t.Stop()
		end := time.After(AnnounceFor)
		for {
			if _, err := f.Write(fr); err != nil {
				return
			}
			select {
			case <-f.ctx.Done():
				return
			case <-end:
				return
			case <-t.C:
			}
		}
	}()
}

// serveLeasePacket serves the lease on a kernel interface: each reply goes
// from the relay's address to 255.255.255.255:68 (GUEST-8).
func (g *Guest) serveLeasePacket(pc net.PacketConn) {
	buf := make([]byte, 1<<16)
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), portClient))
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if m, ok := g.leaseReply(buf[:n]); ok {
			_, _ = pc.WriteTo(m.Marshal(), to)
		}
	}
}

// leaseReply is the relay's answer to a DHCP message, and false for one it
// does not answer: an OFFER to a DISCOVER and an ACK to a REQUEST, the same
// whatever either asks for or names (GUEST-9, GUEST-10), and nothing to any
// other message (GUEST-11).
func (g *Guest) leaseReply(b []byte) (dhcp.Message, bool) {
	m, err := dhcp.Parse(b)
	if err != nil || m.Op != dhcp.BootRequest {
		return dhcp.Message{}, false
	}
	var typ byte
	switch m.Type() {
	case dhcp.Discover:
		typ = dhcp.Offer
	case dhcp.Request:
		typ = dhcp.Ack
	default:
		return dhcp.Message{}, false
	}
	g.mu.Lock()
	link, guest := g.link, g.guest
	g.mu.Unlock()
	if !guest.IsValid() {
		return dhcp.Message{}, false
	}
	relay := link.Addr().As4()
	mask := net.CIDRMask(link.Bits(), 32)
	chaddr := make(net.HardwareAddr, 6)
	copy(chaddr, m.Chaddr)
	return dhcp.Message{
		Op: dhcp.BootReply, HType: 1, HLen: 6, Xid: m.Xid, Flags: m.Flags,
		Yiaddr: guest, Siaddr: link.Addr(), Chaddr: chaddr,
		Options: []dhcp.Option{
			{Code: dhcp.OptMessageType, Data: []byte{typ}},
			{Code: dhcp.OptServerID, Data: relay[:]},
			{Code: dhcp.OptLeaseTime, Data: []byte{0xff, 0xff, 0xff, 0xff}},
			{Code: dhcp.OptSubnetMask, Data: mask},
			{Code: dhcp.OptRouter, Data: relay[:]},
			{Code: dhcp.OptDNS, Data: relay[:]},
		},
	}, true
}
