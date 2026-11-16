package dhcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
)

// Retransmit is how long the client waits for a reply before it sends the
// same message again. It is a constant of a harness release.
const Retransmit = time.Second

// Lease is what an ACK gave.
type Lease struct {
	// Address is the client's address, yiaddr, with the prefix of option 1.
	Address netip.Prefix
	// Server is option 54, the server identifier.
	Server netip.Addr
	// Router and DNS are options 3 and 6; each is empty when the ACK has
	// none.
	Router []netip.Addr
	DNS    []netip.Addr
	// Seconds is option 51; 0xffffffff is an infinite lease.
	Seconds uint32
	// Offer and Ack are the replies as they came.
	Offer, Ack Message
}

// transport is how the client's messages reach the server: broadcast, from
// port 68 to port 67, and the replies back.
type transport interface {
	send(msg []byte) error
	// recv returns the payload of the next datagram to port 68, waiting no
	// later than deadline.
	recv(deadline time.Time) ([]byte, error)
}

// LeaseFrames takes a lease on a frame link, as a party with the Ethernet
// address mac and no IPv4 address yet: each message goes in a frame to the
// Ethernet broadcast address, from 0.0.0.0:68 to 255.255.255.255:67. It reads
// every frame on link until the lease is taken, and drops each that is not a
// reply to it, so nothing else may read link meanwhile.
func LeaseFrames(ctx context.Context, link net.Conn, mac net.HardwareAddr) (Lease, error) {
	return lease(ctx, frames{link: link, mac: mac}, mac)
}

// LeasePacket takes a lease over pc, a datagram endpoint bound to port 68:
// each message is sent to 255.255.255.255:67.
func LeasePacket(ctx context.Context, pc net.PacketConn, mac net.HardwareAddr) (Lease, error) {
	return lease(ctx, packet{pc: pc}, mac)
}

func lease(ctx context.Context, t transport, mac net.HardwareAddr) (Lease, error) {
	if len(mac) != 6 {
		return Lease{}, fmt.Errorf("dhcp: %q is not an Ethernet address", mac)
	}
	xid := rand.Uint32()
	offer, err := exchange(ctx, t, request(xid, mac, Discover, nil), xid, Offer)
	if err != nil {
		return Lease{}, err
	}
	server, ok := Addrs(must(offer.Option(OptServerID)))
	if !ok || len(server) != 1 {
		return Lease{}, errors.New("dhcp: the DHCPOFFER has no server identifier (option 54)")
	}
	ack, err := exchange(ctx, t, request(xid, mac, Request, []Option{
		{Code: OptRequestedIP, Data: offer.Yiaddr.AsSlice()},
		{Code: OptServerID, Data: server[0].AsSlice()},
	}), xid, Ack)
	if err != nil {
		return Lease{}, err
	}
	l, err := leaseOf(ack)
	if err != nil {
		return Lease{}, err
	}
	l.Offer, l.Ack = offer, ack
	return l, nil
}

func must(b []byte, _ bool) []byte { return b }

// request is a client message of type typ.
func request(xid uint32, mac net.HardwareAddr, typ byte, opts []Option) Message {
	return Message{
		Op: BootRequest, HType: 1, HLen: 6, Xid: xid,
		Flags:  0x8000, // broadcast: the client has no address to be answered at
		Chaddr: mac,
		Options: append([]Option{{Code: OptMessageType, Data: []byte{typ}}}, append(opts,
			Option{Code: OptParams, Data: []byte{OptSubnetMask, OptRouter, OptDNS}})...),
	}
}

// exchange sends m until a reply to it of type want comes, and returns it.
// A NAK is an error at once.
func exchange(ctx context.Context, t transport, m Message, xid uint32, want byte) (Message, error) {
	msg := m.Marshal()
	for attempt := 1; ; attempt++ {
		if err := t.send(msg); err != nil {
			return Message{}, fmt.Errorf("dhcp: send %s: %w", typeName(m.Type()), err)
		}
		next := time.Now().Add(Retransmit)
		// When the context ends before the next retransmission, this wait
		// is the last: the read's deadline can pass a moment before the
		// context's timer fires.
		last := false
		if dl, ok := ctx.Deadline(); ok && !dl.After(next) {
			next, last = dl, true
		}
		for {
			b, err := t.recv(next)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return Message{}, fmt.Errorf("dhcp: wait for a %s: %w", typeName(want), err)
			}
			r, err := Parse(b)
			if err != nil || r.Op != BootReply || r.Xid != xid || !bytes.Equal(r.Chaddr, m.Chaddr) {
				continue
			}
			switch r.Type() {
			case want:
				return r, nil
			case Nak:
				return Message{}, fmt.Errorf("dhcp: the server answered the %s with a DHCPNAK", typeName(m.Type()))
			}
		}
		if last {
			<-ctx.Done()
		}
		if err := ctx.Err(); err != nil {
			return Message{}, fmt.Errorf("dhcp: no %s after %d %s: %w", typeName(want), attempt, typeName(m.Type()), err)
		}
	}
}

// leaseOf reads the lease an ACK gives.
func leaseOf(ack Message) (Lease, error) {
	if !ack.Yiaddr.Is4() || ack.Yiaddr.IsUnspecified() {
		return Lease{}, errors.New("dhcp: the DHCPACK gives no address (yiaddr)")
	}
	mask, ok := Addrs(must(ack.Option(OptSubnetMask)))
	if !ok || len(mask) != 1 {
		return Lease{}, errors.New("dhcp: the DHCPACK has no subnet mask (option 1)")
	}
	ones, bits := net.IPMask(mask[0].AsSlice()).Size()
	if bits != 32 {
		return Lease{}, fmt.Errorf("dhcp: the DHCPACK's subnet mask %s is not a prefix", mask[0])
	}
	server, ok := Addrs(must(ack.Option(OptServerID)))
	if !ok || len(server) != 1 {
		return Lease{}, errors.New("dhcp: the DHCPACK has no server identifier (option 54)")
	}
	l := Lease{Address: netip.PrefixFrom(ack.Yiaddr, ones), Server: server[0]}
	if d, ok := ack.Option(OptRouter); ok {
		if l.Router, ok = Addrs(d); !ok {
			return Lease{}, errors.New("dhcp: the DHCPACK's router option (3) is not a list of addresses")
		}
	}
	if d, ok := ack.Option(OptDNS); ok {
		if l.DNS, ok = Addrs(d); !ok {
			return Lease{}, errors.New("dhcp: the DHCPACK's domain name server option (6) is not a list of addresses")
		}
	}
	if d, ok := ack.Option(OptLeaseTime); ok && len(d) == 4 {
		l.Seconds = binary.BigEndian.Uint32(d)
	}
	return l, nil
}

func typeName(t byte) string {
	switch t {
	case Discover:
		return "DHCPDISCOVER"
	case Offer:
		return "DHCPOFFER"
	case Request:
		return "DHCPREQUEST"
	case Ack:
		return "DHCPACK"
	case Nak:
		return "DHCPNAK"
	}
	return fmt.Sprintf("DHCP message of type %d", t)
}

var (
	broadcast  = netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), ServerPort)
	unassigned = netip.AddrPortFrom(netip.IPv4Unspecified(), ClientPort)
)

type frames struct {
	link net.Conn
	mac  net.HardwareAddr
}

func (f frames) send(msg []byte) error {
	_, err := f.link.Write(netstack.UDPFrame{
		SrcMAC: f.mac, DstMAC: netstack.BroadcastMAC,
		Src: unassigned, Dst: broadcast, Payload: msg,
	}.Marshal())
	return err
}

func (f frames) recv(deadline time.Time) ([]byte, error) {
	if err := f.link.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer f.link.SetReadDeadline(time.Time{})
	buf := make([]byte, 1<<16)
	for {
		n, err := f.link.Read(buf)
		if err != nil {
			return nil, err
		}
		u, ok := netstack.ParseUDPFrame(buf[:n])
		if !ok || u.Dst.Port() != ClientPort {
			continue
		}
		if !bytes.Equal(u.DstMAC, f.mac) && !bytes.Equal(u.DstMAC, netstack.BroadcastMAC) {
			continue
		}
		return u.Payload, nil
	}
}

type packet struct{ pc net.PacketConn }

func (p packet) send(msg []byte) error {
	_, err := p.pc.WriteTo(msg, net.UDPAddrFromAddrPort(broadcast))
	return err
}

func (p packet) recv(deadline time.Time) ([]byte, error) {
	if err := p.pc.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer p.pc.SetReadDeadline(time.Time{})
	buf := make([]byte, 1<<16)
	n, _, err := p.pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
