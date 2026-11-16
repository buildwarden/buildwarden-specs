// Package memnet is the harness's in-memory network: one segment, held in
// the memory of the process, on which the harness's roles and the harness's
// own relay meet when no launcher stands behind a case. It has named IPv4
// addresses, stream listeners and connections that behave as TCP's do,
// datagram endpoints that behave as UDP's do with the broadcast an address
// lease needs, and, apart from the segment, a frame pipe that carries one
// Ethernet frame per datagram, as the socket of a relay's frame link does.
//
// An address on the segment is a name and nothing more: any party may bind
// any IPv4 address, and a view of the segment (Host) is only the address a
// party dials from and the one an empty host in Listen stands for. There is
// no routing, no loss but a full datagram queue, and no reordering.
//
// What the segment does where a kernel would answer:
//
//   - A stream dial to an address and port nobody listens on is refused, as
//     a TCP reset would refuse it (ECONNREFUSED).
//   - A datagram to an address and port nobody has bound is dropped, and a
//     connected datagram endpoint that sent it gets ECONNREFUSED from its
//     next Read or Write, as a kernel's does on an ICMP port unreachable.
//   - A datagram to 255.255.255.255 reaches every endpoint bound to its
//     port, whatever address it is bound to.
//   - A bind of an address and port that is taken, or of a port that is
//     taken on the unspecified address 0.0.0.0, is refused (EADDRINUSE).
package memnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// Limits of the segment. They are constants of a harness release.
const (
	// Backlog is how many connections a listener holds before it accepts
	// them; a dial beyond it is refused.
	Backlog = 128
	// StreamBuffer is how many bytes one direction of a stream connection
	// holds before a write waits for the reader, as a TCP window does.
	StreamBuffer = 256 << 10
	// DatagramQueue is how many datagrams an endpoint holds before the
	// segment drops what arrives, as a full socket buffer does.
	DatagramQueue = 256
	// FrameQueue is how many frames one direction of a frame pipe holds
	// before a write waits for the reader, as a datagram socket pair does.
	FrameQueue = 512
)

// The ephemeral port range, the one RFC 6335 gives.
const (
	firstEphemeral = 49152
	lastEphemeral  = 65535
)

// Broadcast is the IPv4 limited broadcast address.
var Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Net is one in-memory segment. Its zero value is not usable; use New.
type Net struct {
	mu        sync.Mutex
	listeners map[netip.AddrPort]*listener
	endpoints map[netip.AddrPort]*packetConn
	next      uint16
}

// New returns an empty segment.
func New() *Net {
	return &Net{
		listeners: map[netip.AddrPort]*listener{},
		endpoints: map[netip.AddrPort]*packetConn{},
		next:      firstEphemeral,
	}
}

// Host is a view of the segment as a party at addr sees it: its Dial sends
// from addr, and its Listen and ListenPacket take an empty host for addr.
// Every view of one segment reaches every other.
func (n *Net) Host(addr netip.Addr) attach.Network {
	return &view{n: n, addr: addr}
}

type view struct {
	n    *Net
	addr netip.Addr
}

func (v *view) Address() netip.Addr { return v.addr }

func (v *view) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := streamNetwork(network); err != nil {
		return nil, err
	}
	ap, err := v.parse(network, address)
	if err != nil {
		return nil, err
	}
	return v.n.listen(network, ap)
}

func (v *view) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if err := packetNetwork(network); err != nil {
		return nil, err
	}
	ap, err := v.parse(network, address)
	if err != nil {
		return nil, err
	}
	return v.n.bind(network, ap, v.addr, netip.AddrPort{})
}

func (v *view) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	dst, err := parseAddrPort(network, address, netip.Addr{})
	if err != nil {
		return nil, err
	}
	if dst.Port() == 0 {
		return nil, opError("dial", network, nil, udpOrTCP(network, dst), errors.New("no port"))
	}
	switch {
	case streamNetwork(network) == nil:
		return v.n.dial(ctx, network, v.addr, dst)
	case packetNetwork(network) == nil:
		return v.n.bind(network, netip.AddrPortFrom(v.addr, 0), v.addr, dst)
	}
	return nil, opError("dial", network, nil, nil, net.UnknownNetworkError(network))
}

// parse reads a listen address, in which an empty host is the view's own
// address and a port of 0 asks for an ephemeral one.
func (v *view) parse(network, address string) (netip.AddrPort, error) {
	return parseAddrPort(network, address, v.addr)
}

func streamNetwork(network string) error {
	switch network {
	case "tcp", "tcp4":
		return nil
	}
	return opError("listen", network, nil, nil, net.UnknownNetworkError(network))
}

func packetNetwork(network string) error {
	switch network {
	case "udp", "udp4":
		return nil
	}
	return opError("listen", network, nil, nil, net.UnknownNetworkError(network))
}

// parseAddrPort reads "host:port", where the host is an IPv4 literal: the
// segment has no names. An empty host is empty.
func parseAddrPort(network, address string, empty netip.Addr) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, opError("parse", network, nil, nil, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, opError("parse", network, nil, nil, fmt.Errorf("port %q: %w", port, err))
	}
	addr := empty
	if host != "" {
		addr, err = netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, opError("parse", network, nil, nil, fmt.Errorf("host %q is not an IP address: the in-memory network has no names", host))
		}
	}
	if !addr.Is4() {
		return netip.AddrPort{}, opError("parse", network, nil, nil, fmt.Errorf("address %q is not IPv4: the in-memory network carries IPv4 only", address))
	}
	return netip.AddrPortFrom(addr, uint16(p)), nil
}

// taken reports whether ap conflicts with a bound key in m: the same
// address and port, or the same port where either is the unspecified
// address. The caller holds n.mu.
func taken[T any](m map[netip.AddrPort]T, ap netip.AddrPort) bool {
	if _, ok := m[ap]; ok {
		return true
	}
	wild := netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port())
	if _, ok := m[wild]; ok {
		return true
	}
	if ap.Addr().IsUnspecified() {
		for k := range m {
			if k.Port() == ap.Port() {
				return true
			}
		}
	}
	return false
}

// ephemeral picks a port for addr that is free in m. The caller holds n.mu.
func ephemeral[T any](n *Net, m map[netip.AddrPort]T, addr netip.Addr) (uint16, error) {
	for range lastEphemeral - firstEphemeral + 1 {
		p := n.next
		if n.next == lastEphemeral {
			n.next = firstEphemeral
		} else {
			n.next++
		}
		if !taken(m, netip.AddrPortFrom(addr, p)) {
			return p, nil
		}
	}
	return 0, syscall.EADDRNOTAVAIL
}

// lookup finds what is bound at dst in m: the exact address, or else the
// unspecified address on dst's port. The caller holds n.mu.
func lookup[T any](m map[netip.AddrPort]T, dst netip.AddrPort) (T, bool) {
	if v, ok := m[dst]; ok {
		return v, true
	}
	v, ok := m[netip.AddrPortFrom(netip.IPv4Unspecified(), dst.Port())]
	return v, ok
}

func tcpAddr(ap netip.AddrPort) *net.TCPAddr { return net.TCPAddrFromAddrPort(ap) }
func udpAddr(ap netip.AddrPort) *net.UDPAddr { return net.UDPAddrFromAddrPort(ap) }

func udpOrTCP(network string, ap netip.AddrPort) net.Addr {
	if packetNetwork(network) == nil {
		return udpAddr(ap)
	}
	return tcpAddr(ap)
}
