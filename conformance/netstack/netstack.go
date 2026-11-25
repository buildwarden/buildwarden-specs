// Package netstack is the harness's own network stack, which a party on a
// frame link brings: the build environment on a relay's frame link, and on
// the other end of an in-memory frame pipe whatever the harness puts there.
// It is gVisor's TCP/IP stack with IPv4, ARP, ICMP, TCP and UDP, on one
// Ethernet interface whose frames are read from and written to a net.Conn
// that carries one frame per datagram (memnet.Frames, or the socket of a
// relay's frame link). Its sockets are an attach.Network, so the harness's
// roles use it as they use any other network.
//
// A stack has a fixed address, given when it is made, and may take every
// other address as its own as well (Config.AnyAddress). The build
// environment takes its address from the relay's DHCP before it makes its
// stack, with the frames UDPFrame reads and writes (package dhcp).
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// MTU is the interface's IP MTU, Ethernet's.
const MTU = 1500

// queueLen is how many frames the stack holds to send before it drops one,
// as an interface's transmit queue does.
const queueLen = 1024

const nic tcpip.NICID = 1

// Config is what a stack is made with.
type Config struct {
	// MAC is the interface's Ethernet address.
	MAC net.HardwareAddr
	// Address is the stack's IPv4 address, and its prefix the link's.
	Address netip.Prefix
	// Gateway, when it is valid, is the router for every address off the
	// link. Without it the stack reaches only its link.
	Gateway netip.Addr
	// AnyAddress has the stack take a packet to any IPv4 address as one to
	// itself, and answer from that address, so that a listener on an
	// address the stack was not given accepts the connections to it: the
	// capture of a relay on a frame link (relay-guest-api, GUEST-6), or a
	// party that stands for the whole world past the link.
	AnyAddress bool
}

func (c Config) check() error {
	switch {
	case len(c.MAC) != 6:
		return fmt.Errorf("netstack: MAC %q is not an Ethernet address", c.MAC)
	case !c.Address.IsValid() || !c.Address.Addr().Is4():
		return fmt.Errorf("netstack: address %v is not an IPv4 address with a prefix", c.Address)
	case c.Gateway.IsValid() && !c.Gateway.Is4():
		return fmt.Errorf("netstack: gateway %v is not an IPv4 address", c.Gateway)
	case c.Gateway.IsValid() && !c.Address.Masked().Contains(c.Gateway):
		return fmt.Errorf("netstack: gateway %v is not on the link %v", c.Gateway, c.Address.Masked())
	}
	return nil
}

// Stack is one network stack on one frame link.
type Stack struct {
	cfg  Config
	link net.Conn
	ep   *channel.Endpoint
	s    *stack.Stack

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// New makes a stack on link, which it owns from then on: Close closes it.
// The stack reads every frame link carries and sends its own on it.
func New(link net.Conn, cfg Config) (*Stack, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	ep := channel.New(queueLen, MTU+ethernetHeader, tcpip.LinkAddress(cfg.MAC))
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	fail := func(what string, e tcpip.Error) (*Stack, error) {
		s.Close()
		return nil, fmt.Errorf("netstack: %s: %s", what, e)
	}
	if e := s.CreateNIC(nic, ethernet.New(ep)); e != nil {
		return fail("create the interface", e)
	}
	addr := cfg.Address.Addr().As4()
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(addr),
			PrefixLen: cfg.Address.Bits(),
		},
	}
	if e := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); e != nil {
		return fail("add the address", e)
	}
	routes := []tcpip.Route{{Destination: pa.AddressWithPrefix.Subnet(), NIC: nic}}
	if cfg.Gateway.IsValid() {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4(cfg.Gateway.As4()), NIC: nic})
	}
	s.SetRouteTable(routes)
	if cfg.AnyAddress {
		if e := s.SetPromiscuousMode(nic, true); e != nil {
			return fail("take packets to any address", e)
		}
		if e := s.SetSpoofing(nic, true); e != nil {
			return fail("send from any address", e)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{cfg: cfg, link: link, ep: ep, s: s, ctx: ctx, cancel: cancel}
	st.wg.Add(2)
	go st.receive()
	go st.transmit()
	return st, nil
}

// receive hands each frame the link carries to the stack, until the link
// fails or is closed.
func (st *Stack) receive() {
	defer st.wg.Done()
	buf := make([]byte, 1<<16)
	for {
		n, err := st.link.Read(buf)
		if err != nil {
			return
		}
		if n < ethernetHeader {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...))})
		st.ep.InjectInbound(0, pkt)
		pkt.DecRef()
	}
}

// transmit writes each frame the stack sends to the link, one per write.
func (st *Stack) transmit() {
	defer st.wg.Done()
	for {
		pkt := st.ep.ReadContext(st.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		frame := append([]byte(nil), v.AsSlice()...)
		v.Release()
		pkt.DecRef()
		if _, err := st.link.Write(frame); err != nil {
			return
		}
	}
}

// Config is what the stack was made with.
func (st *Stack) Config() Config { return st.cfg }

// captureQueue is how many captured connections the stack completes the
// handshake of before handle has taken them; a connection beyond it is
// reset.
const captureQueue = 64

// Capture has the stack accept every TCP connection that no listener of its
// own takes, to any address it takes as its own and any port, and hand each
// to handle on a goroutine of its own. The connection's LocalAddr is the
// address and port the peer connected to, so that handle can select the
// service by them: the capture of a relay on a frame link, which accepts
// connections to any address and port (relay-guest-api, GUEST-6).
func (st *Stack) Capture(handle func(net.Conn)) {
	// No TIME-WAIT. A SYN that reuses the 4-tuple of a connection in
	// TIME-WAIT is handed by gVisor only to a listening endpoint, never to
	// a forwarder, so with its default of 60 s a peer that picks a source
	// port again would be ignored for a minute, though GUEST-6 has the
	// connection accepted. TIME-WAIT guards against a delayed segment of the
	// old connection on a path that reorders; a frame link delivers in
	// order, so it buys nothing here.
	tw := tcpip.TCPTimeWaitTimeoutOption(0)
	if e := st.s.SetTransportProtocolOption(tcp.ProtocolNumber, &tw); e != nil {
		// New registers TCP, whose protocol takes the option.
		panic(fmt.Sprintf("netstack: set TCP's TIME-WAIT timeout: %s", e))
	}
	fwd := tcp.NewForwarder(st.s, 0, captureQueue, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		go handle(gonet.NewTCPConn(&wq, ep))
	})
	st.s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// Close stops the stack and closes its link. Every socket of the stack
// fails from then on.
func (st *Stack) Close() error {
	var err error
	st.once.Do(func() {
		st.cancel()
		err = st.link.Close()
		st.wg.Wait()
		st.s.Close()
		st.ep.Close()
	})
	return err
}

// Network returns the stack's sockets as the harness's roles take them. An
// empty host in Listen or ListenPacket is the stack's address, and
// 0.0.0.0 any address of the stack.
func (st *Stack) Network() attach.Network { return network{st} }

type network struct{ st *Stack }

func (n network) Address() netip.Addr { return n.st.cfg.Address.Addr() }

func (n network) Listen(ctx context.Context, nw, address string) (net.Listener, error) {
	if nw != "tcp" && nw != "tcp4" {
		return nil, &net.OpError{Op: "listen", Net: nw, Err: net.UnknownNetworkError(nw)}
	}
	fa, err := n.full(address, true)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: nw, Err: err}
	}
	return gonet.ListenTCP(n.st.s, fa, ipv4.ProtocolNumber)
}

func (n network) ListenPacket(ctx context.Context, nw, address string) (net.PacketConn, error) {
	if nw != "udp" && nw != "udp4" {
		return nil, &net.OpError{Op: "listen", Net: nw, Err: net.UnknownNetworkError(nw)}
	}
	fa, err := n.full(address, true)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: nw, Err: err}
	}
	return gonet.DialUDP(n.st.s, &fa, nil, ipv4.ProtocolNumber)
}

func (n network) Dial(ctx context.Context, nw, address string) (net.Conn, error) {
	fa, err := n.full(address, false)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: nw, Err: err}
	}
	switch nw {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, n.st.s, fa, ipv4.ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(n.st.s, nil, &fa, ipv4.ProtocolNumber)
	}
	return nil, &net.OpError{Op: "dial", Net: nw, Err: net.UnknownNetworkError(nw)}
}

// full reads "host:port" as the stack's address of it. For a local address
// an empty host is the stack's own and 0.0.0.0 any of its addresses; a
// remote address must name its host.
func (n network) full(address string, local bool) (tcpip.FullAddress, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return tcpip.FullAddress{}, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return tcpip.FullAddress{}, fmt.Errorf("port %q: %w", port, err)
	}
	fa := tcpip.FullAddress{NIC: nic, Port: uint16(p)}
	var addr netip.Addr
	switch {
	case host == "" && local:
		addr = n.st.cfg.Address.Addr()
	case host == "":
		return tcpip.FullAddress{}, errors.New("no host")
	default:
		addr, err = netip.ParseAddr(host)
		if err != nil {
			return tcpip.FullAddress{}, fmt.Errorf("host %q is not an IP address: the stack resolves no names", host)
		}
	}
	if !addr.Is4() {
		return tcpip.FullAddress{}, fmt.Errorf("address %q is not IPv4: the stack carries IPv4 only", address)
	}
	if !addr.IsUnspecified() {
		fa.Addr = tcpip.AddrFrom4(addr.As4())
	}
	return fa, nil
}
