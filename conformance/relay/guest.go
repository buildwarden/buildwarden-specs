package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
)

// The relay's modes (RELAY-04 in buildwarden/buildwarden), which the model
// takes as a start parameter: host serves the build on a frame link, vm and
// container on a kernel interface, here the in-memory network.
const (
	ModeHost      = "host"
	ModeVM        = "vm"
	ModeContainer = "container"
)

// The ports of the build link (relay-guest-api, Transport).
const (
	PortDNS     = 53
	PortHTTP    = 80
	PortTLS     = 443
	PortControl = 8300
	portLease   = 67
	portClient  = 68
)

// The relay's limits on the build side. ArtifactLimit, OutputLimit and
// NameLimit are relay-guest-api's (Limits); the others are this model's own
// and constants of a harness release.
const (
	ArtifactLimit = 2 << 30
	OutputLimit   = 256 << 20
	NameLimit     = 255
	// RequestBodyLimit is the largest body of a proxied request the relay
	// holds; a larger one is answered 413.
	RequestBodyLimit = 64 << 20
	// ResponseBodyLimit is the largest body of an upstream's response the
	// relay holds; a larger one is answered 502.
	ResponseBodyLimit = 1 << 30
	// HandshakeTimeout bounds a TLS handshake with the build environment.
	HandshakeTimeout = 10 * time.Second
	// UpstreamTimeout bounds one exchange with an upstream.
	UpstreamTimeout = 60 * time.Second
)

// DefaultSegment is a host-mode relay's segment for a claim that carries no
// build_link (CLAIM-39): the Go relay's default -subnet.
var DefaultSegment = BuildLink{
	Prefix: netip.MustParsePrefix("10.100.0.0/30"),
	Relay:  netip.MustParseAddr("10.100.0.1"),
	Guest:  netip.MustParseAddr("10.100.0.2"),
}

// RelayMAC is the relay's Ethernet address on a frame link.
var RelayMAC = net.HardwareAddr{0x02, 0x42, 0x57, 0x52, 0x00, 0x01}

// GuestConfig is what the build side is started with: what a launcher
// gives a relay from the kernel, and the harness's in-process attachment
// from memory.
type GuestConfig struct {
	// Mode is ModeHost, ModeVM or ModeContainer.
	Mode string
	// Frames is a host-mode relay's end of its frame link. The relay reads
	// it once it has been claimed and closes it when it ends; until then
	// its owner closes it.
	Frames net.Conn
	// Segment is a host-mode relay's segment for a claim without a
	// build_link; nil is DefaultSegment.
	Segment *BuildLink
	// Net is the build link of a vm-mode or container-mode relay: where it
	// binds its ports, at its own address.
	Net attach.Network
	// Interface are the IPv4 addresses, with their prefixes, already on a
	// vm-mode or container-mode relay's build interface: the address a
	// vm-mode claim without a build_link keeps (CLAIM-38), and a
	// container-mode relay's own (GUEST-1).
	Interface []netip.Prefix
	// OtherAddresses and OtherRoutes are the addresses and the route
	// destinations of a vm-mode relay's other interfaces, which a claim's
	// build_link may not use (CLAIM-36).
	OtherAddresses []netip.Prefix
	OtherRoutes    []netip.Prefix
}

// Guest is the relay's build side: relay-guest-api as it states it for a
// relay, and the relay's half of bootstrap-config. It implements Build.
type Guest struct {
	cfg GuestConfig

	mu        sync.Mutex
	link      netip.Prefix // the relay's address and the build link's length
	guest     netip.Addr   // the lease's address; invalid where none is served
	session   *Session
	ctx       context.Context
	upstream  *http.Transport
	stack     *netstack.Stack
	closers   []io.Closer
	conns     map[net.Conn]bool
	output    int64
	control   *http.Server
	controlLn *connListener
}

// NewGuest checks cfg and returns the build side it describes.
func NewGuest(cfg GuestConfig) (*Guest, error) {
	switch cfg.Mode {
	case ModeHost:
		if cfg.Frames == nil {
			return nil, errors.New("relay: a host-mode relay needs its frame link")
		}
	case ModeVM, ModeContainer:
		if cfg.Net == nil {
			return nil, fmt.Errorf("relay: a %s-mode relay needs its build link's network", cfg.Mode)
		}
		if cfg.Mode == ModeContainer && firstIPv4(cfg.Interface) == nil {
			return nil, errors.New("relay: a container-mode relay needs the address its launcher gave it")
		}
	default:
		return nil, fmt.Errorf("relay: mode %q is none of %s, %s and %s", cfg.Mode, ModeHost, ModeVM, ModeContainer)
	}
	if cfg.Segment == nil {
		seg := DefaultSegment
		cfg.Segment = &seg
	}
	return &Guest{cfg: cfg, conns: map[net.Conn]bool{}}, nil
}

func firstIPv4(ps []netip.Prefix) *netip.Prefix {
	for i := range ps {
		if ps[i].Addr().Is4() {
			return &ps[i]
		}
	}
	return nil
}

// Address is the relay's address on the build link, once a claim has
// configured it.
func (g *Guest) Address() netip.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.link.Addr()
}

// Configure applies the claim's build_link by the relay's mode (CLAIM-36 to
// CLAIM-40).
func (g *Guest) Configure(_ context.Context, c *Claim) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.cfg.Mode {
	case ModeHost:
		link := c.BuildLink
		if link == nil {
			link = g.cfg.Segment
		}
		g.link, g.guest = netip.PrefixFrom(link.Relay, link.Prefix.Bits()), link.Guest
	case ModeVM:
		if link := c.BuildLink; link != nil {
			for _, a := range g.cfg.OtherAddresses {
				if link.Prefix.Contains(a.Addr()) {
					return Refused("build_link: %s is an address of another interface, inside %s", a, link.Prefix)
				}
			}
			for _, r := range g.cfg.OtherRoutes {
				if r.Bits() >= link.Prefix.Bits() && link.Prefix.Contains(r.Addr()) {
					return Refused("build_link: another interface has a route to %s, inside %s", r, link.Prefix)
				}
			}
			own := netip.PrefixFrom(link.Relay, link.Prefix.Bits())
			g.cfg.Interface = []netip.Prefix{own}
			g.link, g.guest = own, link.Guest
			return nil
		}
		p := firstIPv4(g.cfg.Interface)
		if p == nil {
			return Refused("build_link: the claim has none and the build interface has no IPv4 address")
		}
		g.link, g.guest = *p, netip.Addr{}
	case ModeContainer:
		if c.BuildLink != nil {
			return Refused("build_link: a container-mode relay's address is the one its container was given")
		}
		g.link, g.guest = *firstIPv4(g.cfg.Interface), netip.Addr{}
	}
	return nil
}

// Start starts the build side for s: on a frame link the network stack,
// the lease and the capture of every connection; on a kernel interface the
// lease where the claim carried a build_link, and the ports of GUEST-2. All
// of it is serving when Start returns, in every mode (GUEST-51).
func (g *Guest) Start(ctx context.Context, s *Session) error {
	g.mu.Lock()
	g.session, g.ctx = s, ctx
	g.mu.Unlock()
	roots := x509.NewCertPool()
	if s.claim.SystemRoots {
		if sys, err := x509.SystemCertPool(); err == nil && sys != nil {
			roots = sys
		}
	}
	for _, r := range s.claim.Roots {
		roots.AddCert(r)
	}
	g.upstream = &http.Transport{
		DialContext:        g.dialUpstream,
		TLSClientConfig:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableCompression: true,
		DisableKeepAlives:  true,
		// HTTP/1.1 only: an empty map turns HTTP/2 off.
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		ResponseHeaderTimeout: UpstreamTimeout,
	}
	g.control = &http.Server{Handler: http.HandlerFunc(g.serveControl), ReadHeaderTimeout: HeaderTimeout}
	var err error
	if g.cfg.Mode == ModeHost {
		err = g.startFrames(ctx)
	} else {
		err = g.startIP(ctx)
	}
	if err != nil {
		g.stop()
		return err
	}
	go func() {
		<-ctx.Done()
		g.stop()
	}()
	return nil
}

// startFrames brings the relay's own network stack up on the frame link,
// behind the filter that serves the lease and keeps ARP to the relay's
// address (GUEST-3 to GUEST-11).
func (g *Guest) startFrames(ctx context.Context) error {
	fl := newFrameLink(ctx, g.cfg.Frames, g)
	st, err := netstack.New(fl, netstack.Config{MAC: RelayMAC, Address: g.link, AnyAddress: true})
	if err != nil {
		return fmt.Errorf("the frame link's stack: %w", err)
	}
	g.stack = st
	g.controlLn = newConnListener(netip.AddrPortFrom(g.link.Addr(), PortControl))
	g.closers = append(g.closers, st, g.controlLn)
	pc, err := st.Network().ListenPacket(ctx, "udp", netip.AddrPortFrom(g.link.Addr(), PortDNS).String())
	if err != nil {
		return fmt.Errorf("DNS on the frame link: %w", err)
	}
	g.closers = append(g.closers, pc)
	go g.serveDNSPacket(pc)
	go func() { _ = g.control.Serve(g.controlLn) }()
	st.Capture(g.serveCaptured)
	fl.announce()
	return nil
}

// startIP binds the relay's ports at its own address (GUEST-2), and the
// lease's where it serves one.
func (g *Guest) startIP(ctx context.Context) error {
	addr := g.link.Addr()
	n := g.cfg.Net
	at := func(port int) string { return netip.AddrPortFrom(addr, uint16(port)).String() }
	if g.guest.IsValid() {
		pc, err := n.ListenPacket(ctx, "udp", at(portLease))
		if err != nil {
			return fmt.Errorf("the lease's port: %w", err)
		}
		g.closers = append(g.closers, pc)
		go g.serveLeasePacket(pc)
	}
	pc, err := n.ListenPacket(ctx, "udp", at(PortDNS))
	if err != nil {
		return fmt.Errorf("DNS over UDP: %w", err)
	}
	g.closers = append(g.closers, pc)
	go g.serveDNSPacket(pc)
	for _, port := range []int{PortDNS, PortHTTP, PortTLS, PortControl} {
		ln, err := n.Listen(ctx, "tcp", at(port))
		if err != nil {
			return fmt.Errorf("port %d: %w", port, err)
		}
		g.closers = append(g.closers, ln)
		if port == PortControl {
			go func() { _ = g.control.Serve(ln) }()
			continue
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go g.serveCaptured(c)
			}
		}()
	}
	return nil
}

// stop closes everything the build side holds.
func (g *Guest) stop() {
	g.mu.Lock()
	closers := g.closers
	g.closers = nil
	conns := g.conns
	g.conns = map[net.Conn]bool{}
	g.mu.Unlock()
	if g.control != nil {
		_ = g.control.Close()
	}
	for _, c := range closers {
		_ = c.Close()
	}
	for c := range conns {
		_ = c.Close()
	}
	if g.upstream != nil {
		g.upstream.CloseIdleConnections()
	}
}

// track keeps c until untrack, so that the relay's end closes it.
func (g *Guest) track(c net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx == nil || g.ctx.Err() != nil {
		return false
	}
	g.conns[c] = true
	return true
}

func (g *Guest) untrack(c net.Conn) {
	g.mu.Lock()
	delete(g.conns, c)
	g.mu.Unlock()
}

// serveCaptured serves one TCP connection of the build environment by the
// port it was made to: on a frame link to any address (GUEST-6), on a
// kernel interface to the relay's address.
func (g *Guest) serveCaptured(c net.Conn) {
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		_ = c.Close()
		return
	}
	if ap.Port() == PortControl && g.controlLn != nil {
		// The control plane's server takes the connection over.
		g.controlLn.push(c)
		return
	}
	if !g.track(c) {
		_ = c.Close()
		return
	}
	defer g.untrack(c)
	defer c.Close()
	switch ap.Port() {
	case PortTLS:
		g.serveTLS(c)
	case PortDNS:
		g.serveDNSStream(c)
	default:
		g.serveHTTP(c, "")
	}
}

// refused says whether the relay refuses to connect to a on the build's
// behalf (GUEST-46, CLAIM-41): in vm and host mode every address of the
// build link; in host mode also loopback, unspecified, private and
// link-local addresses and the cloud metadata addresses.
func (g *Guest) refused(a netip.Addr) bool {
	a = a.Unmap()
	g.mu.Lock()
	link := g.link.Masked()
	g.mu.Unlock()
	switch g.cfg.Mode {
	case ModeContainer:
		return false
	case ModeVM:
		return link.Contains(a)
	}
	return link.Contains(a) || a.IsLoopback() || a.IsUnspecified() || a.IsPrivate() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a == netip.AddrFrom4([4]byte{169, 254, 169, 254}) || a == netip.AddrFrom4([4]byte{100, 100, 100, 200})
}

// errRefusedUpstream is the dial's error for an upstream the relay refuses.
var errRefusedUpstream = errors.New("the relay refuses to connect there")

// dialUpstream connects to an upstream on the build's behalf: its name
// resolved through the claim's resolvers only, in their order, for A and
// AAAA records (GUEST-45); refused when any address it resolves to is
// refused (GUEST-46); and its addresses tried in their order, IPv4 first.
func (g *Guest) dialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	up := g.session.relay.cfg.Upstream
	if up == nil {
		return nil, errors.New("the relay has no upstream network")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		resolvers := g.session.claim.Resolvers
		v4, err := lookupType(ctx, up, resolvers, host, dns.TypeA)
		if err != nil {
			return nil, err
		}
		v6, err := lookupType(ctx, up, resolvers, host, dns.TypeAAAA)
		if err != nil && len(v4) == 0 {
			return nil, err
		}
		addrs = append(v4, v6...)
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolving %s: no address", host)
		}
	}
	for _, a := range addrs {
		if g.refused(a) {
			return nil, fmt.Errorf("%s: %s: %w", host, a, errRefusedUpstream)
		}
	}
	var last error
	for _, a := range addrs {
		c, err := up.Dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// connListener is a listener whose connections are handed to it: the
// control plane's on a frame link, where the stack captures them.
type connListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newConnListener(ap netip.AddrPort) *connListener {
	return &connListener{addr: net.TCPAddrFromAddrPort(ap), ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

// reservedName is the reserved name host spells, "artifacts" or "cwd", or
// "". This relay reads the names whatever their case and with or without a
// trailing dot, which relay-guest-api leaves undefined (GUEST-18; the Go
// relay matches them exactly, N23), so that a build that spells one so does
// not have it sent upstream.
func reservedName(host string) string {
	switch h := strings.ToLower(strings.TrimSuffix(host, ".")); h {
	case "artifacts", "cwd":
		return h
	}
	return ""
}
