package cases

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The ARP of a frame link as the cases read and write it (RFC 826, for
// Ethernet and IPv4).
const (
	ethHeader  = 14
	arpLen     = 28
	arpRequest = 1
	arpReply   = 2
)

// arp is one ARP message.
type arp struct {
	Op                   uint16
	SenderMAC, TargetMAC net.HardwareAddr
	SenderIP, TargetIP   netip.Addr
}

// arpFrame is an ARP message in an Ethernet frame from src to dst.
func arpFrame(src, dst net.HardwareAddr, m arp) []byte {
	b := make([]byte, ethHeader+arpLen)
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], netstack.EtherTypeARP)
	a := b[ethHeader:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], netstack.EtherTypeIPv4)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], m.Op)
	copy(a[8:14], m.SenderMAC)
	s, d := m.SenderIP.As4(), m.TargetIP.As4()
	copy(a[14:18], s[:])
	copy(a[18:24], m.TargetMAC)
	copy(a[24:28], d[:])
	return b
}

// parseARP reads an Ethernet frame that holds an ARP message for Ethernet
// and IPv4.
func parseARP(b []byte) (arp, bool) {
	if len(b) < ethHeader+arpLen || binary.BigEndian.Uint16(b[12:14]) != netstack.EtherTypeARP {
		return arp{}, false
	}
	a := b[ethHeader:]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != netstack.EtherTypeIPv4 || a[4] != 6 || a[5] != 4 {
		return arp{}, false
	}
	return arp{
		Op:        binary.BigEndian.Uint16(a[6:8]),
		SenderMAC: net.HardwareAddr(append([]byte(nil), a[8:14]...)),
		SenderIP:  netip.AddrFrom4([4]byte(a[14:18])),
		TargetMAC: net.HardwareAddr(append([]byte(nil), a[18:24]...)),
		TargetIP:  netip.AddrFrom4([4]byte(a[24:28])),
	}, true
}

// etherType is a frame's EtherType, and 0 for a frame too short for one.
func etherType(b []byte) uint16 {
	if len(b) < ethHeader {
		return 0
	}
	return binary.BigEndian.Uint16(b[12:14])
}

// dstMAC is a frame's destination address.
func dstMAC(b []byte) net.HardwareAddr { return net.HardwareAddr(b[0:6]) }

// gratuitous says whether b is a gratuitous ARP for addr: an ARP message,
// broadcast, whose sender and target addresses are both addr.
func gratuitous(b []byte, addr netip.Addr) bool {
	m, ok := parseARP(b)
	return ok && bytes.Equal(dstMAC(b), netstack.BroadcastMAC) && m.SenderIP == addr && m.TargetIP == addr
}

// frame is one frame a party read from the link, and when.
type frame struct {
	At    time.Time
	Bytes []byte
}

// party is the harness on a frame link with no network stack: it reads
// every frame the relay sends and keeps them, and sends the frames a case
// builds. Like a build environment it answers each ARP request for its own
// address, ip, with its MAC address, so that a relay that resolves the
// build's address by ARP can send to it; that is all it answers.
type party struct {
	t    *runner.T
	link net.Conn
	mac  net.HardwareAddr
	ip   netip.Addr

	mu     sync.Mutex
	frames []frame
	kick   chan struct{}
	err    error
}

// newParty starts a party on link. Its reader ends when the case does: its
// cleanup sets a read deadline that has passed, and the instance's Stop
// closes the link.
func newParty(t *runner.T, link net.Conn, mac net.HardwareAddr, ip netip.Addr) *party {
	p := &party{t: t, link: link, mac: mac, ip: ip, kick: make(chan struct{}, 1)}
	go p.read()
	t.Cleanup(func() { _ = link.SetReadDeadline(time.Unix(1, 0)) })
	return p
}

func (p *party) read() {
	buf := make([]byte, 1<<16)
	for {
		n, err := p.link.Read(buf)
		if err != nil {
			p.mu.Lock()
			p.err = err
			p.mu.Unlock()
			p.signal()
			return
		}
		b := append([]byte(nil), buf[:n]...)
		if m, ok := parseARP(b); ok && m.Op == arpRequest && m.TargetIP == p.ip {
			_, _ = p.link.Write(arpFrame(p.mac, m.SenderMAC, arp{
				Op: arpReply, SenderMAC: p.mac, SenderIP: p.ip, TargetMAC: m.SenderMAC, TargetIP: m.SenderIP,
			}))
		}
		p.mu.Lock()
		p.frames = append(p.frames, frame{At: time.Now(), Bytes: b})
		p.mu.Unlock()
		p.signal()
	}
}

func (p *party) signal() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// send writes one frame, and fails the case when the link refuses it.
func (p *party) send(b []byte) {
	if _, err := p.link.Write(b); err != nil {
		p.t.Fatalf("writing a frame to the relay's frame link: %v", err)
	}
}

// mark is the number of frames read so far: the index from which since
// and await look.
func (p *party) mark() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.frames)
}

// since is the frames read from index from on.
func (p *party) since(from int) []frame {
	p.mu.Lock()
	defer p.mu.Unlock()
	if from > len(p.frames) {
		return nil
	}
	return append([]frame(nil), p.frames[from:]...)
}

// await waits for at most d for a frame from index from on that match
// accepts, and returns the first.
func (p *party) await(from int, d time.Duration, match func([]byte) bool) (frame, bool) {
	f, _, ok := p.awaitAt(from, d, match)
	return f, ok
}

// awaitAt is await, which also returns the frame's index.
func (p *party) awaitAt(from int, d time.Duration, match func([]byte) bool) (frame, int, bool) {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		for i := from; i < len(p.frames); i++ {
			if match(p.frames[i].Bytes) {
				f := p.frames[i]
				p.mu.Unlock()
				return f, i, true
			}
		}
		from = len(p.frames)
		err := p.err
		p.mu.Unlock()
		if err != nil {
			return frame{}, 0, false
		}
		select {
		case <-p.kick:
		case <-deadline.C:
			return frame{}, 0, false
		case <-p.t.Context().Done():
			return frame{}, 0, false
		}
	}
}

// relayMAC asks the relay for its MAC address by ARP, and fails the case
// when no reply comes within the bound.
func (p *party) relayMAC(relay netip.Addr) net.HardwareAddr {
	from := p.mark()
	p.send(arpFrame(p.mac, netstack.BroadcastMAC, arp{Op: arpRequest, SenderMAC: p.mac, SenderIP: p.ip, TargetMAC: make(net.HardwareAddr, 6), TargetIP: relay}))
	f, ok := p.await(from, within, func(b []byte) bool {
		m, ok := parseARP(b)
		return ok && m.Op == arpReply && m.SenderIP == relay && !bytes.Equal(dstMAC(b), netstack.BroadcastMAC)
	})
	if !ok {
		p.t.Fatalf("no ARP reply for the relay's address %s within %s", relay, within)
	}
	m, _ := parseARP(f.Bytes)
	return m.SenderMAC
}

// udp sends payload from the party's address at port sport to dst, in a
// frame to the MAC address to.
func (p *party) udp(to net.HardwareAddr, sport uint16, dst netip.AddrPort, payload []byte) {
	p.send(netstack.UDPFrame{
		SrcMAC: p.mac, DstMAC: to,
		Src: netip.AddrPortFrom(p.ip, sport), Dst: dst, Payload: payload,
	}.Marshal())
}

// udpTo matches a UDP datagram to the party's port.
func udpTo(port uint16) func([]byte) bool {
	return func(b []byte) bool {
		u, ok := netstack.ParseUDPFrame(b)
		return ok && u.Dst.Port() == port
	}
}

// tap is a frame link as the build environment's stack is given it: it
// passes every frame through, and keeps each with its direction and its
// place in the order, so that a case can see what the relay sent before
// and after the build environment's first frame.
type tap struct {
	net.Conn

	mu     sync.Mutex
	frames []tapped
}

// tapped is one frame through a tap: Out for one the harness sent.
type tapped struct {
	Out   bool
	Bytes []byte
}

func (c *tap) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.keep(false, b[:n])
	}
	return n, err
}

func (c *tap) Write(b []byte) (int, error) {
	c.keep(true, b)
	return c.Conn.Write(b)
}

func (c *tap) keep(out bool, b []byte) {
	c.mu.Lock()
	c.frames = append(c.frames, tapped{Out: out, Bytes: append([]byte(nil), b...)})
	c.mu.Unlock()
}

func (c *tap) all() []tapped {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]tapped(nil), c.frames...)
}
