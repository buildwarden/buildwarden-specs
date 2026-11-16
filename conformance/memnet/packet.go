package memnet

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

type datagram struct {
	from netip.AddrPort
	data []byte
}

// packetConn is a datagram endpoint, unconnected from ListenPacket and
// connected to one remote address from Dial, as a UDP socket is.
type packetConn struct {
	n       *Net
	network string
	local   netip.AddrPort // as bound; its address may be unspecified
	source  netip.Addr     // the address it sends from when local's is unspecified
	remote  netip.AddrPort // the connected remote, or the zero value

	mu      sync.Mutex
	queue   []datagram
	closed  bool
	refused bool
	signal  signal
	rd, wd  deadline
}

// bind binds local, sending from source where local's address is
// unspecified, and connects the endpoint to remote unless it is the zero
// value.
func (n *Net) bind(network string, local netip.AddrPort, source netip.Addr, remote netip.AddrPort) (*packetConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if local.Port() == 0 {
		p, err := ephemeral(n, n.endpoints, local.Addr())
		if err != nil {
			return nil, opError("listen", network, nil, udpAddr(local), err)
		}
		local = netip.AddrPortFrom(local.Addr(), p)
	}
	if taken(n.endpoints, local) {
		return nil, opError("listen", network, nil, udpAddr(local), syscall.EADDRINUSE)
	}
	c := &packetConn{n: n, network: network, local: local, source: source, remote: remote, signal: newSignal()}
	n.endpoints[local] = c
	return c, nil
}

// send delivers one datagram from the endpoint c to dst: to what is bound
// there, or to every endpoint on dst's port when dst is the broadcast
// address. Where nothing is bound it is dropped, and c learns of the refusal
// if c is connected to dst.
func (n *Net) send(c *packetConn, dst netip.AddrPort, p []byte) {
	src := c.local
	if src.Addr().IsUnspecified() {
		src = netip.AddrPortFrom(c.source, src.Port())
	}
	n.mu.Lock()
	var to []*packetConn
	if dst.Addr() == Broadcast {
		for k, e := range n.endpoints {
			if k.Port() == dst.Port() {
				to = append(to, e)
			}
		}
	} else if e, ok := lookup(n.endpoints, dst); ok {
		to = append(to, e)
	}
	n.mu.Unlock()
	if len(to) == 0 {
		if c.remote == dst {
			c.mu.Lock()
			c.refused = true
			c.signal.kick()
			c.mu.Unlock()
		}
		return
	}
	for _, e := range to {
		e.deliver(datagram{from: src, data: append([]byte(nil), p...)})
	}
}

func (c *packetConn) deliver(d datagram) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.queue) >= DatagramQueue {
		return
	}
	if c.remote.IsValid() && d.from != c.remote {
		return
	}
	c.queue = append(c.queue, d)
	c.signal.kick()
}

func (c *packetConn) err(op string, err error) error {
	var remote net.Addr
	if c.remote.IsValid() {
		remote = udpAddr(c.remote)
	}
	return opError(op, c.network, udpAddr(c.local), remote, err)
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			return 0, nil, c.err("read", net.ErrClosed)
		case c.refused:
			c.refused = false
			c.mu.Unlock()
			return 0, nil, c.err("read", syscall.ECONNREFUSED)
		case len(c.queue) > 0:
			d := c.queue[0]
			c.queue = c.queue[1:]
			c.mu.Unlock()
			return copy(p, d.data), udpAddr(d.from), nil
		}
		dl := c.rd.get()
		if expired(dl) {
			c.mu.Unlock()
			return 0, nil, c.err("read", errTimeout)
		}
		ch := c.signal.ch
		c.mu.Unlock()
		wait(ch, dl)
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, c.err("write", errors.New("not a UDP address"))
	}
	dst := ua.AddrPort()
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if !dst.Addr().Is4() {
		return 0, c.err("write", errors.New("the in-memory network carries IPv4 only"))
	}
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return 0, c.err("write", net.ErrClosed)
	case c.refused:
		c.refused = false
		c.mu.Unlock()
		return 0, c.err("write", syscall.ECONNREFUSED)
	}
	c.mu.Unlock()
	if expired(c.wd.get()) {
		return 0, c.err("write", errTimeout)
	}
	c.n.send(c, dst, p)
	return len(p), nil
}

// Read reads the next datagram from the connected remote.
func (c *packetConn) Read(p []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.err("read", syscall.ENOTCONN)
	}
	n, _, err := c.ReadFrom(p)
	return n, err
}

// Write sends p as one datagram to the connected remote.
func (c *packetConn) Write(p []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.err("write", syscall.ENOTCONN)
	}
	return c.WriteTo(p, udpAddr(c.remote))
}

func (c *packetConn) Close() error {
	c.n.mu.Lock()
	if c.n.endpoints[c.local] == c {
		delete(c.n.endpoints, c.local)
	}
	c.n.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.err("close", net.ErrClosed)
	}
	c.closed = true
	c.queue = nil
	c.signal.kick()
	return nil
}

func (c *packetConn) LocalAddr() net.Addr { return udpAddr(c.local) }

// RemoteAddr is the connected remote, or nil for an unconnected endpoint.
func (c *packetConn) RemoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return udpAddr(c.remote)
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	c.wake()
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	c.wake()
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

func (c *packetConn) wake() {
	c.mu.Lock()
	c.signal.kick()
	c.mu.Unlock()
}
