package memnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

type listener struct {
	n       *Net
	network string
	addr    netip.AddrPort
	backlog chan *streamConn
	done    chan struct{}
	once    sync.Once
}

func (n *Net) listen(network string, ap netip.AddrPort) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ap.Port() == 0 {
		p, err := ephemeral(n, n.listeners, ap.Addr())
		if err != nil {
			return nil, opError("listen", network, nil, tcpAddr(ap), err)
		}
		ap = netip.AddrPortFrom(ap.Addr(), p)
	}
	if taken(n.listeners, ap) {
		return nil, opError("listen", network, nil, tcpAddr(ap), syscall.EADDRINUSE)
	}
	l := &listener{n: n, network: network, addr: ap, backlog: make(chan *streamConn, Backlog), done: make(chan struct{})}
	n.listeners[ap] = l
	return l, nil
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.backlog:
		return c, nil
	case <-l.done:
		return nil, opError("accept", l.network, nil, tcpAddr(l.addr), net.ErrClosed)
	}
}

// Close stops the listener. The connections it had not accepted are reset,
// as a kernel resets those in a closed listener's queue.
func (l *listener) Close() error {
	l.once.Do(func() {
		l.n.mu.Lock()
		if l.n.listeners[l.addr] == l {
			delete(l.n.listeners, l.addr)
		}
		close(l.done)
		l.n.mu.Unlock()
		for {
			select {
			case c := <-l.backlog:
				c.reset()
			default:
				return
			}
		}
	})
	return nil
}

func (l *listener) Addr() net.Addr { return tcpAddr(l.addr) }

// dial connects from src, on an ephemeral port, to what listens at dst.
func (n *Net) dial(ctx context.Context, network string, src netip.Addr, dst netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, opError("dial", network, nil, tcpAddr(dst), err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := lookup(n.listeners, dst)
	if !ok {
		return nil, opError("dial", network, nil, tcpAddr(dst), syscall.ECONNREFUSED)
	}
	p, err := ephemeral(n, n.listeners, src)
	if err != nil {
		return nil, opError("dial", network, nil, tcpAddr(dst), err)
	}
	local := netip.AddrPortFrom(src, p)
	client, server := streamPair(network, local, dst)
	select {
	case l.backlog <- server:
		return client, nil
	default:
		return nil, opError("dial", network, tcpAddr(local), tcpAddr(dst), syscall.ECONNREFUSED)
	}
}

// half is one direction of a stream connection: what one end has written
// and the other not yet read.
type half struct {
	mu     sync.Mutex
	buf    []byte
	eof    bool // the writer will write no more
	gone   bool // the reader is closed: a write fails
	reset  bool // the connection was reset: a read fails
	signal signal
}

func newHalf() *half { return &half{signal: newSignal()} }

type streamConn struct {
	network       string
	local, remote netip.AddrPort
	in, out       *half

	mu     sync.Mutex
	closed bool
	rd, wd deadline
}

func streamPair(network string, a, b netip.AddrPort) (*streamConn, *streamConn) {
	ab, ba := newHalf(), newHalf()
	return &streamConn{network: network, local: a, remote: b, in: ba, out: ab},
		&streamConn{network: network, local: b, remote: a, in: ab, out: ba}
}

func (c *streamConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *streamConn) err(op string, err error) error {
	return opError(op, c.network, tcpAddr(c.local), tcpAddr(c.remote), err)
}

func (c *streamConn) Read(p []byte) (int, error) {
	h := c.in
	for {
		if c.isClosed() {
			return 0, c.err("read", net.ErrClosed)
		}
		h.mu.Lock()
		switch {
		case h.reset:
			h.mu.Unlock()
			return 0, c.err("read", syscall.ECONNRESET)
		case len(h.buf) > 0:
			n := copy(p, h.buf)
			h.buf = h.buf[n:]
			h.signal.kick()
			h.mu.Unlock()
			return n, nil
		case h.eof:
			h.mu.Unlock()
			return 0, io.EOF
		case len(p) == 0:
			h.mu.Unlock()
			return 0, nil
		}
		dl := c.rd.get()
		if expired(dl) {
			h.mu.Unlock()
			return 0, c.err("read", errTimeout)
		}
		ch := h.signal.ch
		h.mu.Unlock()
		wait(ch, dl)
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	h := c.out
	written := 0
	for {
		if c.isClosed() {
			return written, c.err("write", net.ErrClosed)
		}
		h.mu.Lock()
		switch {
		case h.reset, h.gone:
			h.mu.Unlock()
			return written, c.err("write", syscall.ECONNRESET)
		case h.eof:
			h.mu.Unlock()
			return written, c.err("write", syscall.EPIPE)
		}
		if written == len(p) {
			h.mu.Unlock()
			return written, nil
		}
		if room := StreamBuffer - len(h.buf); room > 0 {
			n := min(room, len(p)-written)
			h.buf = append(h.buf, p[written:written+n]...)
			written += n
			h.signal.kick()
			h.mu.Unlock()
			continue
		}
		dl := c.wd.get()
		if expired(dl) {
			h.mu.Unlock()
			return written, c.err("write", errTimeout)
		}
		ch := h.signal.ch
		h.mu.Unlock()
		wait(ch, dl)
	}
}

// Close closes both directions: the other end reads what was written and
// then EOF, and its writes fail.
func (c *streamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.err("close", net.ErrClosed)
	}
	c.closed = true
	c.mu.Unlock()
	c.out.mu.Lock()
	c.out.eof = true
	c.out.signal.kick()
	c.out.mu.Unlock()
	c.in.mu.Lock()
	c.in.gone = true
	c.in.buf = nil
	c.in.signal.kick()
	c.in.mu.Unlock()
	return nil
}

// CloseWrite closes the direction this end writes, as a TCP FIN does: the
// other end reads EOF after what was written, and this end can still read.
func (c *streamConn) CloseWrite() error {
	if c.isClosed() {
		return c.err("close", net.ErrClosed)
	}
	c.out.mu.Lock()
	c.out.eof = true
	c.out.signal.kick()
	c.out.mu.Unlock()
	return nil
}

// reset fails both directions for both ends.
func (c *streamConn) reset() {
	for _, h := range []*half{c.in, c.out} {
		h.mu.Lock()
		h.reset = true
		h.buf = nil
		h.signal.kick()
		h.mu.Unlock()
	}
}

func (c *streamConn) LocalAddr() net.Addr  { return tcpAddr(c.local) }
func (c *streamConn) RemoteAddr() net.Addr { return tcpAddr(c.remote) }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	c.wake()
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	c.wake()
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	c.wake()
	return nil
}

// wake has every waiter on this end look at its deadline again.
func (c *streamConn) wake() {
	for _, h := range []*half{c.in, c.out} {
		h.mu.Lock()
		h.signal.kick()
		h.mu.Unlock()
	}
}
