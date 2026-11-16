package memnet

import (
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// Frames returns the two ends of a frame pipe: a link that carries one
// Ethernet frame per datagram, as the socket pair of a relay's frame link
// does. Each Write on one end is one frame, read whole by one Read on the
// other; a Read into a buffer shorter than the frame returns its first bytes
// and drops the rest, as a datagram socket does. A write waits while the
// other end holds FrameQueue frames unread. After one end is closed, the
// other reads what was sent before and then io.EOF, and its writes fail.
//
// A frame pipe is not on any segment: it is the whole link between its two
// ends, which bring their own network stacks.
func Frames() (net.Conn, net.Conn) {
	ab, ba := newFrameQueue(), newFrameQueue()
	return &frameEnd{name: "a", in: ba, out: ab}, &frameEnd{name: "b", in: ab, out: ba}
}

type frameQueue struct {
	mu     sync.Mutex
	frames [][]byte
	eof    bool // the writer is closed
	gone   bool // the reader is closed
	signal signal
}

func newFrameQueue() *frameQueue { return &frameQueue{signal: newSignal()} }

type frameEnd struct {
	name    string
	in, out *frameQueue

	mu     sync.Mutex
	closed bool
	rd, wd deadline
}

// frameAddr names one end of a frame pipe.
type frameAddr string

func (a frameAddr) Network() string { return "frames" }
func (a frameAddr) String() string  { return "frame-pipe-" + string(a) }

func (e *frameEnd) peer() string {
	if e.name == "a" {
		return "b"
	}
	return "a"
}

func (e *frameEnd) err(op string, err error) error {
	return opError(op, "frames", frameAddr(e.name), frameAddr(e.peer()), err)
}

func (e *frameEnd) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func (e *frameEnd) Read(p []byte) (int, error) {
	q := e.in
	for {
		if e.isClosed() {
			return 0, e.err("read", net.ErrClosed)
		}
		q.mu.Lock()
		switch {
		case len(q.frames) > 0:
			f := q.frames[0]
			q.frames = q.frames[1:]
			q.signal.kick()
			q.mu.Unlock()
			return copy(p, f), nil
		case q.eof:
			q.mu.Unlock()
			return 0, io.EOF
		}
		dl := e.rd.get()
		if expired(dl) {
			q.mu.Unlock()
			return 0, e.err("read", errTimeout)
		}
		ch := q.signal.ch
		q.mu.Unlock()
		wait(ch, dl)
	}
}

func (e *frameEnd) Write(p []byte) (int, error) {
	q := e.out
	for {
		if e.isClosed() {
			return 0, e.err("write", net.ErrClosed)
		}
		q.mu.Lock()
		switch {
		case q.gone:
			q.mu.Unlock()
			return 0, e.err("write", syscall.ECONNREFUSED)
		case len(q.frames) < FrameQueue:
			q.frames = append(q.frames, append([]byte(nil), p...))
			q.signal.kick()
			q.mu.Unlock()
			return len(p), nil
		}
		dl := e.wd.get()
		if expired(dl) {
			q.mu.Unlock()
			return 0, e.err("write", errTimeout)
		}
		ch := q.signal.ch
		q.mu.Unlock()
		wait(ch, dl)
	}
}

func (e *frameEnd) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return e.err("close", net.ErrClosed)
	}
	e.closed = true
	e.mu.Unlock()
	e.out.mu.Lock()
	e.out.eof = true
	e.out.signal.kick()
	e.out.mu.Unlock()
	e.in.mu.Lock()
	e.in.gone = true
	e.in.frames = nil
	e.in.signal.kick()
	e.in.mu.Unlock()
	return nil
}

func (e *frameEnd) LocalAddr() net.Addr  { return frameAddr(e.name) }
func (e *frameEnd) RemoteAddr() net.Addr { return frameAddr(e.peer()) }

func (e *frameEnd) SetDeadline(t time.Time) error {
	e.rd.set(t)
	e.wd.set(t)
	e.wake()
	return nil
}

func (e *frameEnd) SetReadDeadline(t time.Time) error {
	e.rd.set(t)
	e.wake()
	return nil
}

func (e *frameEnd) SetWriteDeadline(t time.Time) error {
	e.wd.set(t)
	e.wake()
	return nil
}

func (e *frameEnd) wake() {
	for _, q := range []*frameQueue{e.in, e.out} {
		q.mu.Lock()
		q.signal.kick()
		q.mu.Unlock()
	}
}
