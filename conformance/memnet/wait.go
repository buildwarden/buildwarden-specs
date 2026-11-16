package memnet

import (
	"net"
	"os"
	"sync"
	"time"
)

// signal is a broadcast a waiter selects on: kick wakes every goroutine that
// took the channel before it, and each then looks at the state again. It is
// a sync.Cond that can also be woken by a deadline.
type signal struct{ ch chan struct{} }

func newSignal() signal { return signal{ch: make(chan struct{})} }

// kick must be called with the lock that guards the state held.
func (s *signal) kick() {
	close(s.ch)
	s.ch = make(chan struct{})
}

// deadline is one direction's deadline of a connection.
type deadline struct {
	mu sync.Mutex
	t  time.Time
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.t = t
	d.mu.Unlock()
}

func (d *deadline) get() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.t
}

// wait blocks until ch is closed or the deadline dl passes, and reports
// whether the deadline passed. A zero dl never passes.
func wait(ch <-chan struct{}, dl time.Time) bool {
	if dl.IsZero() {
		<-ch
		return false
	}
	d := time.Until(dl)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return false
	case <-t.C:
		return true
	}
}

// expired reports whether the deadline dl has passed.
func expired(dl time.Time) bool { return !dl.IsZero() && !time.Now().Before(dl) }

// opError is the error an operation on the in-memory network returns, in
// the form the standard library's sockets give, so that errors.Is and the
// net.Error methods work on it as on a kernel socket's.
func opError(op, network string, src, dst net.Addr, err error) error {
	return &net.OpError{Op: op, Net: network, Source: src, Addr: dst, Err: err}
}

// errTimeout is the error of an operation whose deadline passed.
var errTimeout = os.ErrDeadlineExceeded
