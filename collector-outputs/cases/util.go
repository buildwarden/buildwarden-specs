package cases

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// cutSettle is how long a case lets a request's first bytes, or its reset,
// reach the collector.
const cutSettle = 200 * time.Millisecond

// errCut ends the body of a request a case cuts short.
var errCut = errors.New("the case cut the request short")

func contextWithCancel(t *runner.T) (context.Context, context.CancelFunc) {
	return context.WithCancel(t.Context())
}

func newPipe() (*io.PipeReader, *io.PipeWriter) { return io.Pipe() }

// sleep waits for d, or fails the case when its context ends first.
func sleep(t *runner.T, d time.Duration) {
	select {
	case <-time.After(d):
	case <-t.Context().Done():
		t.Fatalf("the case's time ran out")
	}
}

// waitFor polls cond every 20 ms until it holds or within has passed, and
// says whether it held.
func waitFor(t *runner.T, within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		sleep(t, 20*time.Millisecond)
	}
}
