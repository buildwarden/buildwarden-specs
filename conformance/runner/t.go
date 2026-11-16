package runner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// T is what a running case is given: the component under test, through its
// attachment, and what the case reports through. Its methods may be called
// from the case's own goroutines; Fatalf and FailNow only from the case's
// goroutine, as with testing.T.
type T struct {
	ctx    context.Context
	c      Case
	a      attach.Attachment
	shared *instances
	fresh  *instances

	mu       sync.Mutex
	failures []string
	logs     []string
	used     []attach.Instance
	cleanups []func()
	tempDirs []string
}

// Context is the case's context, done at its time limit.
func (t *T) Context() context.Context { return t.ctx }

// Declared is what the target declares.
func (t *T) Declared() target.Declared { return t.a.Declared() }

// Network is where the harness's roles listen and dial on side s. A side
// the component has not fails the case.
func (t *T) Network(s attach.Side) attach.Network {
	n, err := t.a.Network(s)
	if err != nil {
		t.Fatalf("the %s side: %v", s, err)
	}
	return n
}

// Instance is an instance of the component under test started with p: a
// fresh one at each call for a case that ends its instance, and for any
// other case the one that every such case started with p shares. An
// instance that cannot be started fails the case.
func (t *T) Instance(p attach.Params) attach.Instance {
	var in attach.Instance
	var err error
	if t.c.Ends {
		in, err = t.fresh.get(t.ctx, p, false)
	} else {
		in, err = t.shared.get(t.ctx, p, true)
	}
	if err != nil {
		t.Fatalf("starting the component under test: %v", err)
	}
	t.mu.Lock()
	t.used = append(t.used, in)
	t.mu.Unlock()
	return in
}

// TempDir is a new directory for the case, removed when it ends.
func (t *T) TempDir() string {
	dir, err := os.MkdirTemp("", "bw-conformance-case-")
	if err != nil {
		t.Fatalf("a temporary directory: %v", err)
	}
	t.mu.Lock()
	t.tempDirs = append(t.tempDirs, dir)
	t.mu.Unlock()
	return dir
}

// Cleanup registers f to run when the case ends, after the case's own
// code and before its fresh instances are stopped; the last registered
// runs first.
func (t *T) Cleanup(f func()) {
	t.mu.Lock()
	t.cleanups = append(t.cleanups, f)
	t.mu.Unlock()
}

// Logf records a line that the report gives if the case fails.
func (t *T) Logf(format string, args ...any) {
	t.mu.Lock()
	t.logs = append(t.logs, fmt.Sprintf(format, args...))
	t.mu.Unlock()
}

// Errorf records a failure of the case and lets it go on.
func (t *T) Errorf(format string, args ...any) {
	t.mu.Lock()
	t.failures = append(t.failures, fmt.Sprintf(format, args...))
	t.mu.Unlock()
}

// Fatalf records a failure and ends the case.
func (t *T) Fatalf(format string, args ...any) {
	t.Errorf(format, args...)
	t.FailNow()
}

// FailNow ends the case, which has recorded its failure.
func (t *T) FailNow() { runtime.Goexit() }

// Failed reports whether the case has recorded a failure.
func (t *T) Failed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.failures) > 0
}

// Failures returns the failures the case recorded, in order.
func (t *T) Failures() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.failures...)
}

// finish runs the case's cleanups, stops its fresh instances and removes
// its temporary directories.
func (t *T) finish() {
	t.mu.Lock()
	cleanups := t.cleanups
	t.cleanups = nil
	t.mu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("a cleanup panicked: %v", p)
				}
			}()
			cleanups[i]()
		}()
	}
	for _, err := range t.fresh.stop() {
		t.Errorf("stopping an instance: %v", err)
	}
	t.mu.Lock()
	dirs := t.tempDirs
	t.tempDirs = nil
	t.mu.Unlock()
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			t.Errorf("removing %s: %v", d, err)
		}
	}
}

// report is the case's failures, followed, when there are any, by its log
// lines and the log and exit of each instance it used.
func (t *T) report() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.failures) == 0 {
		return nil
	}
	out := append([]string(nil), t.failures...)
	for _, l := range t.logs {
		out = append(out, "log: "+l)
	}
	var seen []attach.Instance
	for _, in := range t.used {
		dup := false
		for _, s := range seen {
			dup = dup || s == in
		}
		if dup {
			continue
		}
		seen = append(seen, in)
		exit := in.Exit()
		if exit == "" {
			exit = "running when the case ended"
		}
		out = append(out, fmt.Sprintf("instance %d (%s), its output:\n%s", len(seen), exit, in.Log()))
	}
	return out
}
