// Package launch makes an attachment of what a target file describes: it
// starts the component under test, or reaches it where it already runs, by
// the launcher the file names.
//
// This harness builds the exec launcher for a collector that claims, which
// runs as a process of this host, and the external launcher for a relay.
// The exec launcher for a relay runs it in the Linux sandbox, and the oci
// launcher runs an image; neither is built yet, and neither is a collector
// that listens, which the format names so that it does not assume a
// collector is its own claimant. A target that needs one of them is an
// error that says so, never a skip.
package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// Limits of the launchers. They are constants of a harness release, not
// settings.
const (
	// StopGrace is how long a stopped process has to exit after it is
	// interrupted before it is killed.
	StopGrace = 5 * time.Second
	// CommandLimit is how long a target's own command (an external relay's
	// request, a read-back) may run.
	CommandLimit = 60 * time.Second
	// LogLimit is how much of a component's output is kept for a failure:
	// the last LogLimit bytes.
	LogLimit = 1 << 20
)

// ErrNotBuilt is wrapped by the error for a target whose launcher or
// attachment this harness does not build yet.
var ErrNotBuilt = errors.New("not built by this harness yet")

// Attach makes the attachment of the target f describes.
func Attach(f target.File) (attach.Attachment, error) {
	switch {
	case f.Role == "relay" && f.Launcher == "exec":
		return nil, fmt.Errorf("%s: the exec launcher runs a relay in the Linux sandbox, which is %w", f.Path, ErrNotBuilt)
	case f.Launcher == "oci":
		return nil, fmt.Errorf("%s: the oci launcher is %w", f.Path, ErrNotBuilt)
	case f.Role == "collector" && f.Collector.Attachment == "listens":
		return nil, fmt.Errorf("%s: a collector that listens is named by the target-file format and %w", f.Path, ErrNotBuilt)
	case f.Role == "collector":
		return &execCollector{f: f}, nil
	default:
		up, err := netip.ParseAddr(f.External.Upstream)
		if err != nil {
			return nil, fmt.Errorf("%s: external.upstream: %w", f.Path, err)
		}
		return &externalRelay{f: f, upstream: up}, nil
	}
}

// program resolves a target's program: a path with a separator is relative
// to the target file's directory, and a bare name is looked up in PATH.
func program(f target.File, name string) string {
	name = filepath.FromSlash(name)
	if filepath.IsAbs(name) || !strings.ContainsRune(name, filepath.Separator) {
		return name
	}
	return filepath.Join(filepath.Dir(f.Path), name)
}

func values(p attach.Params) map[string]string {
	return map[string]string{
		"claim":   p.Claim,
		"token":   p.Token,
		"out":     p.Out,
		"context": p.Context,
		"script":  p.Script,
		"capture": p.Capture,
	}
}

// runCommand runs a target's own command to its end, within CommandLimit,
// and returns its standard output.
func runCommand(ctx context.Context, f target.File, key string, argv []string, log *logBuffer) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, program(f, argv[0]), argv[1:]...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = log
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %s did not end within %s", f.Path, key, CommandLimit)
		}
		return nil, fmt.Errorf("%s: %s %q: %w", f.Path, key, argv, err)
	}
	return stdout.Bytes(), nil
}

// logBuffer keeps the last LogLimit bytes written to it.
type logBuffer struct {
	mu      sync.Mutex
	b       []byte
	dropped bool
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	if over := len(l.b) - LogLimit; over > 0 {
		l.b = append(l.b[:0], l.b[over:]...)
		l.dropped = true
	}
	return len(p), nil
}

func (l *logBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dropped {
		return append([]byte("[earlier output dropped]\n"), l.b...)
	}
	return append([]byte(nil), l.b...)
}
