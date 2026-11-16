package inprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// Form is what an in-process collector is started as beside what a start's
// parameters give it (the build script, the context and the capture mode):
// its token, its bootstrap config, and whether it serves after its
// completion. Each is one configuration, which declares the forms it is:
// no_bootstrap when Bootstrap is nil, no_token when Token is empty, and
// serves_after_completion; no_script and no_context always, since a start
// without either leaves it out.
type Form struct {
	Token                 string
	Bootstrap             []byte
	ServesAfterCompletion bool
	// UpstreamCACerts are sent in the claim, as the disk collector sends
	// those of its --upstream-ca; the forms of Forms have none.
	UpstreamCACerts []string
}

// Bootstrap is the bootstrap config of the forms that have one: the disk
// collector's (bootstrap-config).
var Bootstrap = []byte(`{"version":1,"trust":{"mode":"exclusive"}}`)

// Forms are the collector's in-process configurations, by name: each of the
// token, the bootstrap config and serving after the completion, present or
// not.
func Forms() map[string]Form {
	out := map[string]Form{}
	for i := 0; i < 8; i++ {
		var f Form
		var name []string
		if i&1 != 0 {
			f.Token = "session-token"
			name = append(name, "token")
		}
		if i&2 != 0 {
			f.Bootstrap = Bootstrap
			name = append(name, "bootstrap")
		}
		if i&4 != 0 {
			f.ServesAfterCompletion = true
			name = append(name, "serves-after")
		}
		if len(name) == 0 {
			name = []string{"bare"}
		}
		out[strings.Join(name, "+")] = f
	}
	return out
}

// errNoClaim is Start's error for a collector given no claim address.
var errNoClaim = errors.New("inprocess: a collector that claims is started against a claim address, and none was given")

// Collector is an attachment of the harness's collector in form f, with the
// harness's claimant in front of it.
func Collector(f Form) attach.Attachment {
	return &collectorAttachment{f: f, claim: memnet.New()}
}

type collectorAttachment struct {
	f     Form
	claim *memnet.Net
}

func (a *collectorAttachment) Declared() target.Declared {
	return target.Declared{
		Role: "collector", Attachment: "claims",
		Forms: target.Forms{
			NoScript: true, NoContext: true,
			NoBootstrap: a.f.Bootstrap == nil, NoToken: a.f.Token == "",
			ServesAfterCompletion: a.f.ServesAfterCompletion,
		},
		Capture: true, ReadBack: true, FreshInstances: true,
	}
}

// Network is the claim side, where the harness's relay waits for the
// collector's claim; a collector has no other side.
func (a *collectorAttachment) Network(s attach.Side) (attach.Network, error) {
	if s != attach.Claim {
		return nil, fmt.Errorf("a collector has no %s side: %w", s, attach.ErrNoSide)
	}
	return a.claim.Host(ClaimRelay), nil
}

func (a *collectorAttachment) Close() error { return nil }

// Start starts a collector in the attachment's form, with p's build script
// and context, which opens the tunnel to the relay at p.Claim and claims it
// with p.Token and capture mode p.Capture, as the disk collector does when it
// starts. The claim is made after Start returns, as a process's is.
func (a *collectorAttachment) Start(ctx context.Context, p attach.Params) (attach.Instance, error) {
	if p.Claim == "" {
		return nil, errNoClaim
	}
	form := collector.Form{Token: a.f.Token, Bootstrap: a.f.Bootstrap, ServesAfterCompletion: a.f.ServesAfterCompletion}
	if p.Script != "" {
		b, err := os.ReadFile(p.Script)
		if err != nil {
			return nil, fmt.Errorf("inprocess: the build script: %w", err)
		}
		form.Script = b
	}
	if p.Context != "" {
		files, err := readContext(p.Context)
		if err != nil {
			return nil, fmt.Errorf("inprocess: the context: %w", err)
		}
		form.Context = files
	}
	in := &collectorInstance{coll: collector.New(form, nil), out: p.Out, done: make(chan struct{})}
	cl := claimant.Claimant{Net: a.claim.Host(ClaimHarness), Endpoint: attach.Endpoint{Address: p.Claim, Token: p.Token}}
	cctx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	go in.run(cctx, cl, claimant.Config{CollectorToken: a.f.Token, CaptureMode: p.Capture, UpstreamCACerts: a.f.UpstreamCACerts})
	return in, nil
}

// readContext reads every regular file under dir, by its path relative to
// dir with "/" between segments.
func readContext(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		files[filepath.ToSlash(rel)] = b
		return err
	})
	return files, err
}

// collectorInstance is one collector and its claimant's session.
type collectorInstance struct {
	coll   *collector.Collector
	out    string
	cancel context.CancelFunc
	done   chan struct{}

	mu   sync.Mutex
	log  bytes.Buffer
	exit string
	tun  *claimant.Tunnel
}

func (in *collectorInstance) logf(format string, a ...any) {
	in.mu.Lock()
	defer in.mu.Unlock()
	fmt.Fprintf(&in.log, time.Now().UTC().Format(time.RFC3339Nano)+" "+format+"\n", a...)
}

// run opens the tunnel and claims, and then waits for the session's end.
func (in *collectorInstance) run(ctx context.Context, cl claimant.Claimant, cfg claimant.Config) {
	defer close(in.done)
	tun, rep, err := cl.Session(ctx, in.coll, cfg)
	if err != nil {
		in.end(fmt.Sprintf("the claim failed: %v", err))
		return
	}
	in.mu.Lock()
	in.tun = tun
	in.mu.Unlock()
	in.logf("claimed: %d %s", rep.Status, strings.TrimSpace(string(rep.Body)))
	select {
	case <-tun.Closed():
		in.end("the session's connection closed")
	case <-ctx.Done():
		in.end("stopped")
	}
}

func (in *collectorInstance) end(why string) {
	in.logf("%s", why)
	in.mu.Lock()
	if in.exit == "" {
		in.exit = why
	}
	in.mu.Unlock()
}

func (in *collectorInstance) Claim() attach.Endpoint { return attach.Endpoint{} }

func (in *collectorInstance) Frames() (net.Conn, error) {
	return nil, fmt.Errorf("a collector has no build link: %w", attach.ErrNoFrames)
}

func (in *collectorInstance) Log() []byte {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]byte(nil), in.log.Bytes()...)
}

func (in *collectorInstance) Exit() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.exit
}

// Stop closes the session's tunnel and waits for the claimant to end.
func (in *collectorInstance) Stop() error {
	in.cancel()
	in.mu.Lock()
	tun := in.tun
	in.mu.Unlock()
	var err error
	if tun != nil {
		err = tun.Close()
	}
	<-in.done
	return err
}

// ReadBack writes what the collector stored into a directory in the disk
// layout (collector-outputs, The disk collector's layout): the start's
// output location when it was given one, and otherwise a new temporary
// directory, which the caller removes.
func (in *collectorInstance) ReadBack(context.Context) (string, error) {
	dir := in.out
	if dir == "" {
		d, err := os.MkdirTemp("", "bw-conformance-readback-")
		if err != nil {
			return "", err
		}
		dir = d
	}
	return dir, writeLayout(dir, in.coll)
}

func writeLayout(dir string, c *collector.Collector) error {
	write := func(rel string, b []byte) error {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o644)
	}
	var errs []error
	names := make([]string, 0)
	arts := c.Artifacts()
	for n := range arts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		errs = append(errs, write("artifacts/"+n, arts[n]))
	}
	for _, cp := range c.Captures() {
		payload := "payloads/" + cp.Hash
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(payload))); err != nil {
			errs = append(errs, write(payload, cp.Body))
		}
		link := filepath.Join(dir, "captures", filepath.FromSlash(cp.Name))
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			errs = append(errs, err)
			continue
		}
		up := strings.Repeat("../", strings.Count(cp.Name, "/")+1)
		if err := os.Symlink(up+payload, link); err != nil {
			// Where a link cannot be made, a copy (COLLOUT-33).
			errs = append(errs, write("captures/"+cp.Name, cp.Body))
		}
	}
	ledger, _, _ := c.Ledger()
	errs = append(errs, write("ledger", ledger))
	if env, n := c.Environment(); n > 0 && env != nil {
		errs = append(errs, write("environment.json", env))
	}
	errs = append(errs, write("build-output.log", c.Output()))
	return errors.Join(errs...)
}
