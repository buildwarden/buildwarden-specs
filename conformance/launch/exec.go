package launch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// execCollector is the exec launcher for a collector that claims: each start
// runs the target's program with its command line and environment expanded
// for that start. The collector runs on this host, so the harness's relay
// waits for its claim on loopback.
type execCollector struct{ f target.File }

func (a *execCollector) Declared() target.Declared { return a.f.Declared() }

func (a *execCollector) Network(s attach.Side) (attach.Network, error) {
	if s != attach.Claim {
		return nil, fmt.Errorf("a collector target has no %s side: %w", s, attach.ErrNoSide)
	}
	return attach.Host(netip.AddrFrom4([4]byte{127, 0, 0, 1})), nil
}

func (a *execCollector) Close() error { return nil }

func (a *execCollector) Start(_ context.Context, p attach.Params) (attach.Instance, error) {
	v := values(p)
	argv, err := target.ExpandArgv(a.f.Exec.Argv, v)
	if err != nil {
		return nil, fmt.Errorf("%s: exec.argv: %w", a.f.Path, err)
	}
	env, err := target.ExpandEnv(a.f.Exec.Env, v)
	if err != nil {
		return nil, fmt.Errorf("%s: exec.env: %w", a.f.Path, err)
	}
	for _, n := range a.f.Exec.PassEnv {
		if val, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+val)
		}
	}
	// The process outlives the start's context: it is ended by Stop.
	cmd := exec.Command(program(a.f, argv[0]), argv[1:]...)
	cmd.Env = env
	in := &process{f: a.f, values: v, cmd: cmd, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = &in.log, &in.log
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: starting %q: %w", a.f.Path, argv[0], err)
	}
	go func() {
		err := cmd.Wait()
		in.mu.Lock()
		switch {
		case cmd.ProcessState != nil:
			in.exit = cmd.ProcessState.String()
		case err != nil:
			in.exit = err.Error()
		}
		in.mu.Unlock()
		close(in.done)
	}()
	return in, nil
}

// process is a component started as a process of this host.
type process struct {
	f      target.File
	values map[string]string
	cmd    *exec.Cmd
	done   chan struct{}
	log    logBuffer

	mu       sync.Mutex
	exit     string
	readBack string
}

func (p *process) Claim() attach.Endpoint { return attach.Endpoint{} }

func (p *process) Log() []byte { return p.log.Bytes() }

// Frames is an error: a collector has no frame link.
func (p *process) Frames() (net.Conn, error) {
	return nil, fmt.Errorf("%s: a collector has no build link: %w", p.f.Path, attach.ErrNoFrames)
}

func (p *process) Exit() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exit
}

// Stop interrupts the process, and kills it if it has not exited within
// StopGrace; where interrupting is not supported (Windows) it is killed at
// once. What it does on the way out is never asserted on.
func (p *process) Stop() error {
	select {
	case <-p.done:
	default:
		if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = p.cmd.Process.Kill()
		}
		select {
		case <-p.done:
		case <-time.After(StopGrace):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	}
	p.mu.Lock()
	dir := p.readBack
	p.readBack = ""
	p.mu.Unlock()
	if dir != "" {
		return os.RemoveAll(dir)
	}
	return nil
}

func (p *process) ReadBack(ctx context.Context) (string, error) {
	rb := p.f.Collector.ReadBack
	if rb == nil {
		return "", errors.New(p.f.Path + ": the target declares no read-back")
	}
	if rb.Dir != "" {
		dir, err := target.Expand(rb.Dir, p.values)
		if err != nil {
			return "", fmt.Errorf("%s: collector.read_back.dir: %w", p.f.Path, err)
		}
		return program(p.f, dir), nil
	}
	dir, err := os.MkdirTemp("", "bw-conformance-read-back-")
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.readBack = dir
	p.mu.Unlock()
	v := map[string]string{"out": p.values["out"], "dir": dir}
	argv, err := target.ExpandPlain(rb.Argv, v)
	if err != nil {
		return "", fmt.Errorf("%s: collector.read_back.argv: %w", p.f.Path, err)
	}
	if _, err := runCommand(ctx, p.f, "collector.read_back.argv", argv, &p.log); err != nil {
		return "", err
	}
	return dir, nil
}
