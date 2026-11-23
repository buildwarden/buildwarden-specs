package launch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/sandbox"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// ociClaim is the {claim} of an oci relay. Its container has no interface
// but loopback when it starts and gets its links from the sandbox after, so
// it serves its claim endpoint on every address, at the instance's port.
var ociClaim = netip.AddrPortFrom(netip.IPv4Unspecified(), sandbox.ClaimPort).String()

// sandboxRelay is the exec and oci launchers for a relay: each start is a
// fresh relay in an instance of the Linux sandbox (package sandbox), whose
// harness's namespace is the attachment's claim side and upstream, and whose
// newest instance's build environment namespace is its build side.
type sandboxRelay struct {
	f  target.File
	sb *sandbox.Sandbox
}

func newSandboxRelay(f target.File) (attach.Attachment, error) {
	if err := claimHeld(f); err != nil {
		return nil, err
	}
	sb, err := sandbox.New(f)
	if err != nil {
		return nil, err
	}
	if f.Launcher == "oci" {
		if err := runtimeRuns(f); err != nil {
			_ = sb.Close()
			return nil, err
		}
	}
	return &sandboxRelay{f: f, sb: sb}, nil
}

// runtimeRuns is an error, naming what is missing, unless the runtime an oci
// target names is installed and answers its version command: the harness
// looks for no other runtime, and an error here names the one the file does.
func runtimeRuns(f target.File) error {
	rt, err := exec.LookPath(f.OCI.Runtime)
	if err != nil {
		return fmt.Errorf("%s: oci.runtime %q: %w", f.Path, f.OCI.Runtime, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), CommandLimit)
	defer cancel()
	if out, err := exec.CommandContext(ctx, rt, "version").CombinedOutput(); err != nil {
		return fmt.Errorf("%s: oci.runtime %q cannot run containers on this host: %s version: %w\n%s", f.Path, f.OCI.Runtime, f.OCI.Runtime, err, out)
	}
	return nil
}

// claimHeld refuses a relay command line that does not hold {claim} outside
// an optional group: the launcher chooses the claim endpoint, so it must be
// able to tell the relay.
func claimHeld(f target.File) error {
	var argv target.Argv
	var env map[string]string
	key := "exec.argv"
	if f.Launcher == "oci" {
		argv, env, key = f.OCI.Args, f.OCI.Env, "oci.args"
	} else {
		argv, env = f.Exec.Argv, f.Exec.Env
	}
	if _, err := target.ExpandArgv(argv, map[string]string{"token": "t"}); err != nil {
		return nil
	}
	for _, val := range env {
		if strings.Contains(val, "{claim}") {
			return nil
		}
	}
	return fmt.Errorf("%s: %s holds no {claim} outside an optional group, and no variable of its env holds one: the sandbox chooses a relay's claim endpoint and gives it as {claim}", f.Path, key)
}

// Declared is what the file declares, with the relay's build address where
// the sandbox assigns it.
func (a *sandboxRelay) Declared() target.Declared {
	d := a.f.Declared()
	if d.AddressByLauncher {
		d.Address = sandbox.LauncherRelay.Addr().String()
	}
	return d
}

func (a *sandboxRelay) Network(s attach.Side) (attach.Network, error) {
	switch s {
	case attach.Claim, attach.Upstream:
		return a.sb.Harness(), nil
	case attach.Build:
		if a.f.Relay.Link == "frames" {
			return nil, fmt.Errorf("the relay's build link is a frame link, which each instance gives: %w", attach.ErrNoSide)
		}
		return a.sb.Build(), nil
	}
	return nil, fmt.Errorf("a relay target has no %s side: %w", s, attach.ErrNoSide)
}

func (a *sandboxRelay) Close() error { return a.sb.Close() }

// Start starts a fresh relay in a new instance of the sandbox, with a claim
// token of its own when its command line takes one and p does not ask for
// none, and returns once it serves its claim endpoint.
func (a *sandboxRelay) Start(ctx context.Context, p attach.Params) (attach.Instance, error) {
	sb, err := a.sb.Reserve()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.f.Path, err)
	}
	in := &relayInstance{f: a.f, sb: sb, done: make(chan struct{})}
	if err := in.start(ctx, p); err != nil {
		err = fmt.Errorf("%s: %w", a.f.Path, err)
		if serr := in.Stop(); serr != nil {
			err = errors.Join(err, serr)
		}
		if log := in.log.Bytes(); len(log) > 0 {
			err = fmt.Errorf("%w\nthe relay's output:\n%s", err, log)
		}
		return nil, err
	}
	return in, nil
}

// relayInstance is one relay started in the sandbox.
type relayInstance struct {
	f        target.File
	sb       *sandbox.Instance
	endpoint attach.Endpoint
	cmd      *exec.Cmd
	done     chan struct{}
	log      logBuffer
	// phases is an oci start's, recorded as it reaches each.
	phases ociPhases

	mu   sync.Mutex
	exit string
}

func (in *relayInstance) start(ctx context.Context, p attach.Params) error {
	d := in.f.Declared()
	if p.NoClaimToken && !d.NoClaimToken {
		return errors.New("the relay's command line requires {token}, so it cannot be started without a claim token")
	}
	if !p.NoClaimToken && d.ClaimToken {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		in.endpoint.Token = hex.EncodeToString(b)
	}
	in.endpoint.Address = in.sb.Claim().String()
	if in.f.Launcher == "oci" {
		return in.startOCI(ctx)
	}
	return in.startExec(ctx)
}

func (in *relayInstance) startExec(ctx context.Context) error {
	v := map[string]string{"claim": in.endpoint.Address, "token": in.endpoint.Token}
	argv, env, err := execCommand(in.f, v)
	if err != nil {
		return err
	}
	if err := in.sb.Build(0); err != nil {
		return err
	}
	// The process outlives the start's context: it is ended by Stop.
	in.cmd = exec.Command(program(in.f, argv[0]), argv[1:]...)
	in.cmd.Env = env
	in.cmd.Stdout, in.cmd.Stderr = &in.log, &in.log
	if err := in.sb.Start(in.cmd); err != nil {
		in.cmd = nil
		return fmt.Errorf("starting %q: %w", argv[0], err)
	}
	go in.wait()
	return in.sb.WaitListening(ctx, in.cmd.Process.Pid, in.done)
}

// execCommand is an exec relay's command line and environment for a start
// whose placeholders have the values v.
func execCommand(f target.File, v map[string]string) (argv, env []string, err error) {
	if argv, err = target.ExpandArgv(f.Exec.Argv, v); err != nil {
		return nil, nil, fmt.Errorf("exec.argv: %w", err)
	}
	if env, err = target.ExpandEnv(f.Exec.Env, v); err != nil {
		return nil, nil, fmt.Errorf("exec.env: %w", err)
	}
	for _, n := range f.Exec.PassEnv {
		if val, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+val)
		}
	}
	return argv, env, nil
}

// ociRun is the runtime's command line that runs an oci relay: in the
// foreground, so that its output is the relay's log; removed when it ends;
// with no network of the runtime's, since the sandbox gives it its links; with
// the image the runtime has, never one it pulls; with the sandbox's resolver
// configuration as its /etc/resolv.conf; and with each variable of env by
// name, its value in the runtime's own environment.
func ociRun(o *target.OCI, name, resolvConf string, env, args []string) []string {
	out := []string{"run", "--rm", "--name", name, "--network", "none", "--pull", "never",
		"--volume", resolvConf + ":/etc/resolv.conf:ro"}
	for _, e := range env {
		n, _, _ := strings.Cut(e, "=")
		out = append(out, "--env", n)
	}
	out = append(out, o.Image)
	return append(out, args...)
}

// ociInspect and ociRemove are the runtime's command lines that print a
// running container's process ID and that remove it.
func ociInspect(name string) []string { return []string{"inspect", "--format", "{{.State.Pid}}", name} }
func ociRemove(name string) []string  { return []string{"rm", "--force", name} }

// removeContainer removes the container name with the runtime rt. A container
// that is already being removed, or is gone, is not an error: a relay that
// exits by itself after a failed start, as the specification requires, has
// its container removed by the runtime's --rm while the run command has not
// yet returned, and the runtime then refuses a second removal.
func removeContainer(rt, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), CommandLimit)
	defer cancel()
	out, err := exec.CommandContext(ctx, rt, ociRemove(name)...).CombinedOutput()
	if err == nil {
		return nil
	}
	if msg := strings.ToLower(string(out)); strings.Contains(msg, "already in progress") || strings.Contains(msg, "no such container") {
		return nil
	}
	return fmt.Errorf("removing the container %s: %w: %s", name, err, out)
}

func (in *relayInstance) startOCI(ctx context.Context) error {
	o := in.f.OCI
	v := map[string]string{"claim": ociClaim, "token": in.endpoint.Token}
	args, err := target.ExpandArgv(o.Args, v)
	if err != nil {
		return fmt.Errorf("oci.args: %w", err)
	}
	env, err := target.ExpandEnv(o.Env, v)
	if err != nil {
		return fmt.Errorf("oci.env: %w", err)
	}
	rt, err := exec.LookPath(o.Runtime)
	if err != nil {
		return fmt.Errorf("oci.runtime %q: %w", o.Runtime, err)
	}
	name := in.sb.Names().Container
	in.cmd = exec.Command(rt, ociRun(o, name, in.sb.ResolvConf(), env, args)...)
	in.cmd.Env = append(os.Environ(), env...)
	in.cmd.Stdout, in.cmd.Stderr = &in.log, &in.log
	in.phases.run = time.Now()
	if err := in.cmd.Start(); err != nil {
		in.cmd = nil
		return fmt.Errorf("starting %s: %w", o.Runtime, err)
	}
	go in.wait()
	if err := in.awaitOCI(ctx, rt, name); err != nil {
		return fmt.Errorf("%w\nthe start's phases: %s\nthe runtime's state of %s: %s", err, in.phases, name, ociState(rt, name))
	}
	return nil
}

// awaitOCI waits for a started oci relay's container to be running, gives
// it its links, and waits for the relay to serve its claim endpoint.
func (in *relayInstance) awaitOCI(ctx context.Context, rt, name string) error {
	pid, err := in.containerPID(ctx, rt, name, containerLimit, &in.phases)
	if err != nil {
		return err
	}
	if err := in.sb.Build(pid); err != nil {
		return err
	}
	if err := in.sb.WaitListening(ctx, pid, in.done); err != nil {
		return err
	}
	in.phases.serving = time.Now()
	return nil
}

// containerLimit is how long the runtime has to start an oci relay's
// container: the bound of a target's own command, since the runtime is not
// the component under test. The relay's own bound, sandbox.StartLimit, runs
// from when its container is running.
const containerLimit = CommandLimit

// containerPID waits, for at most limit, for the container to be running
// and returns its process's ID. It records in ph when the runtime first
// returned the container and when the container had a process.
func (in *relayInstance) containerPID(ctx context.Context, rt, name string, limit time.Duration, ph *ociPhases) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	never := "the relay under test was never running"
	for {
		// Bounded by what is left of the wait.
		out, err := exec.CommandContext(ctx, rt, ociInspect(name)...).Output()
		if err == nil {
			if ph.listed.IsZero() {
				ph.listed = time.Now()
			}
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(out))); pid > 0 {
				ph.running = time.Now()
				return pid, nil
			}
		}
		select {
		case <-in.done:
			return 0, fmt.Errorf("%s run %s exited before the container was running: %s", in.f.OCI.Runtime, name, never)
		case <-ctx.Done():
			return 0, fmt.Errorf("the runtime %s did not start the container %s within %s: %s", in.f.OCI.Runtime, name, limit, never)
		case <-time.After(sandbox.StartPoll):
		}
	}
}

// ociPhases is when an oci start reached each of its phases, zero for one
// it did not reach: the runtime's run command started, the runtime's inspect
// first returned the container, the container had a process, and the relay
// served its claim endpoint. A failed start prints them, so that it says
// whether the time went to the runtime or to the relay.
type ociPhases struct {
	run, listed, running, serving time.Time
}

func (ph ociPhases) String() string {
	at := func(t time.Time) string {
		if t.IsZero() {
			return "not reached"
		}
		return "after " + t.Sub(ph.run).Round(time.Millisecond).String()
	}
	return fmt.Sprintf("run started at %s; inspect first returned the container %s; the container had a process %s; the claim endpoint answered %s",
		ph.run.UTC().Format("15:04:05.000"), at(ph.listed), at(ph.running), at(ph.serving))
}

// ociState is the runtime's inspect state of the container name, or what
// the runtime said when it could not give it, for a failed start's report.
func ociState(rt, name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), CommandLimit)
	defer cancel()
	out, err := exec.CommandContext(ctx, rt, "inspect", "--format", "{{json .State}}", name).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

func (in *relayInstance) wait() {
	err := in.cmd.Wait()
	in.mu.Lock()
	switch {
	case in.cmd.ProcessState != nil:
		in.exit = in.cmd.ProcessState.String()
	case err != nil:
		in.exit = err.Error()
	}
	in.mu.Unlock()
	close(in.done)
}

func (in *relayInstance) Claim() attach.Endpoint { return in.endpoint }
func (in *relayInstance) Log() []byte            { return in.log.Bytes() }

func (in *relayInstance) Exit() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.exit
}

// Frames is the harness's end of the instance's frame link.
func (in *relayInstance) Frames() (net.Conn, error) {
	if c, ok := in.sb.Frames(); ok {
		return c, nil
	}
	return nil, fmt.Errorf("%s: the relay's build link is ip: %w", in.f.Path, attach.ErrNoFrames)
}

func (in *relayInstance) ReadBack(context.Context) (string, error) {
	return "", errors.New(in.f.Path + ": a relay has no read-back")
}

// Stop ends the relay, and then removes the instance's links and namespaces.
// An exec relay is interrupted, and killed if it has not exited within
// StopGrace; an oci relay's container is removed by its runtime (one the
// runtime is already removing is left to it), and the runtime's process
// killed if it has not exited within StopGrace after.
func (in *relayInstance) Stop() error {
	var errs []error
	if in.cmd != nil {
		select {
		case <-in.done:
		default:
			if in.f.Launcher == "oci" {
				if err := removeContainer(in.cmd.Path, in.sb.Names().Container); err != nil {
					errs = append(errs, err)
				}
			} else if err := in.cmd.Process.Signal(os.Interrupt); err != nil {
				_ = in.cmd.Process.Kill()
			}
			select {
			case <-in.done:
			case <-time.After(StopGrace):
				_ = in.cmd.Process.Kill()
				<-in.done
			}
		}
	}
	errs = append(errs, in.sb.Close())
	return errors.Join(errs...)
}
