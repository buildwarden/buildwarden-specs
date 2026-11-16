package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// Limits of the sandbox. They are constants of a harness release.
const (
	// StartLimit is how long a started relay has to serve its claim
	// endpoint, and an oci relay's container to be running.
	StartLimit = 30 * time.Second
	// StartPoll is how often a start looks again.
	StartPoll = 20 * time.Millisecond
)

// limitedBroadcast is 255.255.255.255, as a route's destination.
var limitedBroadcast = netip.MustParsePrefix("255.255.255.255/32")

// Sandbox is the namespaces and links of one attachment's relay target.
type Sandbox struct {
	link Link
	dir  string
	ns   *os.File
	book book[*Instance]
}

// New builds the sandbox for the relay target f: its build link, and the
// harness's namespace, after the probe that says whether this process may.
func New(f target.File) (*Sandbox, error) {
	link, err := BuildLink(f.Relay)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	if f.Launcher == "oci" && link.Kind != "ip" {
		return nil, fmt.Errorf("%s: an oci relay's relay.link is \"ip\": the sandbox cannot hand a container one end of a socket pair", f.Path)
	}
	if err := hostProbe().check(f.Launcher); err != nil {
		return nil, err
	}
	return newSandbox(link)
}

func hostProbe() Probe {
	return Probe{
		Euid:     os.Geteuid(),
		InUserNS: os.Getenv(UserNSEnv) != "",
		NetNS: func() error {
			ns, err := newNetNS()
			if ns != nil {
				_ = ns.Close()
			}
			return err
		},
	}
}

func newSandbox(link Link) (*Sandbox, error) {
	dir, err := os.MkdirTemp("", "bw-conformance-sandbox-")
	if err != nil {
		return nil, err
	}
	s := &Sandbox{link: link, dir: dir}
	if err := os.WriteFile(s.ResolvConf(), []byte(ResolvConf), 0o644); err != nil {
		_ = s.Close()
		return nil, err
	}
	if s.ns, err = newNetNS(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("the harness's network namespace: %w", err)
	}
	if err := inNS(s.ns, func() error {
		if err := linkUp("lo"); err != nil {
			return err
		}
		for _, r := range HarnessRanges {
			if err := addLocalRoute(r); err != nil {
				return fmt.Errorf("making %s local: %w", r, err)
			}
		}
		return nil
	}); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("the harness's network namespace: %w", err)
	}
	return s, nil
}

// ResolvConf is the file a relay is given as its /etc/resolv.conf.
func (s *Sandbox) ResolvConf() string { return filepath.Join(s.dir, "resolv.conf") }

// Harness is the harness's network: its claim side and its upstream, at
// UpstreamHarness.
func (s *Sandbox) Harness() attach.Network { return nsNetwork{ns: s.ns, addr: UpstreamHarness} }

// Build is the build environment's network on an "ip" link: that of the
// newest open instance, at the link's harness address.
func (s *Sandbox) Build() attach.Network { return buildNetwork{s} }

// Close removes the harness's namespace and the resolver configuration;
// every instance has been closed first.
func (s *Sandbox) Close() error {
	var err error
	if s.ns != nil {
		err = s.ns.Close()
	}
	return errors.Join(err, os.RemoveAll(s.dir))
}

// Instance is the namespaces and links of one start of the relay.
type Instance struct {
	s           *Sandbox
	slot        int
	names       Names
	relayNS     *os.File
	buildNS     *os.File
	relayFrames *os.File
	frames      net.Conn
}

// Reserve reserves an instance's slot of the address plan and its names.
func (s *Sandbox) Reserve() (*Instance, error) {
	slot, id, err := s.book.take()
	if err != nil {
		return nil, err
	}
	return &Instance{s: s, slot: slot, names: NamesFor(os.Getpid(), id)}, nil
}

// ResolvConf is the file the instance's relay is given as its
// /etc/resolv.conf.
func (in *Instance) ResolvConf() string { return in.s.ResolvConf() }

// Names are the instance's names.
func (in *Instance) Names() Names { return in.names }

// Claim is the instance's claim endpoint.
func (in *Instance) Claim() netip.AddrPort { return Claim(in.slot) }

// Build makes the instance's namespaces and links. With pid 0 the relay's
// network namespace is a new one, which Start starts the relay in; otherwise
// it is that of the process pid, an oci relay's container.
func (in *Instance) Build(pid int) error {
	var err error
	if pid == 0 {
		in.relayNS, err = newNetNS()
	} else {
		in.relayNS, err = os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	}
	if err != nil {
		return fmt.Errorf("the relay's network namespace: %w", err)
	}
	if err := in.links(); err != nil {
		return err
	}
	in.s.book.add(in)
	return nil
}

// links creates the instance's links, the build link's before the
// upstream's (see the package comment for why the order matters).
func (in *Instance) links() error {
	n := in.names
	link := in.s.link
	if err := inNS(in.relayNS, func() error { return linkUp("lo") }); err != nil {
		return fmt.Errorf("the relay's loopback: %w", err)
	}
	switch link.Kind {
	case "frames":
		var err error
		if in.relayFrames, in.frames, err = socketPair(); err != nil {
			return fmt.Errorf("the frame link: %w", err)
		}
	case "ip":
		var err error
		if in.buildNS, err = newNetNS(); err != nil {
			return fmt.Errorf("the build environment's network namespace: %w", err)
		}
		if err := inNS(in.relayNS, func() error { return addVeth(n.Build, n.Build, in.buildNS) }); err != nil {
			return fmt.Errorf("the build link %s: %w", n.Build, err)
		}
		if err := inNS(in.buildNS, func() error {
			if err := up(n.Build, link.Harness, "lo"); err != nil {
				return err
			}
			// A build environment that takes a lease broadcasts before
			// it has an address of the relay's giving.
			return addLinkRoute(n.Build, limitedBroadcast)
		}); err != nil {
			return fmt.Errorf("the build link %s, the build environment's end: %w", n.Build, err)
		}
		if err := inNS(in.relayNS, func() error { return up(n.Build, link.Relay) }); err != nil {
			return fmt.Errorf("the build link %s, the relay's end: %w", n.Build, err)
		}
	}
	relay, harness := Upstream(in.slot)
	if err := inNS(in.relayNS, func() error { return addVeth(n.Upstream, n.Upstream, in.s.ns) }); err != nil {
		return fmt.Errorf("the upstream link %s: %w", n.Upstream, err)
	}
	if err := inNS(in.s.ns, func() error { return up(n.Upstream, harness) }); err != nil {
		return fmt.Errorf("the upstream link %s, the harness's end: %w", n.Upstream, err)
	}
	if err := inNS(in.relayNS, func() error {
		if err := up(n.Upstream, relay); err != nil {
			return err
		}
		return addDefaultRoute(harness.Addr())
	}); err != nil {
		return fmt.Errorf("the upstream link %s, the relay's end: %w", n.Upstream, err)
	}
	return nil
}

// up brings each interface named up, giving the first the address addr when
// addr is valid.
func up(name string, addr netip.Prefix, others ...string) error {
	if addr.IsValid() {
		if err := addAddr(name, addr); err != nil {
			return err
		}
	}
	for _, n := range append([]string{name}, others...) {
		if err := linkUp(n); err != nil {
			return err
		}
	}
	return nil
}

// Start starts cmd, an exec relay, in the instance's network namespace and
// in a mount namespace of its own (see the package comment). On a frame link
// the relay's end of the socket pair is its file descriptor 3.
func (in *Instance) Start(cmd *exec.Cmd) error {
	if in.relayFrames != nil {
		cmd.ExtraFiles = []*os.File{in.relayFrames}
	}
	return startIn(in.relayNS, in.s.ResolvConf(), cmd)
}

// Frames is the harness's end of a frame link.
func (in *Instance) Frames() (net.Conn, bool) { return in.frames, in.frames != nil }

// WaitListening waits until process pid listens on the instance's claim
// endpoint, for at most StartLimit, or until exited is closed.
func (in *Instance) WaitListening(ctx context.Context, pid int, exited <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(ctx, StartLimit)
	defer cancel()
	c := in.Claim()
	for {
		var tables strings.Builder
		for _, f := range []string{"tcp", "tcp6"} {
			b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, f))
			tables.Write(b)
		}
		if listening(tables.String(), c.Addr(), c.Port()) {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("the relay exited before it served its claim endpoint %s", c)
		case <-ctx.Done():
			return fmt.Errorf("the relay did not serve its claim endpoint %s within %s", c, StartLimit)
		case <-time.After(StartPoll):
		}
	}
}

// Close removes the instance's links and namespaces; the relay has ended.
// The harness's end of the upstream link is deleted, with its pair, before
// the slot is freed, so the next instance in the slot finds its addresses
// free.
func (in *Instance) Close() error {
	var errs []error
	if in.relayNS != nil {
		errs = append(errs, inNS(in.s.ns, func() error { return delLink(in.names.Upstream) }))
	}
	if in.frames != nil {
		errs = append(errs, in.frames.Close())
	}
	for _, f := range []*os.File{in.relayFrames, in.buildNS, in.relayNS} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	in.s.book.release(in, in.slot)
	return errors.Join(errs...)
}

// nsNetwork is a network namespace as an attach.Network: each listener and
// connection is made on an OS thread in the namespace, and keeps to it.
type nsNetwork struct {
	ns   *os.File
	addr netip.Addr
}

func (n nsNetwork) Address() netip.Addr { return n.addr }

func (n nsNetwork) Listen(ctx context.Context, network, address string) (ln net.Listener, err error) {
	err = inNS(n.ns, func() (err error) {
		var lc net.ListenConfig
		ln, err = lc.Listen(ctx, network, address)
		return err
	})
	return ln, err
}

func (n nsNetwork) ListenPacket(ctx context.Context, network, address string) (pc net.PacketConn, err error) {
	err = inNS(n.ns, func() (err error) {
		var lc net.ListenConfig
		pc, err = lc.ListenPacket(ctx, network, address)
		return err
	})
	return pc, err
}

func (n nsNetwork) Dial(ctx context.Context, network, address string) (c net.Conn, err error) {
	err = inNS(n.ns, func() (err error) {
		var d net.Dialer
		c, err = d.DialContext(ctx, network, address)
		return err
	})
	return c, err
}

// buildNetwork is the newest open instance's build environment network.
type buildNetwork struct{ s *Sandbox }

func (b buildNetwork) Address() netip.Addr { return b.s.link.Harness.Addr() }

func (b buildNetwork) net() (nsNetwork, error) {
	in, ok := b.s.book.newest()
	if !ok || in.buildNS == nil {
		return nsNetwork{}, errors.New("no instance with a build link is open")
	}
	return nsNetwork{ns: in.buildNS, addr: b.Address()}, nil
}

func (b buildNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	n, err := b.net()
	if err != nil {
		return nil, err
	}
	return n.Listen(ctx, network, address)
}

func (b buildNetwork) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	n, err := b.net()
	if err != nil {
		return nil, err
	}
	return n.ListenPacket(ctx, network, address)
}

func (b buildNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n, err := b.net()
	if err != nil {
		return nil, err
	}
	return n.Dial(ctx, network, address)
}
