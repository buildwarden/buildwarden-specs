package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// externalRelay is the external launcher for a relay: one that is already
// running at the claim endpoint the file names, or a fresh one for each
// start, whose endpoint the file's request command prints. The harness
// reaches it, and it reaches the harness's upstream servers, on the host's
// network.
type externalRelay struct {
	f        target.File
	upstream netip.Addr
}

func (a *externalRelay) Declared() target.Declared { return a.f.Declared() }

func (a *externalRelay) Network(s attach.Side) (attach.Network, error) {
	switch s {
	case attach.Claim, attach.Build:
		return attach.Host(netip.Addr{}), nil
	case attach.Upstream:
		return attach.Host(a.upstream), nil
	}
	return nil, fmt.Errorf("a relay target has no %s side: %w", s, attach.ErrNoSide)
}

func (a *externalRelay) Close() error { return nil }

func (a *externalRelay) Start(ctx context.Context, p attach.Params) (attach.Instance, error) {
	e := a.f.External
	if p.NoClaimToken && e.Token != "" {
		return nil, fmt.Errorf("%s: the external relay has a claim token, external.token, and cannot be started without one", a.f.Path)
	}
	in := &external{f: a.f, endpoint: attach.Endpoint{Address: e.Claim, Token: e.Token}}
	if e.Claim != "" {
		return in, nil
	}
	out, err := runCommand(ctx, a.f, "external.request", e.Request, &in.log)
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(string(out), "\n")
	line = strings.TrimSpace(line)
	if !isEndpoint(line) {
		return nil, fmt.Errorf("%s: external.request printed %q as its first line, which is not a claim endpoint, host:port", a.f.Path, line)
	}
	in.endpoint.Address = line
	if _, rest, _ := bytes.Cut(out, []byte("\n")); len(bytes.TrimSpace(rest)) > 0 {
		fmt.Fprintf(&in.log, "external.request printed after the endpoint:\n%s", rest)
	}
	return in, nil
}

// isEndpoint reports whether s is host:port with a numeric port and a host
// that holds no space.
func isEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || strings.ContainsAny(host, " \t") {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}

// external is a relay that the harness did not start and does not stop.
type external struct {
	f        target.File
	endpoint attach.Endpoint
	log      logBuffer
}

func (e *external) Claim() attach.Endpoint { return e.endpoint }
func (e *external) Log() []byte            { return e.log.Bytes() }
func (e *external) Exit() string           { return "" }
func (e *external) Stop() error            { return nil }

// Frames is an error: an external relay's link is "ip".
func (e *external) Frames() (net.Conn, error) {
	return nil, fmt.Errorf("%s: an external relay's link is ip: %w", e.f.Path, attach.ErrNoFrames)
}

func (e *external) ReadBack(context.Context) (string, error) {
	return "", errors.New(e.f.Path + ": a relay has no read-back")
}
