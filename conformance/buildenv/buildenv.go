// Package buildenv is the harness's build environment: the client role of
// relay-guest-api, which a relay serves on its build link. It is what a
// relay case uses to reach the relay as a build would, on either kind of
// link a relay target declares:
//
//   - On "frames", a socket that carries one Ethernet frame per datagram, it
//     brings the harness's own network stack (package netstack). It takes
//     its lease from the relay's DHCP first (package dhcp), makes its stack
//     with the address, the router and the DNS server the lease gave, and
//     connects to the address DNS returns for a name, which the relay
//     captures (GUEST-6).
//   - On "ip", a kernel interface or the in-memory network, it is at an
//     address its launcher gave it and connects to the relay's own address
//     for every name, with the name in Host and in TLS's server name, since
//     bringing other addresses onto the relay's ports is the driver's
//     (relay-guest-api, Scope and roles).
//
// On both it asks DNS of the relay's address, and before its first request
// it waits for the relay to serve: Ready polls GET /health on port 8300
// every ReadyPoll for at most ReadyWithin (Known divergences, D19, of
// relay-claim and relay-guest-api: vm and container mode answer the claim
// before their ports are bound).
package buildenv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
)

// The readiness poll's timings and the control plane's port. They are
// constants of a harness release.
const (
	ReadyPoll   = 100 * time.Millisecond
	ReadyWithin = 10 * time.Second
	ControlPort = 8300
	// DNSTimeout bounds one DNS exchange with the relay.
	DNSTimeout = 10 * time.Second
)

// The kinds of build link, as a relay target names them.
const (
	Frames = "frames"
	IP     = "ip"
)

// Config is what a build environment is started on.
type Config struct {
	// Link is Frames or IP.
	Link string

	// Frames is the build environment's end of a frame link, which it owns
	// from Start on, and MAC its Ethernet address there.
	Frames net.Conn
	MAC    net.HardwareAddr

	// Network is the build environment's network on an IP link, and Relay
	// the relay's address on it.
	Network attach.Network
	Relay   netip.Addr
}

// Env is a started build environment.
type Env struct {
	link    string
	network attach.Network
	relay   netip.Addr
	dns     netip.Addr
	lease   *dhcp.Lease
	stack   *netstack.Stack
}

// Start starts a build environment on cfg's link. On Frames it takes its
// lease first, and fails if the lease gives no router or no DNS server.
func Start(ctx context.Context, cfg Config) (*Env, error) {
	switch cfg.Link {
	case Frames:
		if cfg.Frames == nil {
			return nil, errors.New("buildenv: a frames link needs its frame socket")
		}
		l, err := dhcp.LeaseFrames(ctx, cfg.Frames, cfg.MAC)
		if err != nil {
			return nil, fmt.Errorf("buildenv: the lease: %w", err)
		}
		if len(l.Router) == 0 {
			return nil, fmt.Errorf("buildenv: the lease from %s gives no router (option 3)", l.Server)
		}
		if len(l.DNS) == 0 {
			return nil, fmt.Errorf("buildenv: the lease from %s gives no DNS server (option 6)", l.Server)
		}
		st, err := netstack.New(cfg.Frames, netstack.Config{MAC: cfg.MAC, Address: l.Address, Gateway: l.Router[0]})
		if err != nil {
			return nil, fmt.Errorf("buildenv: the stack for the lease %s: %w", l.Address, err)
		}
		return &Env{link: Frames, network: st.Network(), relay: l.Server, dns: l.DNS[0], lease: &l, stack: st}, nil
	case IP:
		if cfg.Network == nil || !cfg.Relay.Is4() {
			return nil, errors.New("buildenv: an ip link needs its network and the relay's IPv4 address")
		}
		return &Env{link: IP, network: cfg.Network, relay: cfg.Relay, dns: cfg.Relay}, nil
	}
	return nil, fmt.Errorf("buildenv: link %q is neither %q nor %q", cfg.Link, Frames, IP)
}

// Link is the kind of the build link.
func (e *Env) Link() string { return e.link }

// Relay is the relay's address: on Frames the lease's server identifier,
// on IP the one given.
func (e *Env) Relay() netip.Addr { return e.relay }

// DNSServer is the address the build environment asks DNS of: on Frames
// the lease's first DNS server, on IP the relay's address.
func (e *Env) DNSServer() netip.Addr { return e.dns }

// Lease is the lease taken on a Frames link, and false on IP.
func (e *Env) Lease() (dhcp.Lease, bool) {
	if e.lease == nil {
		return dhcp.Lease{}, false
	}
	return *e.lease, true
}

// Network is where the build environment's sockets are: its stack on
// Frames, the given network on IP. A case that needs a socket the methods
// below do not give takes it here.
func (e *Env) Network() attach.Network { return e.network }

// Close stops the build environment; on Frames it closes the frame socket.
func (e *Env) Close() error {
	if e.stack != nil {
		return e.stack.Close()
	}
	return nil
}

// Ready polls GET /health on the relay's port 8300 every ReadyPoll until it
// is answered 200, for at most ReadyWithin. It asserts nothing about the
// answer's body: that is a case's.
func (e *Env) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ReadyWithin)
	defer cancel()
	c := &http.Client{Transport: &http.Transport{
		DialContext:       e.dialRelay,
		DisableKeepAlives: true,
	}}
	url := "http://" + net.JoinHostPort(e.relay.String(), strconv.Itoa(ControlPort)) + "/health"
	tick := time.NewTicker(ReadyPoll)
	defer tick.Stop()
	var last error
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("answered %s", resp.Status)
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("buildenv: GET %s was not answered 200 in %d attempts within %s: %w", url, attempt, ReadyWithin, last)
		case <-tick.C:
		}
	}
}

func (e *Env) dialRelay(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return e.network.Dial(ctx, network, net.JoinHostPort(e.relay.String(), port))
}

// Exchange sends q to the DNS server over transport, "udp" or "tcp", and
// returns its answer.
func (e *Env) Exchange(ctx context.Context, transport string, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, DNSTimeout)
	defer cancel()
	c, err := e.network.Dial(ctx, transport, net.JoinHostPort(e.dns.String(), "53"))
	if err != nil {
		return nil, fmt.Errorf("buildenv: DNS over %s to %s: %w", transport, e.dns, err)
	}
	defer c.Close()
	cl := &dns.Client{Net: transport, Timeout: DNSTimeout}
	r, _, err := cl.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: c})
	if err != nil {
		return nil, fmt.Errorf("buildenv: DNS over %s to %s: %w", transport, e.dns, err)
	}
	return r, nil
}

// Resolve asks the DNS server, over UDP, for name's A records and returns
// their addresses. An answer that is not NOERROR is an error that names its
// response code.
func (e *Env) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, err := e.Exchange(ctx, "udp", q)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("buildenv: DNS for %s answered %s", name, dns.RcodeToString[r.Rcode])
	}
	var as []netip.Addr
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			if addr, ok := netip.AddrFromSlice(a.A.To4()); ok {
				as = append(as, addr)
			}
		}
	}
	if len(as) == 0 {
		return nil, fmt.Errorf("buildenv: DNS for %s answered no address", name)
	}
	return as, nil
}

// Dial connects to address, "host:port", as a build does on this link: on
// Frames to the host if it is an IP address and otherwise to the first
// address DNS gives for it; on IP to the relay's address at the port,
// whatever the host.
func (e *Env) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if e.link == IP {
		return e.dialRelay(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return e.network.Dial(ctx, network, address)
	}
	as, err := e.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return e.network.Dial(ctx, network, net.JoinHostPort(as[0].String(), port))
}

// Transport is an HTTP/1.1 transport that connects through Dial and
// trusts roots for TLS, with the URL's host in Host and as the TLS server
// name. It uses no proxy and keeps no connection between requests, so that
// each request is its own connection to the relay.
func (e *Env) Transport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		DialContext:       e.Dial,
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
}

// Client is an HTTP client over Transport(roots) that follows no redirect,
// so that a case sees each response the relay gave.
func (e *Env) Client(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: e.Transport(roots),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
