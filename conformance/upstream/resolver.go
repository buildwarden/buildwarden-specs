package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// TTL is the time to live of every record the resolver answers with.
const TTL = 60

// Mode is how a resolver treats the queries it is sent.
type Mode int

const (
	// Answering answers each query from the resolver's zone.
	Answering Mode = iota
	// Silent reads each query and answers none, so a client waits out its
	// own time limit.
	Silent
	// Failing has the resolver's port refuse: its sockets are closed, so a
	// query to it is refused at once, as by a host that has no resolver
	// running (on a kernel network, an ICMP port unreachable for UDP and a
	// reset for TCP).
	Failing
)

func (m Mode) String() string {
	switch m {
	case Answering:
		return "answering"
	case Silent:
		return "silent"
	case Failing:
		return "failing"
	}
	return fmt.Sprintf("mode %d", int(m))
}

// Query is one query a resolver was sent, in the order they came.
type Query struct {
	// Seq is the query's place in the order, from 1.
	Seq int
	At  time.Time
	// Transport is "udp" or "tcp".
	Transport string
	From      string
	ID        uint16
	// Name is the queried name, absolute, as it was sent.
	Name  string
	Type  uint16
	Class uint16
	// Answered is whether the resolver answered it.
	Answered bool
}

// Resolver is an upstream DNS resolver on port 53 of one address, over UDP
// and TCP. Its zone maps names to addresses: a query of type A for a name
// in the zone is answered with one A record for each IPv4 address, one of
// type AAAA with one AAAA record for each IPv6 address, one of another type
// with no records, and a query for a name not in the zone with NXDOMAIN. A name in the zone matches a query whatever its case.
type Resolver struct {
	net  attach.Network
	addr netip.Addr

	mu      sync.Mutex
	zone    map[string][]netip.Addr
	mode    Mode
	queries []Query
	servers []*dns.Server
}

// StartResolver starts a resolver at addr:53 on n, answering from zone.
// addr must be in the documentation ranges (CheckAddress).
func StartResolver(ctx context.Context, n attach.Network, addr netip.Addr, zone map[string][]netip.Addr) (*Resolver, error) {
	if err := CheckAddress(addr); err != nil {
		return nil, err
	}
	r := &Resolver{net: n, addr: addr, zone: map[string][]netip.Addr{}}
	for name, as := range zone {
		r.zone[dns.CanonicalName(name)] = append([]netip.Addr(nil), as...)
	}
	if err := r.serve(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Address is the resolver's address; it listens on port 53 of it.
func (r *Resolver) Address() netip.Addr { return r.addr }

// Set puts name in the zone with addrs, or takes it out for none.
func (r *Resolver) Set(name string, addrs ...netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(addrs) == 0 {
		delete(r.zone, dns.CanonicalName(name))
		return
	}
	r.zone[dns.CanonicalName(name)] = append([]netip.Addr(nil), addrs...)
}

// Mode is the resolver's mode.
func (r *Resolver) Mode() Mode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode
}

// SetMode puts the resolver in mode m. Into Failing it closes its sockets;
// out of Failing it binds them again.
func (r *Resolver) SetMode(ctx context.Context, m Mode) error {
	r.mu.Lock()
	was := r.mode
	r.mode = m
	r.mu.Unlock()
	switch {
	case m == Failing && was != Failing:
		r.shutdown()
	case m != Failing && was == Failing:
		return r.serve(ctx)
	}
	return nil
}

// Queries returns the queries the resolver was sent, in order. A query to
// a Failing resolver never reaches it and is not among them.
func (r *Resolver) Queries() []Query {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Query(nil), r.queries...)
}

// Close stops the resolver.
func (r *Resolver) Close() error {
	r.shutdown()
	return nil
}

func (r *Resolver) serve(ctx context.Context) error {
	address := net.JoinHostPort(r.addr.String(), "53")
	pc, err := r.net.ListenPacket(ctx, "udp", address)
	if err != nil {
		return fmt.Errorf("upstream: the resolver on %s: %w", address, err)
	}
	ln, err := r.net.Listen(ctx, "tcp", address)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("upstream: the resolver on %s: %w", address, err)
	}
	servers := []*dns.Server{
		{PacketConn: pc, Handler: r.handler("udp")},
		{Listener: ln, Handler: r.handler("tcp")},
	}
	for _, s := range servers {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		<-started
	}
	r.mu.Lock()
	r.servers = servers
	r.mu.Unlock()
	return nil
}

func (r *Resolver) shutdown() {
	r.mu.Lock()
	servers := r.servers
	r.servers = nil
	r.mu.Unlock()
	for _, s := range servers {
		_ = s.Shutdown()
	}
}

func (r *Resolver) handler(transport string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, q *dns.Msg) {
		r.mu.Lock()
		rec := Query{Seq: len(r.queries) + 1, At: time.Now(), Transport: transport, From: w.RemoteAddr().String(), ID: q.Id}
		if len(q.Question) > 0 {
			rec.Name, rec.Type, rec.Class = q.Question[0].Name, q.Question[0].Qtype, q.Question[0].Qclass
		}
		answer := r.mode == Answering
		rec.Answered = answer
		r.queries = append(r.queries, rec)
		var addrs []netip.Addr
		found := false
		if len(q.Question) > 0 {
			addrs, found = r.zone[strings.ToLower(dns.CanonicalName(q.Question[0].Name))]
		}
		r.mu.Unlock()
		if !answer {
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.RecursionAvailable = true
		switch {
		case len(q.Question) != 1:
			m.Rcode = dns.RcodeFormatError
		case !found:
			m.Rcode = dns.RcodeNameError
		case q.Question[0].Qclass != dns.ClassINET:
		case q.Question[0].Qtype == dns.TypeA:
			// A name's IPv4 addresses in A records, and its IPv6 ones in
			// AAAA records only.
			for _, a := range addrs {
				if a.Unmap().Is4() {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: TTL},
						A:   a.Unmap().AsSlice(),
					})
				}
			}
		case q.Question[0].Qtype == dns.TypeAAAA:
			for _, a := range addrs {
				if !a.Unmap().Is4() {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: TTL},
						AAAA: a.AsSlice(),
					})
				}
			}
		}
		_ = w.WriteMsg(m)
	}
}
