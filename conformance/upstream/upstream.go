// Package upstream is the harness's upstream world: what a relay under test
// reaches past itself. It has DNS resolvers on port 53, which a case can
// make silent or failing; origin servers on ports 80 and 443; and the
// certificate authority of the origins, which a claim carries in
// upstream_ca_certs with upstream_system_ca false (relay-claim).
//
// Every server is on an address in the documentation ranges, 192.0.2.0/24,
// 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737), because a host-mode relay
// refuses to dial loopback, private and link-local addresses. They listen
// on the attach.Network they are given: the in-memory network in a module's
// own tests, and the sandbox's upstream network under a launcher.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
)

// DocumentationRanges are the IPv4 ranges RFC 5737 reserves for
// documentation, in which every upstream server has its address.
var DocumentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

// CheckAddress is an error unless a is an IPv4 address in the documentation
// ranges.
func CheckAddress(a netip.Addr) error {
	for _, p := range DocumentationRanges {
		if p.Contains(a) {
			return nil
		}
	}
	return fmt.Errorf("upstream: %v is not in the documentation ranges (%v): a host-mode relay refuses to dial loopback, private and link-local addresses", a, DocumentationRanges)
}

// World is what to start: the resolvers' addresses, in the order a claim
// lists them in upstream_dns, and the origins, each of whose names every
// resolver answers with its address.
type World struct {
	Resolvers []netip.Addr
	Origins   []Origin
}

// Upstream is a started World.
type Upstream struct {
	CA        *CA
	Resolvers []*Resolver
	Origins   *Origins
}

// Start starts w on n with a fresh CA.
func Start(ctx context.Context, n attach.Network, w World) (*Upstream, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	zone := map[string][]netip.Addr{}
	for _, o := range w.Origins {
		zone[o.Name] = append(zone[o.Name], o.Addr)
	}
	u := &Upstream{CA: ca}
	for _, a := range w.Resolvers {
		r, err := StartResolver(ctx, n, a, zone)
		if err != nil {
			_ = u.Close()
			return nil, err
		}
		u.Resolvers = append(u.Resolvers, r)
	}
	if u.Origins, err = StartOrigins(ctx, n, ca, w.Origins); err != nil {
		_ = u.Close()
		return nil, err
	}
	return u, nil
}

// DNS is the resolvers' addresses in order: a claim's upstream_dns.
func (u *Upstream) DNS() []string {
	var s []string
	for _, r := range u.Resolvers {
		s = append(s, r.Address().String())
	}
	return s
}

// Close stops every server.
func (u *Upstream) Close() error {
	var errs []error
	for _, r := range u.Resolvers {
		errs = append(errs, r.Close())
	}
	if u.Origins != nil {
		errs = append(errs, u.Origins.Close())
	}
	return errors.Join(errs...)
}
