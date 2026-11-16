package cases

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/buildwarden/buildwarden-specs/conformance/buildenv"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// failover is the least time the relay may give a resolver that has not
// answered before it asks the next (GUEST-15's 5 s), less the slack of the
// harness's own measure: the silent resolver's query is timed as it
// arrives, after the relay sent it.
const failover = 4500 * time.Millisecond

// transports are the DNS transports the relay serves on its build link:
// UDP, and on a kernel interface TCP as well (GUEST-2, GUEST-12; Known
// divergences, D15, for a frame link).
func transports(link string) []string {
	if link == buildenv.IP {
		return []string{"udp", "tcp"}
	}
	return []string{"udp"}
}

// question is a query for name of type qt with the ID id.
func question(name string, qt uint16, id uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	q.Id = id
	return q
}

// askedFor is the queries for name each resolver of the world received.
func askedFor(up *upstream.Upstream, name string) [][]upstream.Query {
	var out [][]upstream.Query
	for _, r := range up.Resolvers {
		var qs []upstream.Query
		for _, q := range r.Queries() {
			if strings.EqualFold(q.Name, dns.Fqdn(name)) {
				qs = append(qs, q)
			}
		}
		out = append(out, qs)
	}
	return out
}

// dnsServed: the relay answers DNS at port 53 of its own address over UDP,
// and on a kernel interface over TCP as well.
var dnsServed = runner.Case{
	Name:  "the relay serves DNS on port 53 of its address over UDP, and on a kernel interface over TCP as well",
	Cites: []string{"GUEST-12"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		if env.DNSServer() != r.relayAddr() {
			t.Errorf("the build environment asks DNS of %s, and the relay's address is %s", env.DNSServer(), r.relayAddr())
		}
		for i, tr := range transports(r.d.Link) {
			q := question("artifacts", dns.TypeA, uint16(0x1200+i))
			ans, err := env.Exchange(t.Context(), tr, q)
			if err != nil {
				t.Errorf("a query over %s to %s:53: %v", tr, env.DNSServer(), err)
				continue
			}
			if !ans.Response || ans.Id != q.Id {
				t.Errorf("the reply over %s is not a response to the query: response %v, ID %#x for %#x", tr, ans.Response, ans.Id, q.Id)
			}
		}
	},
}

// reservedA: queries of type A for artifacts and cwd are answered by the
// relay itself with one A record of its address and TTL 0, over each
// transport it serves, and are not forwarded.
var reservedA = runner.Case{
	Name:  "a query of type A for artifacts or cwd is answered with one A record of the relay's address, with TTL 0",
	Cites: []string{"GUEST-13"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		relay := r.relayAddr()
		id := uint16(0x1300)
		for _, tr := range transports(r.d.Link) {
			for _, name := range []string{"artifacts", "cwd"} {
				id++
				q := question(name, dns.TypeA, id)
				ans, err := env.Exchange(t.Context(), tr, q)
				if err != nil {
					t.Errorf("A %s over %s: %v", name, tr, err)
					continue
				}
				what := "the answer to A " + name + " over " + tr
				if ans.Id != q.Id || ans.Rcode != dns.RcodeSuccess {
					t.Errorf("%s has ID %#x and code %s, want %#x and NOERROR", what, ans.Id, dns.RcodeToString[ans.Rcode], q.Id)
				}
				if len(ans.Answer) != 1 {
					t.Errorf("%s has %d answer records, want 1: %v", what, len(ans.Answer), ans.Answer)
					continue
				}
				a, ok := ans.Answer[0].(*dns.A)
				if !ok {
					t.Errorf("%s is %v, not an A record", what, ans.Answer[0])
					continue
				}
				if !strings.EqualFold(a.Hdr.Name, dns.Fqdn(name)) || a.Hdr.Class != dns.ClassINET || a.Hdr.Ttl != 0 {
					t.Errorf("%s is for %q of class %d with TTL %d, want %q, IN, 0", what, a.Hdr.Name, a.Hdr.Class, a.Hdr.Ttl, dns.Fqdn(name))
				}
				if got, _ := netip.AddrFromSlice(a.A.To4()); got != relay {
					t.Errorf("%s holds %s, want the relay's address %s", what, a.A, relay)
				}
			}
		}
		for _, name := range []string{"artifacts", "cwd"} {
			for i, qs := range askedFor(r.up, name) {
				if len(qs) > 0 {
					t.Errorf("the resolver %s was asked for %s: the relay forwarded a reserved name", r.up.Resolvers[i].Address(), name)
				}
			}
		}
	},
}

// reservedOther: queries of other types for artifacts and cwd are answered
// by the relay itself with NOERROR and no records.
var reservedOther = runner.Case{
	Name:  "a query of another type for artifacts or cwd is answered with NOERROR and no records",
	Cites: []string{"GUEST-14"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		id := uint16(0x1400)
		for _, tr := range transports(r.d.Link) {
			for _, name := range []string{"artifacts", "cwd"} {
				for _, qt := range []uint16{dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeCNAME, dns.TypeHTTPS} {
					id++
					q := question(name, qt, id)
					what := dns.TypeToString[qt] + " " + name + " over " + tr
					ans, err := env.Exchange(t.Context(), tr, q)
					if err != nil {
						t.Errorf("%s: %v", what, err)
						continue
					}
					if ans.Id != q.Id || ans.Rcode != dns.RcodeSuccess || len(ans.Answer) != 0 {
						t.Errorf("the answer to %s has ID %#x, code %s and %d answer records; want %#x, NOERROR and none", what, ans.Id, dns.RcodeToString[ans.Rcode], len(ans.Answer), q.Id)
					}
				}
			}
		}
		for _, name := range []string{"artifacts", "cwd"} {
			for i, qs := range askedFor(r.up, name) {
				if len(qs) > 0 {
					t.Errorf("the resolver %s was asked for %s: the relay forwarded a reserved name", r.up.Resolvers[i].Address(), name)
				}
			}
		}
	},
}

// resolveVia sends one query for name of type qt from the build and
// returns the reply, failing the case when there is none.
func resolveVia(t *runner.T, env *buildenv.Env, name string, qt uint16, id uint16) *dns.Msg {
	q := question(name, qt, id)
	ans, err := env.Exchange(t.Context(), "udp", q)
	if err != nil {
		t.Fatalf("%s %s from the build: %v", dns.TypeToString[qt], name, err)
	}
	if ans.Id != q.Id {
		t.Errorf("the reply to %s %s has ID %#x, want the build's %#x", dns.TypeToString[qt], name, ans.Id, q.Id)
	}
	return ans
}

// wantAsked fails the case unless each resolver of the world received n[i]
// queries for name.
func wantAsked(t *runner.T, up *upstream.Upstream, name string, n ...int) {
	for i, qs := range askedFor(up, name) {
		if len(qs) != n[i] {
			t.Errorf("the resolver %s received %d queries for %s, want %d", up.Resolvers[i].Address(), len(qs), name, n[i])
		}
	}
}

// hasAddr says whether ans answers with an A record holding a.
func hasAddr(ans *dns.Msg, a netip.Addr) bool {
	for _, rr := range ans.Answer {
		if r, ok := rr.(*dns.A); ok && r.A.Equal(net.IP(a.AsSlice())) {
			return true
		}
	}
	return false
}

// forwardFirst: with every resolver answering, a query goes to the first
// in the claim's list alone, and its answer is the reply, an NXDOMAIN and
// an empty answer as much as an address; the third resolver, which the
// claim does not list, is never asked.
var forwardFirst = runner.Case{
	Name:  "a query for another name goes to the first resolver in the list, and its answer, whatever it is, is the reply",
	Cites: []string{"GUEST-15"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		ans := resolveVia(t, env, originName, dns.TypeA, 0x1501)
		if ans.Rcode != dns.RcodeSuccess || !hasAddr(ans, originAddr) {
			t.Errorf("A %s was answered %s with %v, want the first resolver's NOERROR with %s", originName, dns.RcodeToString[ans.Rcode], ans.Answer, originAddr)
		}
		wantAsked(t, r.up, originName, 1, 0, 0)
		const missing = "missing.example"
		ans = resolveVia(t, env, missing, dns.TypeA, 0x1502)
		if ans.Rcode != dns.RcodeNameError {
			t.Errorf("A %s was answered %s, want the first resolver's NXDOMAIN", missing, dns.RcodeToString[ans.Rcode])
		}
		wantAsked(t, r.up, missing, 1, 0, 0)
	},
}

// forwardRefused: the first resolver's port refuses, and the query goes to
// the second, whose answer is the reply.
var forwardRefused = runner.Case{
	Name:  "a query the first resolver refuses goes to the next in the list",
	Cites: []string{"GUEST-15"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		if err := r.up.Resolvers[0].SetMode(t.Context(), upstream.Failing); err != nil {
			t.Fatalf("making the first resolver refuse: %v", err)
		}
		ans := resolveVia(t, env, originName, dns.TypeA, 0x1511)
		if ans.Rcode != dns.RcodeSuccess || !hasAddr(ans, originAddr) {
			t.Errorf("A %s was answered %s with %v, want the second resolver's NOERROR with %s", originName, dns.RcodeToString[ans.Rcode], ans.Answer, originAddr)
		}
		wantAsked(t, r.up, originName, 0, 1, 0)
	},
}

// forwardSilent: the first resolver reads the query and never answers;
// the relay asks the second no sooner than 5 s later, and the second's
// answer reaches the build within its DNS time limit.
var forwardSilent = runner.Case{
	Name:  "a query the first resolver has not answered in 5 s goes to the next in the list",
	Cites: []string{"GUEST-15"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		if err := r.up.Resolvers[0].SetMode(t.Context(), upstream.Silent); err != nil {
			t.Fatalf("making the first resolver silent: %v", err)
		}
		ans := resolveVia(t, env, originName, dns.TypeA, 0x1521)
		if ans.Rcode != dns.RcodeSuccess || !hasAddr(ans, originAddr) {
			t.Errorf("A %s was answered %s with %v, want the second resolver's NOERROR with %s", originName, dns.RcodeToString[ans.Rcode], ans.Answer, originAddr)
		}
		asked := askedFor(r.up, originName)
		if len(asked[0]) != 1 || len(asked[1]) != 1 || len(asked[2]) != 0 {
			t.Fatalf("the resolvers received %d, %d and %d queries for %s, want 1, 1 and 0", len(asked[0]), len(asked[1]), len(asked[2]), originName)
		}
		if gap := asked[1][0].At.Sub(asked[0][0].At); gap < failover {
			t.Errorf("the relay asked the second resolver %s after the first, which had not answered; it gives a resolver 5 s", gap)
		}
	},
}

// servfail: no resolver in the list answers, the first silent and then the
// second refusing, and then both refusing: each reply is SERVFAIL, and the
// unlisted resolver is never asked.
var servfail = runner.Case{
	Name:  "when no resolver in the list answers, the reply is SERVFAIL",
	Cites: []string{"GUEST-16"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t)
		r.claim()
		env := r.build(nil)
		if err := r.up.Resolvers[0].SetMode(t.Context(), upstream.Silent); err != nil {
			t.Fatalf("making the first resolver silent: %v", err)
		}
		if err := r.up.Resolvers[1].SetMode(t.Context(), upstream.Failing); err != nil {
			t.Fatalf("making the second resolver refuse: %v", err)
		}
		ans := resolveVia(t, env, originName, dns.TypeA, 0x1601)
		if ans.Rcode != dns.RcodeServerFailure {
			t.Errorf("with the first resolver silent and the second refusing, A %s was answered %s with %v, want SERVFAIL", originName, dns.RcodeToString[ans.Rcode], ans.Answer)
		}
		if err := r.up.Resolvers[0].SetMode(t.Context(), upstream.Failing); err != nil {
			t.Fatalf("making the first resolver refuse: %v", err)
		}
		const other = "other.example"
		ans = resolveVia(t, env, other, dns.TypeA, 0x1602)
		if ans.Rcode != dns.RcodeServerFailure {
			t.Errorf("with both resolvers refusing, A %s was answered %s with %v, want SERVFAIL", other, dns.RcodeToString[ans.Rcode], ans.Answer)
		}
		for _, name := range []string{originName, other} {
			if qs := askedFor(r.up, name)[2]; len(qs) > 0 {
				t.Errorf("the resolver %s, which the claim does not list, was asked for %s", unlistedResolver, name)
			}
		}
	},
}
