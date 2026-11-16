package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSStreamIdle is how long the relay keeps a DNS-over-TCP connection with
// no query on it. It is a constant of a harness release.
const DNSStreamIdle = 30 * time.Second

// serveDNSPacket answers DNS over UDP at the relay's address (GUEST-12).
func (g *Guest) serveDNSPacket(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if ans := g.answerDNS(q); ans != nil {
				_, _ = pc.WriteTo(ans, from)
			}
		}()
	}
}

// serveDNSStream answers DNS over TCP, each message after its two-byte
// length (RFC 1035, section 4.2.2), on a kernel interface (GUEST-2) and, on
// a frame link, at port 53 of any address (GUEST-6 lets it).
func (g *Guest) serveDNSStream(c net.Conn) {
	for {
		_ = c.SetReadDeadline(time.Now().Add(DNSStreamIdle))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		ans := g.answerDNS(q)
		if ans == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(ans)))
		if _, err := c.Write(append(out, ans...)); err != nil {
			return
		}
	}
}

// answerDNS is the relay's answer to one query, or nil for bytes that are
// not one. The reserved names it answers itself (GUEST-13, GUEST-14); every
// other query goes to the claim's resolvers in their order, each given
// ResolveTimeout, and the first answer is the reply, with the query's ID
// (GUEST-15); when none answers, the reply is SERVFAIL (GUEST-16).
func (g *Guest) answerDNS(query []byte) []byte {
	q := new(dns.Msg)
	if err := q.Unpack(query); err != nil || q.Response {
		return nil
	}
	if len(q.Question) == 1 && reservedName(q.Question[0].Name) != "" {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Authoritative = true
		if qq := q.Question[0]; qq.Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.IP(g.Address().AsSlice()),
			}}
		}
		b, err := r.Pack()
		if err != nil {
			return nil
		}
		return b
	}
	s := g.session
	ctx := g.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for _, server := range s.claim.Resolvers {
		if s.relay.cfg.Upstream == nil {
			break
		}
		if raw, _, err := askRaw(ctx, s.relay.cfg.Upstream, server, query, q.Id); err == nil {
			return raw
		}
	}
	r := new(dns.Msg)
	r.SetRcode(q, dns.RcodeServerFailure)
	b, err := r.Pack()
	if err != nil {
		return nil
	}
	return b
}
