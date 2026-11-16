package dhcp

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
)

var (
	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	serverMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	relay     = netip.MustParseAddr("10.0.2.1")
	guest     = netip.MustParseAddr("10.0.2.15")
)

func TestMessageRoundTrip(t *testing.T) {
	t.Parallel()
	m := Message{
		Op: BootReply, HType: 1, HLen: 6, Xid: 0x01020304, Flags: 0x8000,
		Yiaddr: guest, Siaddr: relay, Chaddr: clientMAC,
		Options: []Option{
			{Code: OptMessageType, Data: []byte{Offer}},
			{Code: OptServerID, Data: relay.AsSlice()},
			{Code: OptDNS, Data: append(relay.AsSlice(), 10, 0, 2, 2)},
		},
	}
	b := m.Marshal()
	if len(b) != 300 {
		t.Errorf("marshalled %d bytes, want 300", len(b))
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != m.Op || got.Xid != m.Xid || got.Flags != m.Flags || got.Yiaddr != m.Yiaddr ||
		got.Siaddr != m.Siaddr || !bytes.Equal(got.Chaddr, m.Chaddr) || len(got.Options) != 3 || got.Type() != Offer {
		t.Errorf("parsed %+v, want %+v", got, m)
	}
	dns, ok := Addrs(must(got.Option(OptDNS)))
	if !ok || len(dns) != 2 || dns[1] != netip.MustParseAddr("10.0.2.2") {
		t.Errorf("option 6 = %v, %v; want 10.0.2.1 and 10.0.2.2", dns, ok)
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	valid := Message{Op: BootRequest, HType: 1, HLen: 6, Chaddr: clientMAC,
		Options: []Option{{Code: OptMessageType, Data: []byte{Discover}}}}.Marshal()
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{"shorter than 240 bytes", valid[:239], ErrShort.Error()},
		{"no cookie", append(append([]byte(nil), valid[:236]...), 1, 2, 3, 4), ErrNoCookie.Error()},
		{"an option cut short", append(append([]byte(nil), valid[:240]...), OptMessageType, 4, 1), ErrTruncated.Error()},
		{"an option without its length", append(append([]byte(nil), valid[:240]...), OptMessageType), ErrTruncated.Error()},
		{"a hardware address over 16 bytes", func() []byte { b := append([]byte(nil), valid...); b[2] = 17; return b }(), "over 16"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tt.b)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one that says %q", err, tt.want)
			}
		})
	}
	// Options run out without an end option: read to the end.
	m, err := Parse(append(append([]byte(nil), valid[:240]...), OptMessageType, 1, Discover))
	if err != nil || m.Type() != Discover {
		t.Errorf("parsed type %d, %v; want a DISCOVER", m.Type(), err)
	}
}

// responder is a server scripted in the test: it answers each message the
// client sends with what answer returns, and records what it was sent.
type responder struct {
	answer func(n int, req Message) []Message
	got    []Message
}

// reply is the OFFER or ACK a stateless server like the relay's gives.
func reply(req Message, typ byte, opts ...Option) Message {
	return Message{
		Op: BootReply, HType: 1, HLen: 6, Xid: req.Xid, Yiaddr: guest, Siaddr: relay, Chaddr: req.Chaddr,
		Options: append([]Option{
			{Code: OptMessageType, Data: []byte{typ}},
			{Code: OptServerID, Data: relay.AsSlice()},
			{Code: OptLeaseTime, Data: []byte{0xff, 0xff, 0xff, 0xff}},
			{Code: OptSubnetMask, Data: []byte{255, 255, 255, 0}},
			{Code: OptRouter, Data: relay.AsSlice()},
			{Code: OptDNS, Data: relay.AsSlice()},
		}, opts...),
	}
}

func stateless(n int, req Message) []Message {
	switch req.Type() {
	case Discover:
		return []Message{reply(req, Offer)}
	case Request:
		return []Message{reply(req, Ack)}
	}
	return nil
}

// serveFrames answers on the server's end of a frame pipe until it closes.
func (r *responder) serveFrames(t *testing.T, link net.Conn) {
	buf := make([]byte, 1<<16)
	for n := 0; ; n++ {
		k, err := link.Read(buf)
		if err != nil {
			return
		}
		u, ok := netstack.ParseUDPFrame(buf[:k])
		if !ok {
			t.Errorf("the client sent a frame that is not UDP over IPv4")
			continue
		}
		if !bytes.Equal(u.DstMAC, netstack.BroadcastMAC) || u.Src.String() != "0.0.0.0:68" || u.Dst.String() != "255.255.255.255:67" {
			t.Errorf("the client sent from %s %s to %s %s, want 0.0.0.0:68 to the broadcast address's port 67", u.SrcMAC, u.Src, u.DstMAC, u.Dst)
		}
		req, err := Parse(u.Payload)
		if err != nil {
			t.Errorf("the client sent a message Parse refuses: %v", err)
			continue
		}
		r.got = append(r.got, req)
		for _, a := range r.answer(n, req) {
			_, _ = link.Write(netstack.UDPFrame{
				SrcMAC: serverMAC, DstMAC: req.Chaddr,
				Src: netip.AddrPortFrom(relay, ServerPort), Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), ClientPort),
				Payload: a.Marshal(),
			}.Marshal())
		}
	}
}

// servePacket answers on a datagram endpoint bound to port 67.
func (r *responder) servePacket(t *testing.T, pc net.PacketConn) {
	buf := make([]byte, 1<<16)
	for n := 0; ; n++ {
		k, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := Parse(buf[:k])
		if err != nil {
			t.Errorf("the client sent a message Parse refuses: %v", err)
			continue
		}
		r.got = append(r.got, req)
		for _, a := range r.answer(n, req) {
			_, _ = pc.WriteTo(a.Marshal(), net.UDPAddrFromAddrPort(netip.AddrPortFrom(memnet.Broadcast, ClientPort)))
		}
	}
}

func TestLease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		answer func(n int, req Message) []Message
		want   string // an error the lease fails with, or empty
		sent   int    // messages the client sent
	}{{
		name:   "a stateless server",
		answer: stateless,
		sent:   2,
	}, {
		name: "replies to another transaction and client first",
		answer: func(n int, req Message) []Message {
			other := req
			other.Xid++
			stranger := req
			stranger.Chaddr = serverMAC
			return append([]Message{reply(other, Offer), reply(stranger, Ack)}, stateless(n, req)...)
		},
		sent: 2,
	}, {
		name: "the first DISCOVER is lost",
		answer: func(n int, req Message) []Message {
			if n == 0 {
				return nil
			}
			return stateless(n, req)
		},
		sent: 3,
	}, {
		name: "a NAK",
		answer: func(n int, req Message) []Message {
			if req.Type() == Request {
				return []Message{reply(req, Nak)}
			}
			return stateless(n, req)
		},
		want: "answered the DHCPREQUEST with a DHCPNAK",
	}, {
		name: "an OFFER without a server identifier",
		answer: func(n int, req Message) []Message {
			m := reply(req, Offer)
			m.Options = slicesDelete(m.Options, OptServerID)
			return []Message{m}
		},
		want: "the DHCPOFFER has no server identifier",
	}, {
		name: "an ACK without a mask",
		answer: func(n int, req Message) []Message {
			if req.Type() == Request {
				m := reply(req, Ack)
				m.Options = slicesDelete(m.Options, OptSubnetMask)
				return []Message{m}
			}
			return stateless(n, req)
		},
		want: "the DHCPACK has no subnet mask",
	}}
	for _, tt := range tests {
		for _, kind := range []string{"frames", "packet"} {
			t.Run(tt.name+" on "+kind, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				r := &responder{answer: tt.answer}
				done := make(chan struct{})
				var l Lease
				var err error
				switch kind {
				case "frames":
					c, s := memnet.Frames()
					go func() { r.serveFrames(t, s); close(done) }()
					l, err = LeaseFrames(ctx, c, clientMAC)
					_ = c.Close()
				case "packet":
					n := memnet.New()
					spc, lerr := n.Host(relay).ListenPacket(ctx, "udp", "0.0.0.0:67")
					if lerr != nil {
						t.Fatal(lerr)
					}
					cpc, lerr := n.Host(netip.IPv4Unspecified()).ListenPacket(ctx, "udp", "0.0.0.0:68")
					if lerr != nil {
						t.Fatal(lerr)
					}
					go func() { r.servePacket(t, spc); close(done) }()
					l, err = LeasePacket(ctx, cpc, clientMAC)
					_ = cpc.Close()
					_ = spc.Close()
				}
				<-done
				if tt.want != "" {
					if err == nil || !strings.Contains(err.Error(), tt.want) {
						t.Errorf("error = %v, want one that says %q", err, tt.want)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if l.Address != netip.MustParsePrefix("10.0.2.15/24") || l.Server != relay ||
					len(l.Router) != 1 || l.Router[0] != relay || len(l.DNS) != 1 || l.DNS[0] != relay || l.Seconds != 0xffffffff {
					t.Errorf("lease = %+v, want 10.0.2.15/24 from 10.0.2.1, which is router and DNS, for ever", l)
				}
				if len(r.got) != tt.sent {
					t.Fatalf("the client sent %d messages, want %d", len(r.got), tt.sent)
				}
				d, q := r.got[0], r.got[len(r.got)-1]
				if d.Type() != Discover || q.Type() != Request || d.Xid != q.Xid || !bytes.Equal(d.Chaddr, clientMAC) {
					t.Errorf("the client sent a %d and a %d, want a DISCOVER and a REQUEST of one transaction from its MAC", d.Type(), q.Type())
				}
				if ip, _ := q.Option(OptRequestedIP); !bytes.Equal(ip, guest.AsSlice()) {
					t.Errorf("the REQUEST asks for %v, want the offered 10.0.2.15", ip)
				}
				if id, _ := q.Option(OptServerID); !bytes.Equal(id, relay.AsSlice()) {
					t.Errorf("the REQUEST names server %v, want 10.0.2.1", id)
				}
			})
		}
	}
}

func TestLeaseEndsWithItsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c, s := memnet.Frames()
	defer s.Close()
	_, err := LeaseFrames(ctx, c, clientMAC)
	if err == nil || !strings.Contains(err.Error(), "no DHCPOFFER after 1 DHCPDISCOVER") {
		t.Errorf("error = %v, want one that says no DHCPOFFER came", err)
	}
}

func slicesDelete(opts []Option, code byte) []Option {
	var out []Option
	for _, o := range opts {
		if o.Code != code {
			out = append(out, o)
		}
	}
	return out
}
