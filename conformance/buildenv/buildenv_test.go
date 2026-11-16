package buildenv

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/dhcp"
	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
	"github.com/buildwarden/buildwarden-specs/conformance/netstack"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The test's world, with no relay in it. "relay" is the address that
// stands where a relay's would: the DNS server and, on an ip link, what
// every connection goes to. On a frames link the origin is elsewhere, and
// the party at the other end of the pipe takes every address, so that the
// build environment's connection to the address DNS gave is seen to reach
// that address.
var (
	relay     = netip.MustParseAddr("192.0.2.1")
	guest     = netip.MustParseAddr("192.0.2.15")
	elsewhere = netip.MustParseAddr("198.51.100.80")
	guestMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0f}
	worldMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
)

const originName = "origin.example"

// health serves the control plane's /health at relay:8300 on n, after
// delay, as a relay whose ports are not yet bound when it is claimed.
func health(t *testing.T, n attach.Network, delay time.Duration) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		http.NotFound(w, r)
	})}
	t.Cleanup(func() { _ = srv.Close() })
	go func() {
		time.Sleep(delay)
		// A failure to listen shows as Ready's failure.
		ln, err := n.Listen(context.Background(), "tcp", net.JoinHostPort(relay.String(), "8300"))
		if err != nil {
			return
		}
		_ = srv.Serve(ln)
	}()
}

// leaseResponder answers the build environment's DISCOVER and REQUEST on
// the world's end of a frame pipe, as the relay's stateless DHCP does, and
// returns once it has sent the ACK, so that the world's stack can take the
// link from then on.
func leaseResponder(link net.Conn) error {
	buf := make([]byte, 1<<16)
	for {
		n, err := link.Read(buf)
		if err != nil {
			return err
		}
		u, ok := netstack.ParseUDPFrame(buf[:n])
		if !ok || u.Dst.Port() != dhcp.ServerPort {
			continue
		}
		req, err := dhcp.Parse(u.Payload)
		if err != nil {
			continue
		}
		typ := byte(dhcp.Offer)
		if req.Type() == dhcp.Request {
			typ = dhcp.Ack
		}
		reply := dhcp.Message{
			Op: dhcp.BootReply, HType: 1, HLen: 6, Xid: req.Xid, Yiaddr: guest, Siaddr: relay, Chaddr: req.Chaddr,
			Options: []dhcp.Option{
				{Code: dhcp.OptMessageType, Data: []byte{typ}},
				{Code: dhcp.OptServerID, Data: relay.AsSlice()},
				{Code: dhcp.OptLeaseTime, Data: []byte{0xff, 0xff, 0xff, 0xff}},
				{Code: dhcp.OptSubnetMask, Data: []byte{255, 255, 255, 0}},
				{Code: dhcp.OptRouter, Data: relay.AsSlice()},
				{Code: dhcp.OptDNS, Data: relay.AsSlice()},
			},
		}
		if _, err := link.Write(netstack.UDPFrame{
			SrcMAC: worldMAC, DstMAC: req.Chaddr,
			Src: netip.AddrPortFrom(relay, dhcp.ServerPort), Dst: netip.AddrPortFrom(memnet.Broadcast, dhcp.ClientPort),
			Payload: reply.Marshal(),
		}.Marshal()); err != nil {
			return err
		}
		if typ == dhcp.Ack {
			return nil
		}
	}
}

// start starts the world and a build environment on a link of kind link,
// and returns them with the address the origin is at.
func start(t *testing.T, link string, healthDelay time.Duration) (*Env, *upstream.Upstream, netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	var (
		world  attach.Network
		cfg    Config
		origin netip.Addr
	)
	switch link {
	case IP:
		n := memnet.New()
		world, origin = n.Host(relay), relay
		cfg = Config{Link: IP, Network: n.Host(guest), Relay: relay}
	case Frames:
		build, end := memnet.Frames()
		stacked := make(chan *netstack.Stack, 1)
		go func() {
			defer close(stacked)
			if err := leaseResponder(end); err != nil {
				t.Error(err)
				return
			}
			st, err := netstack.New(end, netstack.Config{MAC: worldMAC, Address: netip.PrefixFrom(relay, 24), AnyAddress: true})
			if err != nil {
				t.Error(err)
				return
			}
			stacked <- st
		}()
		cfg = Config{Link: Frames, Frames: build, MAC: guestMAC}
		env, err := Start(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = env.Close() })
		st := <-stacked
		if st == nil {
			t.FailNow()
		}
		t.Cleanup(func() { _ = st.Close() })
		world, origin = st.Network(), elsewhere
		u := startWorld(t, ctx, world, origin)
		health(t, world, healthDelay)
		return env, u, origin
	}
	u := startWorld(t, ctx, world, origin)
	health(t, world, healthDelay)
	env, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	return env, u, origin
}

func startWorld(t *testing.T, ctx context.Context, n attach.Network, origin netip.Addr) *upstream.Upstream {
	t.Helper()
	u, err := upstream.Start(ctx, n, upstream.World{
		Resolvers: []netip.Addr{relay},
		Origins:   []upstream.Origin{{Name: originName, Addr: origin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func TestBuildEnvironmentWithNoRelay(t *testing.T) {
	t.Parallel()
	for _, link := range []string{IP, Frames} {
		t.Run(link, func(t *testing.T) {
			t.Parallel()
			env, u, origin := start(t, link, 300*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if env.Link() != link || env.Relay() != relay || env.DNSServer() != relay {
				t.Errorf("link %s, relay %s, DNS %s; want %s, %s, %s", env.Link(), env.Relay(), env.DNSServer(), link, relay, relay)
			}
			l, leased := env.Lease()
			if leased != (link == Frames) || (leased && l.Address != netip.PrefixFrom(guest, 24)) {
				t.Errorf("lease %+v, %v; want 192.0.2.15/24 on frames and none on ip", l, leased)
			}
			if got := env.Network().Address(); got != guest {
				t.Errorf("the build environment is at %s, want %s", got, guest)
			}

			// The health stub binds 300 ms late: Ready waits for it.
			if err := env.Ready(ctx); err != nil {
				t.Fatal(err)
			}

			as, err := env.Resolve(ctx, originName)
			if err != nil || len(as) != 1 || as[0] != origin {
				t.Errorf("Resolve(%s) = %v, %v; want %s", originName, as, err, origin)
			}
			if _, err := env.Resolve(ctx, "absent.example"); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
				t.Errorf("Resolve(absent.example): %v, want NXDOMAIN", err)
			}

			c := env.Client(u.CA.Pool())
			for i, url := range []string{"http://" + originName + "/a", "https://" + originName + upstream.BytesPath + "100000"} {
				resp, err := c.Get(url)
				if err != nil {
					t.Fatalf("GET %s: %v", url, err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				path := strings.TrimPrefix(strings.TrimPrefix(url, "http://"+originName), "https://"+originName)
				if resp.StatusCode != 200 || !bytes.Equal(body, upstream.Body(originName, path)) {
					t.Errorf("GET %s: %d with %d bytes, want 200 with Body", url, resp.StatusCode, len(body))
				}
				ex := u.Origins.Exchanges()
				if len(ex) != i+1 {
					t.Fatalf("the origin has %d exchanges, want %d", len(ex), i+1)
				}
				e := ex[i]
				if e.Origin != originName || e.Host != originName || !strings.HasPrefix(e.From, guest.String()+":") {
					t.Errorf("exchange %+v, want Host %s from %s", e, originName, guest)
				}
				if e.Port == 443 && e.ServerName != originName {
					t.Errorf("server name %q, want %s", e.ServerName, originName)
				}
			}
		})
	}
}

func TestReadyEndsWithItsContext(t *testing.T) {
	t.Parallel()
	n := memnet.New()
	env, err := Start(context.Background(), Config{Link: IP, Network: n.Host(guest), Relay: relay})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := env.Ready(ctx); err == nil || !strings.Contains(err.Error(), "was not answered 200") || !strings.Contains(err.Error(), "refused") {
		t.Errorf("error = %v, want one that says /health was not answered and the last attempt was refused", err)
	}
}

func TestStartErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no link", Config{}, `link "" is neither`},
		{"frames without a socket", Config{Link: Frames}, "needs its frame socket"},
		{"ip without a network", Config{Link: IP, Relay: relay}, "needs its network"},
		{"ip without the relay", Config{Link: IP, Network: memnet.New().Host(guest)}, "needs its network and the relay's IPv4 address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Start(context.Background(), tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one that says %q", err, tt.want)
			}
		})
	}
}
