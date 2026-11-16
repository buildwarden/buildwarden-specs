package netstack

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/memnet"
)

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
)

// twoStacks makes a stack on each end of one frame pipe, on one link.
func twoStacks(t *testing.T) (*Stack, *Stack) {
	t.Helper()
	ea, eb := memnet.Frames()
	a, err := New(ea, Config{MAC: macA, Address: netip.MustParsePrefix("10.0.0.1/24")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := New(eb, Config{MAC: macB, Address: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return a, b
}

func TestTCPAcrossTheFramePipe(t *testing.T) {
	t.Parallel()
	a, b := twoStacks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ln, err := a.Network().Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c, err := b.Network().Dial(ctx, "tcp", "10.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// More than one segment and more than one window's worth.
	msg := bytes.Repeat([]byte("frames "), 200_000)
	go func() {
		_, _ = c.Write(msg)
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echoed %d bytes, want the %d sent", len(got), len(msg))
	}
	if got := c.LocalAddr().String(); !strings.HasPrefix(got, "10.0.0.2:") {
		t.Errorf("local address = %s, want one on 10.0.0.2", got)
	}
}

func TestUDPAcrossTheFramePipe(t *testing.T) {
	t.Parallel()
	a, b := twoStacks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, err := a.Network().ListenPacket(ctx, "udp", ":53")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := b.Network().Dial(ctx, "udp", "10.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(20 * time.Second))
	n, from, err := srv.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "query" || !strings.HasPrefix(from.String(), "10.0.0.2:") {
		t.Errorf("read %q from %s, want \"query\" from 10.0.0.2", buf[:n], from)
	}
	if _, err := srv.WriteTo([]byte("answer"), from); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	n, err = c.Read(buf)
	if err != nil || string(buf[:n]) != "answer" {
		t.Errorf("read %q, %v; want \"answer\"", buf[:n], err)
	}
}

func TestAnyAddress(t *testing.T) {
	t.Parallel()
	ea, eb := memnet.Frames()
	a, err := New(ea, Config{MAC: macA, Address: netip.MustParsePrefix("10.0.0.1/24"), AnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(eb, Config{MAC: macB, Address: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ln, err := a.Network().Listen(ctx, "tcp", "198.51.100.80:80")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte(c.LocalAddr().String()))
		_ = c.Close()
	}()
	c, err := b.Network().Dial(ctx, "tcp", "198.51.100.80:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "198.51.100.80:80" {
		t.Errorf("read %q, %v; want the address dialled, 198.51.100.80:80", got, err)
	}
}

func TestDialWithNothingListeningIsRefused(t *testing.T) {
	t.Parallel()
	_, b := twoStacks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := b.Network().Dial(ctx, "tcp", "10.0.0.1:81"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("error = %v, want a refusal", err)
	}
}

func TestConfigErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no MAC", Config{Address: netip.MustParsePrefix("10.0.0.1/24")}, "is not an Ethernet address"},
		{"no address", Config{MAC: macA}, "is not an IPv4 address with a prefix"},
		{"IPv6", Config{MAC: macA, Address: netip.MustParsePrefix("2001:db8::1/64")}, "is not an IPv4 address with a prefix"},
		{"gateway off the link", Config{MAC: macA, Address: netip.MustParsePrefix("10.0.0.1/24"), Gateway: netip.MustParseAddr("10.0.1.1")}, "is not on the link 10.0.0.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ea, eb := memnet.Frames()
			defer ea.Close()
			defer eb.Close()
			_, err := New(ea, tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one that says %q", err, tt.want)
			}
		})
	}
}

func TestNetworkAddresses(t *testing.T) {
	t.Parallel()
	a, _ := twoStacks(t)
	ctx := context.Background()
	tests := []struct {
		address, want string
	}{
		{"10.0.0.1:http", "port \"http\""},
		{"relay:80", "the stack resolves no names"},
		{"[2001:db8::1]:80", "IPv4 only"},
	}
	for _, tt := range tests {
		if _, err := a.Network().Listen(ctx, "tcp", tt.address); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Listen(%q): %v, want an error that says %q", tt.address, err, tt.want)
		}
	}
	if _, err := a.Network().Dial(ctx, "tcp", ":80"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Errorf("Dial(\":80\"): %v, want an error that says \"no host\"", err)
	}
	if got := a.Network().Address(); got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("Address() = %v, want 10.0.0.1", got)
	}
}

func TestUDPFrame(t *testing.T) {
	t.Parallel()
	f := UDPFrame{
		SrcMAC:  macA,
		DstMAC:  BroadcastMAC,
		Src:     netip.MustParseAddrPort("0.0.0.0:68"),
		Dst:     netip.MustParseAddrPort("255.255.255.255:67"),
		Payload: []byte("an odd-length payload"),
	}
	b := f.Marshal()
	got, ok := ParseUDPFrame(b)
	if !ok {
		t.Fatal("ParseUDPFrame refused what Marshal wrote")
	}
	f.TTL = 64
	if got.SrcMAC.String() != f.SrcMAC.String() || got.DstMAC.String() != f.DstMAC.String() ||
		got.Src != f.Src || got.Dst != f.Dst || got.TTL != f.TTL || !bytes.Equal(got.Payload, f.Payload) {
		t.Errorf("parsed %+v, want %+v", got, f)
	}

	tests := []struct {
		name  string
		edit  func(b []byte) []byte
		valid bool
	}{
		{"unchanged", func(b []byte) []byte { return b }, true},
		{"padded to the Ethernet minimum", func(b []byte) []byte { return append(b, make([]byte, 20)...) }, true},
		{"no UDP checksum", func(b []byte) []byte { b[40], b[41] = 0, 0; return b }, true},
		{"an ARP frame", func(b []byte) []byte { b[12], b[13] = 0x08, 0x06; return b }, false},
		{"TCP", func(b []byte) []byte { b[23] = 6; return ipChecksum(b) }, false},
		{"IP options", func(b []byte) []byte { b[14] = 0x46; return ipChecksum(b) }, false},
		{"a fragment", func(b []byte) []byte { b[20] = 0x20; return ipChecksum(b) }, false},
		{"a wrong IP checksum", func(b []byte) []byte { b[24] ^= 1; return b }, false},
		{"a wrong UDP checksum", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, false},
		{"cut short", func(b []byte) []byte { return b[:len(b)-1] }, false},
		{"too short for its headers", func(b []byte) []byte { return b[:40] }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := ParseUDPFrame(tt.edit(f.Marshal()))
			if ok != tt.valid {
				t.Errorf("ParseUDPFrame reported %v, want %v", ok, tt.valid)
			}
		})
	}
}

// ipChecksum writes the IPv4 header checksum of the frame b again, so that
// an edit of the header is refused for the edit and not for the checksum.
func ipChecksum(b []byte) []byte {
	ip := b[ethernetHeader : ethernetHeader+ipv4Header]
	ip[10], ip[11] = 0, 0
	c := ^sum(0, ip)
	ip[10], ip[11] = byte(c>>8), byte(c)
	return b
}

func TestCaptureTakesAnyAddressAndPort(t *testing.T) {
	t.Parallel()
	ea, eb := memnet.Frames()
	a, err := New(ea, Config{MAC: macA, Address: netip.MustParsePrefix("10.0.0.1/24"), AnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(eb, Config{MAC: macB, Address: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A listener of the stack's own takes its port; Capture takes the rest.
	ln, err := a.Network().Listen(ctx, "tcp", "10.0.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("listener"))
		_ = c.Close()
	}()
	a.Capture(func(c net.Conn) {
		_, _ = c.Write([]byte("captured " + c.LocalAddr().String()))
		_ = c.Close()
	})
	for addr, want := range map[string]string{
		"10.0.0.1:7":        "listener",
		"10.0.0.1:9999":     "captured 10.0.0.1:9999",
		"198.51.100.80:443": "captured 198.51.100.80:443",
		"203.0.113.9:12345": "captured 203.0.113.9:12345",
	} {
		c, err := b.Network().Dial(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		got, err := io.ReadAll(c)
		_ = c.Close()
		if err != nil || string(got) != want {
			t.Errorf("%s: read %q, %v; want %q", addr, got, err, want)
		}
	}
}
