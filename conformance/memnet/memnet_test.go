package memnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	addrA = netip.MustParseAddr("192.0.2.1")
	addrB = netip.MustParseAddr("192.0.2.2")
)

func TestStreamEcho(t *testing.T) {
	t.Parallel()
	n := New()
	ctx := context.Background()
	ln, err := n.Host(addrA).Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := ln.Addr().String(); got != "192.0.2.1:80" {
		t.Errorf("listener address = %s, want 192.0.2.1:80", got)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c, err := n.Host(addrB).Dial(ctx, "tcp", "192.0.2.1:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != "192.0.2.1:80" {
		t.Errorf("remote address = %s, want 192.0.2.1:80", got)
	}
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	if local.Addr() != addrB || local.Port() < firstEphemeral {
		t.Errorf("local address = %s, want 192.0.2.2 on an ephemeral port", local)
	}
	// More than the buffer holds, so that the writer waits for the reader.
	msg := bytes.Repeat([]byte("0123456789abcdef"), StreamBuffer/4)
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
}

func TestStreamErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name string
		run  func(n *Net) error
		want error
	}{{
		name: "dial with nothing listening",
		run: func(n *Net) error {
			_, err := n.Host(addrB).Dial(ctx, "tcp", "192.0.2.1:80")
			return err
		},
		want: syscall.ECONNREFUSED,
	}, {
		name: "dial to a closed listener",
		run: func(n *Net) error {
			ln, err := n.Host(addrA).Listen(ctx, "tcp", ":80")
			if err != nil {
				return err
			}
			_ = ln.Close()
			_, err = n.Host(addrB).Dial(ctx, "tcp", "192.0.2.1:80")
			return err
		},
		want: syscall.ECONNREFUSED,
	}, {
		name: "listen twice",
		run: func(n *Net) error {
			if _, err := n.Host(addrA).Listen(ctx, "tcp", ":80"); err != nil {
				return err
			}
			_, err := n.Host(addrA).Listen(ctx, "tcp", "192.0.2.1:80")
			return err
		},
		want: syscall.EADDRINUSE,
	}, {
		name: "listen on a port the unspecified address holds",
		run: func(n *Net) error {
			if _, err := n.Host(addrA).Listen(ctx, "tcp", "0.0.0.0:80"); err != nil {
				return err
			}
			_, err := n.Host(addrB).Listen(ctx, "tcp", ":80")
			return err
		},
		want: syscall.EADDRINUSE,
	}, {
		name: "write after the peer closed",
		run: func(n *Net) error {
			a, b := pair(t, n)
			_ = b.Close()
			_, err := a.Write([]byte("x"))
			return err
		},
		want: syscall.ECONNRESET,
	}, {
		name: "write after CloseWrite",
		run: func(n *Net) error {
			a, _ := pair(t, n)
			_ = a.(interface{ CloseWrite() error }).CloseWrite()
			_, err := a.Write([]byte("x"))
			return err
		},
		want: syscall.EPIPE,
	}, {
		name: "read after Close",
		run: func(n *Net) error {
			a, _ := pair(t, n)
			_ = a.Close()
			_, err := a.Read(make([]byte, 1))
			return err
		},
		want: net.ErrClosed,
	}, {
		name: "read past its deadline",
		run: func(n *Net) error {
			a, _ := pair(t, n)
			_ = a.SetReadDeadline(time.Now().Add(-time.Second))
			_, err := a.Read(make([]byte, 1))
			return err
		},
		want: os.ErrDeadlineExceeded,
	}, {
		name: "a reset of what a closed listener had not accepted",
		run: func(n *Net) error {
			ln, err := n.Host(addrA).Listen(ctx, "tcp", ":80")
			if err != nil {
				return err
			}
			c, err := n.Host(addrB).Dial(ctx, "tcp", "192.0.2.1:80")
			if err != nil {
				return err
			}
			_ = ln.Close()
			_, err = c.Read(make([]byte, 1))
			return err
		},
		want: syscall.ECONNRESET,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run(New())
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestStreamPeerCloseIsEOF(t *testing.T) {
	t.Parallel()
	a, b := pair(t, New())
	if _, err := b.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	got, err := io.ReadAll(a)
	if err != nil || string(got) != "last" {
		t.Errorf("read %q, %v; want \"last\" and EOF", got, err)
	}
}

func TestDeadlineWakesABlockedRead(t *testing.T) {
	t.Parallel()
	a, _ := pair(t, New())
	done := make(chan error, 1)
	go func() {
		_, err := a.Read(make([]byte, 1))
		done <- err
	}()
	_ = a.SetReadDeadline(time.Now())
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("error = %v, want a timeout", err)
	}
	var ne net.Error
	_ = a.SetReadDeadline(time.Now())
	_, err := a.Read(make([]byte, 1))
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("error = %v, want a net.Error whose Timeout is true", err)
	}
}

func TestParseAddresses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		network, address, want string
	}{
		{"tcp", "example.com:80", "the in-memory network has no names"},
		{"tcp", "[2001:db8::1]:80", "IPv4 only"},
		{"tcp", "192.0.2.1", "missing port"},
		{"tcp", "192.0.2.1:http", "port \"http\""},
		{"unix", "192.0.2.1:80", "unknown network"},
		{"udp6", "192.0.2.1:80", "unknown network"},
	}
	for _, tt := range tests {
		t.Run(tt.network+" "+tt.address, func(t *testing.T) {
			t.Parallel()
			v := New().Host(addrA)
			var err error
			if strings.HasPrefix(tt.network, "udp") {
				_, err = v.ListenPacket(ctx, tt.network, tt.address)
			} else {
				_, err = v.Listen(ctx, tt.network, tt.address)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one that says %q", err, tt.want)
			}
		})
	}
}

func TestDatagrams(t *testing.T) {
	t.Parallel()
	n := New()
	ctx := context.Background()
	srv, err := n.Host(addrA).ListenPacket(ctx, "udp", ":53")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := n.Host(addrB).Dial(ctx, "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	nr, from, err := srv.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:nr]) != "query" || from.String() != c.LocalAddr().String() {
		t.Errorf("read %q from %s, want \"query\" from %s", buf[:nr], from, c.LocalAddr())
	}
	// A datagram from another address does not reach a connected endpoint.
	other, err := n.Host(addrA).ListenPacket(ctx, "udp", ":54")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.WriteTo([]byte("stray"), c.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.WriteTo([]byte("answer"), from); err != nil {
		t.Fatal(err)
	}
	nr, err = c.Read(buf)
	if err != nil || string(buf[:nr]) != "answer" {
		t.Errorf("read %q, %v; want \"answer\"", buf[:nr], err)
	}
	// A datagram longer than the buffer is cut to it.
	if _, err := srv.WriteTo([]byte("a longer answer"), from); err != nil {
		t.Fatal(err)
	}
	nr, err = c.Read(buf[:3])
	if err != nil || string(buf[:nr]) != "a l" {
		t.Errorf("read %q, %v; want \"a l\"", buf[:nr], err)
	}
}

func TestConnectedDatagramIsRefused(t *testing.T) {
	t.Parallel()
	c, err := New().Host(addrB).Dial(context.Background(), "udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatalf("first write: %v, want none: the refusal comes after", err)
	}
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("read: %v, want ECONNREFUSED", err)
	}
}

func TestBroadcast(t *testing.T) {
	t.Parallel()
	n := New()
	ctx := context.Background()
	// Two servers on port 67, on the unspecified address and on one of their
	// own, and one on another port, which the broadcast does not reach.
	s1, err := n.Host(addrA).ListenPacket(ctx, "udp", "0.0.0.0:67")
	if err != nil {
		t.Fatal(err)
	}
	s3, err := n.Host(addrA).ListenPacket(ctx, "udp", ":68")
	if err != nil {
		t.Fatal(err)
	}
	// A party with no address yet, as a client before its lease.
	client, err := n.Host(netip.IPv4Unspecified()).ListenPacket(ctx, "udp", "0.0.0.0:68")
	if err == nil {
		t.Fatal("bound 0.0.0.0:68 over 192.0.2.1:68, want EADDRINUSE")
	}
	_ = s3.Close()
	client, err = n.Host(netip.IPv4Unspecified()).ListenPacket(ctx, "udp", "0.0.0.0:68")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo([]byte("discover"), udpAddr(netip.AddrPortFrom(Broadcast, 67))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	nr, from, err := s1.ReadFrom(buf)
	if err != nil || string(buf[:nr]) != "discover" || from.String() != "0.0.0.0:68" {
		t.Errorf("server read %q from %v, %v; want \"discover\" from 0.0.0.0:68", buf[:nr], from, err)
	}
	if _, err := s1.WriteTo([]byte("offer"), udpAddr(netip.AddrPortFrom(Broadcast, 68))); err != nil {
		t.Fatal(err)
	}
	nr, from, err = client.ReadFrom(buf)
	if err != nil || string(buf[:nr]) != "offer" || from.String() != "192.0.2.1:67" {
		t.Errorf("client read %q from %v, %v; want \"offer\" from 192.0.2.1:67", buf[:nr], from, err)
	}
}

func TestFrames(t *testing.T) {
	t.Parallel()
	a, b := Frames()
	defer a.Close()
	for _, f := range []string{"first frame", "second", ""} {
		if _, err := a.Write([]byte(f)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64)
	for _, want := range []string{"first frame", "second", ""} {
		n, err := b.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Errorf("read %q, %v; want %q", buf[:n], err, want)
		}
	}
	// A frame longer than the buffer is cut, and the rest dropped.
	_, _ = b.Write([]byte("0123456789"))
	_, _ = b.Write([]byte("next"))
	if n, _ := a.Read(buf[:4]); string(buf[:n]) != "0123" {
		t.Errorf("read %q, want \"0123\"", buf[:n])
	}
	if n, _ := a.Read(buf); string(buf[:n]) != "next" {
		t.Errorf("read %q, want \"next\"", buf[:n])
	}
	// After one end closes, the other reads what was sent, then EOF.
	_, _ = b.Write([]byte("bye"))
	_ = b.Close()
	if n, err := a.Read(buf); err != nil || string(buf[:n]) != "bye" {
		t.Errorf("read %q, %v; want \"bye\"", buf[:n], err)
	}
	if _, err := a.Read(buf); err != io.EOF {
		t.Errorf("read: %v, want EOF", err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("write: %v, want ECONNREFUSED", err)
	}
}

func TestFramesWriteWaitsForTheReader(t *testing.T) {
	t.Parallel()
	a, b := Frames()
	defer a.Close()
	defer b.Close()
	for range FrameQueue {
		if _, err := a.Write([]byte("f")); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := a.Write([]byte("f")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("write to a full pipe: %v, want a timeout", err)
	}
}

// pair returns the two ends of one stream connection on n.
func pair(t *testing.T, n *Net) (net.Conn, net.Conn) {
	t.Helper()
	ctx := context.Background()
	ln, err := n.Host(addrA).Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	a, err := n.Host(addrB).Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}
