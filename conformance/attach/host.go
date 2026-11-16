package attach

import (
	"context"
	"net"
	"net/netip"
)

// Host is the host's own network, on which the harness's address on a side
// is addr: the launchers' network for a component that runs as a process of
// this host or that is reached at addresses a target file gives.
func Host(addr netip.Addr) Network { return host{addr: addr} }

type host struct{ addr netip.Addr }

func (h host) Address() netip.Addr { return h.addr }

func (h host) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, network, address)
}

func (h host) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}

func (h host) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
