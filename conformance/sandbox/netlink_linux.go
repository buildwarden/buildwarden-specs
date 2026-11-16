//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The few rtnetlink requests the sandbox makes, each in the network namespace
// of the thread that calls it (inNS): it runs no program to make them.

// vethInfoPeer is VETH_INFO_PEER of linux/veth.h.
const vethInfoPeer = 1

// linkUp sets the interface name up.
func linkUp(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return request(unix.RTM_NEWLINK, 0, ifInfo(ifi.Index, unix.IFF_UP, unix.IFF_UP))
}

// addAddr adds the IPv4 address p to the interface name.
func addAddr(name string, p netip.Prefix) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	a := p.Addr().As4()
	m := make([]byte, unix.SizeofIfAddrmsg)
	m[0], m[1], m[3] = unix.AF_INET, byte(p.Bits()), unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(m[4:], uint32(ifi.Index))
	m = append(m, attr(unix.IFA_LOCAL, a[:])...)
	m = append(m, attr(unix.IFA_ADDRESS, a[:])...)
	return request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, m)
}

// addVeth creates a veth pair, name here and peer in the network namespace
// the file peerNS holds.
func addVeth(name, peer string, peerNS *os.File) error {
	fd := make([]byte, 4)
	binary.NativeEndian.PutUint32(fd, uint32(peerNS.Fd()))
	p := ifInfo(0, 0, 0)
	p = append(p, attr(unix.IFLA_IFNAME, cstring(peer))...)
	p = append(p, attr(unix.IFLA_NET_NS_FD, fd)...)
	info := attr(unix.IFLA_INFO_KIND, []byte("veth"))
	info = append(info, attr(unix.IFLA_INFO_DATA, attr(vethInfoPeer, p))...)
	m := ifInfo(0, 0, 0)
	m = append(m, attr(unix.IFLA_IFNAME, cstring(name))...)
	m = append(m, attr(unix.IFLA_LINKINFO, info)...)
	return request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, m)
}

// addDefaultRoute adds the default route via gw.
func addDefaultRoute(gw netip.Addr) error {
	a := gw.As4()
	m := make([]byte, unix.SizeofRtMsg)
	m[0], m[4], m[5], m[6], m[7] = unix.AF_INET, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST
	m = append(m, attr(unix.RTA_GATEWAY, a[:])...)
	return request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, m)
}

// addLinkRoute routes p out of the interface name, with no gateway.
func addLinkRoute(name string, p netip.Prefix) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	a := p.Addr().As4()
	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(ifi.Index))
	m := make([]byte, unix.SizeofRtMsg)
	m[0], m[1], m[4], m[5], m[6], m[7] = unix.AF_INET, byte(p.Bits()), unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_LINK, unix.RTN_UNICAST
	m = append(m, attr(unix.RTA_DST, a[:])...)
	m = append(m, attr(unix.RTA_OIF, oif)...)
	return request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, m)
}

// addLocalRoute makes every address of p local, on loopback, so that a
// socket may be bound to any of them.
func addLocalRoute(p netip.Prefix) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	a := p.Addr().As4()
	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(lo.Index))
	m := make([]byte, unix.SizeofRtMsg)
	m[0], m[1], m[4], m[5], m[6], m[7] = unix.AF_INET, byte(p.Bits()), unix.RT_TABLE_LOCAL, unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL
	m = append(m, attr(unix.RTA_DST, a[:])...)
	m = append(m, attr(unix.RTA_OIF, oif)...)
	return request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, m)
}

// delLink deletes the interface name, and with a veth its pair. One that is
// gone already, with the namespace of its pair, is not an error.
func delLink(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		if strings.Contains(err.Error(), "no such network interface") {
			return nil
		}
		return err
	}
	err = request(unix.RTM_DELLINK, 0, ifInfo(ifi.Index, 0, 0))
	if errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}

func ifInfo(index int, flags, change uint32) []byte {
	m := make([]byte, unix.SizeofIfInfomsg)
	m[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(m[4:], uint32(index))
	binary.NativeEndian.PutUint32(m[8:], flags)
	binary.NativeEndian.PutUint32(m[12:], change)
	return m
}

func cstring(s string) []byte { return append([]byte(s), 0) }

// attr is one route attribute, padded to four bytes.
func attr(typ uint16, data []byte) []byte {
	n := unix.SizeofRtAttr + len(data)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(n))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[unix.SizeofRtAttr:], data)
	return b
}

// request sends one rtnetlink request and waits for its acknowledgement.
func request(typ, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	const seq = 1
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	binary.NativeEndian.PutUint16(msg[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], seq)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("netlink: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return fmt.Errorf("netlink: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq || m.Header.Type != unix.NLMSG_ERROR || len(m.Data) < 4 {
				continue
			}
			if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
				return syscall.Errno(-e)
			}
			return nil
		}
	}
}
