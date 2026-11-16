package netstack

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Sizes of the headers a UDPFrame carries.
const (
	ethernetHeader = 14
	ipv4Header     = 20
	udpHeader      = 8
)

// The EtherTypes and the IP protocol a UDPFrame names.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	protocolUDP   = 17
)

// BroadcastMAC is the Ethernet broadcast address.
var BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// UDPFrame is one IPv4 UDP datagram in an Ethernet frame, with no IP
// options and no fragmentation. It is what a party on a frame link sends
// and reads before it has a network stack: the address lease's messages,
// and a responder's that a test scripts.
type UDPFrame struct {
	SrcMAC, DstMAC net.HardwareAddr
	Src, Dst       netip.AddrPort
	// TTL is the IPv4 time to live; Marshal writes 64 for 0.
	TTL     uint8
	Payload []byte
}

// Marshal returns the frame's bytes, with the IPv4 header checksum and the
// UDP checksum computed.
func (f UDPFrame) Marshal() []byte {
	b := make([]byte, ethernetHeader+ipv4Header+udpHeader+len(f.Payload))
	copy(b[0:6], f.DstMAC)
	copy(b[6:12], f.SrcMAC)
	binary.BigEndian.PutUint16(b[12:14], EtherTypeIPv4)

	ip := b[ethernetHeader : ethernetHeader+ipv4Header]
	ttl := f.TTL
	if ttl == 0 {
		ttl = 64
	}
	ip[0] = 0x45 // version 4, header of five words
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Header+udpHeader+len(f.Payload)))
	ip[8] = ttl
	ip[9] = protocolUDP
	src, dst := f.Src.Addr().As4(), f.Dst.Addr().As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], ^sum(0, ip))

	u := b[ethernetHeader+ipv4Header:]
	binary.BigEndian.PutUint16(u[0:2], f.Src.Port())
	binary.BigEndian.PutUint16(u[2:4], f.Dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[udpHeader:], f.Payload)
	c := ^sum(pseudoHeader(src, dst, len(u)), u)
	if c == 0 {
		c = 0xffff // RFC 768: a computed zero is sent as all ones
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return b
}

// ParseUDPFrame reads b as a UDPFrame. It reports false for anything else:
// another EtherType, another protocol, IP options, a fragment, a length that
// does not fit, or a checksum that is wrong. A UDP checksum of zero is none,
// which IPv4 allows.
func ParseUDPFrame(b []byte) (UDPFrame, bool) {
	if len(b) < ethernetHeader+ipv4Header+udpHeader || binary.BigEndian.Uint16(b[12:14]) != EtherTypeIPv4 {
		return UDPFrame{}, false
	}
	ip := b[ethernetHeader:]
	if ip[0] != 0x45 || ip[9] != protocolUDP || sum(0, ip[:ipv4Header]) != 0xffff {
		return UDPFrame{}, false
	}
	if flags := binary.BigEndian.Uint16(ip[6:8]); flags&0x3fff != 0 { // more fragments, or an offset
		return UDPFrame{}, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total < ipv4Header+udpHeader || total > len(ip) {
		return UDPFrame{}, false
	}
	u := ip[ipv4Header:total]
	if int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
		return UDPFrame{}, false
	}
	src, dst := [4]byte(ip[12:16]), [4]byte(ip[16:20])
	if binary.BigEndian.Uint16(u[6:8]) != 0 && sum(pseudoHeader(src, dst, len(u)), u) != 0xffff {
		return UDPFrame{}, false
	}
	return UDPFrame{
		DstMAC:  net.HardwareAddr(append([]byte(nil), b[0:6]...)),
		SrcMAC:  net.HardwareAddr(append([]byte(nil), b[6:12]...)),
		Src:     netip.AddrPortFrom(netip.AddrFrom4(src), binary.BigEndian.Uint16(u[0:2])),
		Dst:     netip.AddrPortFrom(netip.AddrFrom4(dst), binary.BigEndian.Uint16(u[2:4])),
		TTL:     ip[8],
		Payload: append([]byte(nil), u[udpHeader:]...),
	}, true
}

// pseudoHeader is the ones-complement sum of UDP's IPv4 pseudo-header.
func pseudoHeader(src, dst [4]byte, length int) uint16 {
	var p [12]byte
	copy(p[0:4], src[:])
	copy(p[4:8], dst[:])
	p[9] = protocolUDP
	binary.BigEndian.PutUint16(p[10:12], uint16(length))
	return sum(0, p[:])
}

// sum adds b to initial in ones-complement arithmetic, 16 bits at a time
// (RFC 1071).
func sum(initial uint16, b []byte) uint16 {
	s := uint32(initial)
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return uint16(s)
}
