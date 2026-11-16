// Package dhcp is the build environment's side of the address lease that
// relay-guest-api states (The address lease): the DHCP message format of
// RFC 2131 and RFC 2132, as far as the lease uses it, and a client that
// takes a lease, on a frame link before the build environment has a network
// stack, or over a datagram endpoint where the link is a kernel interface or
// the in-memory network.
//
// The client keeps to what the specification asks of a build environment
// and no more: DISCOVER, then REQUEST for what the OFFER gave, both
// broadcast; a NAK, or an ACK that does not give an address, is a failed
// lease. Each step is sent again every Retransmit until its reply comes or
// the context ends (RFC 2131, section 4.1, has a client retransmit).
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// The ports of the lease.
const (
	ServerPort = 67
	ClientPort = 68
)

// The BOOTP operations.
const (
	BootRequest = 1
	BootReply   = 2
)

// The DHCP message types, option 53's values.
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// The options the lease uses.
const (
	OptPad         = 0
	OptSubnetMask  = 1
	OptRouter      = 3
	OptDNS         = 6
	OptRequestedIP = 50
	OptLeaseTime   = 51
	OptMessageType = 53
	OptServerID    = 54
	OptParams      = 55
	OptEnd         = 255
)

// Sizes of a message.
const (
	// headerLen is the fixed part of a BOOTP message, before the cookie.
	headerLen = 236
	// MinLen is the shortest message: the fixed part and the cookie.
	MinLen = headerLen + 4
	// paddedLen is the length a BOOTP message is padded to (RFC 951).
	paddedLen = 300
)

// Cookie is the magic cookie that opens the options (RFC 2131, section 3).
var Cookie = [4]byte{99, 130, 83, 99}

// Option is one option of a message.
type Option struct {
	Code byte
	Data []byte
}

// Message is a BOOTP message with DHCP options.
type Message struct {
	Op     byte
	HType  byte
	HLen   byte
	Xid    uint32
	Flags  uint16
	Ciaddr netip.Addr
	Yiaddr netip.Addr
	Siaddr netip.Addr
	Giaddr netip.Addr
	// Chaddr is the client's hardware address, the first HLen bytes of the
	// field.
	Chaddr net.HardwareAddr
	// Options are the options in the order they came, without the pad and
	// end options.
	Options []Option
}

// Marshal returns the message's bytes: the fixed part, the cookie, the
// options in their order, the end option, and padding to 300 bytes.
func (m Message) Marshal() []byte {
	b := make([]byte, MinLen, paddedLen)
	b[0], b[1], b[2] = m.Op, m.HType, m.HLen
	binary.BigEndian.PutUint32(b[4:8], m.Xid)
	binary.BigEndian.PutUint16(b[10:12], m.Flags)
	put4(b[12:16], m.Ciaddr)
	put4(b[16:20], m.Yiaddr)
	put4(b[20:24], m.Siaddr)
	put4(b[24:28], m.Giaddr)
	copy(b[28:44], m.Chaddr)
	copy(b[headerLen:MinLen], Cookie[:])
	for _, o := range m.Options {
		b = append(b, o.Code, byte(len(o.Data)))
		b = append(b, o.Data...)
	}
	b = append(b, OptEnd)
	for len(b) < paddedLen {
		b = append(b, OptPad)
	}
	return b
}

func put4(b []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(b, v[:])
	}
}

// Errors Parse returns, for the messages GUEST-11 has a relay ignore.
var (
	ErrShort     = errors.New("dhcp: a message shorter than 240 bytes")
	ErrNoCookie  = errors.New("dhcp: no magic cookie")
	ErrTruncated = errors.New("dhcp: an option runs past the end of the message")
)

// Parse reads a message. Options after the end option are not read; a
// message whose options run out without one is read to its end.
func Parse(b []byte) (Message, error) {
	if len(b) < MinLen {
		return Message{}, ErrShort
	}
	if [4]byte(b[headerLen:MinLen]) != Cookie {
		return Message{}, ErrNoCookie
	}
	hlen := int(b[2])
	if hlen > 16 {
		return Message{}, fmt.Errorf("dhcp: hardware address length %d is over 16", hlen)
	}
	m := Message{
		Op: b[0], HType: b[1], HLen: b[2],
		Xid:    binary.BigEndian.Uint32(b[4:8]),
		Flags:  binary.BigEndian.Uint16(b[10:12]),
		Ciaddr: netip.AddrFrom4([4]byte(b[12:16])),
		Yiaddr: netip.AddrFrom4([4]byte(b[16:20])),
		Siaddr: netip.AddrFrom4([4]byte(b[20:24])),
		Giaddr: netip.AddrFrom4([4]byte(b[24:28])),
		Chaddr: net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...)),
	}
	for o := b[MinLen:]; len(o) > 0; {
		switch o[0] {
		case OptPad:
			o = o[1:]
			continue
		case OptEnd:
			return m, nil
		}
		if len(o) < 2 || len(o) < 2+int(o[1]) {
			return Message{}, ErrTruncated
		}
		m.Options = append(m.Options, Option{Code: o[0], Data: append([]byte(nil), o[2:2+int(o[1])]...)})
		o = o[2+int(o[1]):]
	}
	return m, nil
}

// Option returns the data of the message's first option with code, and
// whether it has one.
func (m Message) Option(code byte) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Code == code {
			return o.Data, true
		}
	}
	return nil, false
}

// Type returns the message's DHCP type, option 53, or 0 when it has none or
// one that is not one byte.
func (m Message) Type() byte {
	if d, ok := m.Option(OptMessageType); ok && len(d) == 1 {
		return d[0]
	}
	return 0
}

// Addrs reads the data of an option that holds IPv4 addresses (options 1, 3,
// 6, 50 and 54). It reports false for data that is not a whole number of
// them or holds none.
func Addrs(data []byte) ([]netip.Addr, bool) {
	if len(data) == 0 || len(data)%4 != 0 {
		return nil, false
	}
	var as []netip.Addr
	for i := 0; i < len(data); i += 4 {
		as = append(as, netip.AddrFrom4([4]byte(data[i:i+4])))
	}
	return as, true
}
