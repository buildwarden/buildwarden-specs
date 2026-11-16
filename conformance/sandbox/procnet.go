package sandbox

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// listening reports whether table, the text of /proc/<pid>/net/tcp or tcp6,
// lists a socket listening (state 0A) on port at addr, or on the unspecified
// address. It is how a launcher sees that a relay it started serves its claim
// endpoint without connecting to it, which a relay could count as a claimant.
func listening(table string, addr netip.Addr, port uint16) bool {
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		host, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(p, 16, 16)
		if err != nil || uint16(n) != port {
			continue
		}
		a, ok := procAddr(host)
		if ok && (a.IsUnspecified() || a == addr) {
			return true
		}
	}
	return false
}

// procAddr decodes an address of /proc/net/tcp: hexadecimal 32-bit words,
// each in the host's byte order.
func procAddr(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, false
	}
	out := make([]byte, len(b))
	for i := 0; i < len(b); i += 4 {
		binary.NativeEndian.PutUint32(out[i:], binary.BigEndian.Uint32(b[i:]))
	}
	a, _ := netip.AddrFromSlice(out)
	return a.Unmap(), true
}
