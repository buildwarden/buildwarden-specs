package relay

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// TunnelURL is the collector_url that selects the tunnel (CLAIM-22).
const TunnelURL = "http://collector.tunnel"

// MaxClaim is the largest claim body the relay reads (CLAIM-52).
const MaxClaim = 16 << 20

// The capture modes of CLAIM-25.
const (
	CaptureNone    = "none"
	CaptureHeaders = "headers"
	CaptureBodies  = "bodies"
	CaptureAll     = "all"
)

// Claim is a claim the relay decoded and found valid, field by field
// (relay-claim, Messages and fields).
type Claim struct {
	CollectorURL   string
	CollectorToken string
	// CaptureMode is one of the four modes; an empty or absent field is
	// CaptureNone.
	CaptureMode string
	// Roots are the certificates of upstream_ca_certs, and SystemRoots
	// whether the system's roots are trusted beside them (CLAIM-26,
	// CLAIM-27).
	Roots       []*x509.Certificate
	SystemRoots bool
	// Environment is nil for a claim that carries none. Its fields are as
	// sent: whether they can be used is found at the start (CLAIM-28).
	Environment *Environment
	// BuildLink is nil for a claim that carries none.
	BuildLink *BuildLink
	// UpstreamDNS is the claim's list, or nil when it has none; Resolvers
	// are the servers the relay resolves through (CLAIM-31, CLAIM-32).
	UpstreamDNS []netip.Addr
	Resolvers   []netip.Addr
}

// Tunnel says whether the claim selects the tunnel.
func (c *Claim) Tunnel() bool { return c.CollectorURL == TunnelURL }

// Environment is the claim's environment, its byte strings decoded.
type Environment struct {
	Type     string
	Payload  []byte
	Metadata []byte
}

// BuildLink is the claim's build_link.
type BuildLink struct {
	Prefix netip.Prefix
	Relay  netip.Addr
	Guest  netip.Addr
}

// refusal is a claim answered 400, which leaves the relay claimable: its
// text is the whole body's reason, "invalid claim: ..." or
// "claim refused: ...".
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

func invalid(format string, a ...any) error {
	return &refusal{"invalid claim: " + fmt.Sprintf(format, a...)}
}

// Refused is the error a Build returns from Configure for a claim its mode
// cannot apply: the claim is answered 400 with "claim refused: " and the
// reason, and the relay stays claimable (CLAIM-48, CLAIM-49).
func Refused(format string, a ...any) error {
	return &refusal{"claim refused: " + fmt.Sprintf(format, a...)}
}

// member is one member of a JSON object, as it was sent.
type member struct {
	name  string
	value json.RawMessage
}

// object reads b as one JSON object and nothing after it, and returns its
// members. Where relay-claim lets a relay be lenient, this one is not: a
// member whose name is a field's in another case, a member named twice, a
// member whose value is null, and anything after the object are each
// refused, because a claimant sends none of them (CLAIM-17, CLAIM-18). A
// member whose name is no field is refused with the reason CLAIM-19 gives.
func object(b []byte, where string, fields []string) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, invalid("%snot JSON: %v", where, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, invalid("%snot a JSON object", where)
	}
	var out []member
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, invalid("%snot JSON: %v", where, err)
		}
		name, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, invalid("%snot JSON: %v", where, err)
		}
		i := slices.IndexFunc(fields, func(f string) bool { return strings.EqualFold(f, name) })
		switch {
		case i < 0:
			return nil, invalid("%sunknown field %q", where, name)
		case fields[i] != name:
			return nil, invalid("%sthe member %q is the field %q in another case", where, name, fields[i])
		case seen[name]:
			return nil, invalid("%sthe member %q is given twice", where, name)
		case string(v) == "null":
			return nil, invalid("%sthe member %q is null", where, name)
		}
		seen[name] = true
		out = append(out, member{name, v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, invalid("%snot JSON: %v", where, err)
	}
	if where == "" {
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return nil, invalid("the body has more after its object")
		}
	}
	return out, nil
}

func text(m member, where string) (string, error) {
	var s string
	if err := json.Unmarshal(m.value, &s); err != nil {
		return "", invalid("%s%s is not a string", where, m.name)
	}
	return s, nil
}

func texts(m member, where string) ([]string, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(m.value, &raw); err != nil {
		return nil, invalid("%s%s is not an array of strings", where, m.name)
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		var s string
		if string(r) == "null" || json.Unmarshal(r, &s) != nil {
			return nil, invalid("%s%s is not an array of strings", where, m.name)
		}
		out = append(out, s)
	}
	return out, nil
}

// bytesField decodes a byte string in standard base64 with padding, and
// refuses the line breaks Go's decoder would skip.
func bytesField(m member, where string) ([]byte, error) {
	s, err := text(m, where)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(s, "\r\n") {
		return nil, invalid("%s%s is not base64: it has a line break", where, m.name)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, invalid("%s%s is not base64: %v", where, m.name, err)
	}
	return b, nil
}

var (
	claimFields       = []string{"collector_url", "collector_token", "capture_mode", "upstream_ca_certs", "upstream_system_ca", "environment", "build_link", "upstream_dns"}
	environmentFields = []string{"type", "payload", "metadata"}
	buildLinkFields   = []string{"prefix", "relay", "guest"}
)

// decode reads a claim's body and checks every rule of relay-claim that is
// answered 400 "invalid claim: ..." (CLAIM-18 to CLAIM-30), in the order of
// the field table. tunnel says whether the relay has accepted a tunnel.
func decode(body []byte, tunnel bool) (*Claim, error) {
	if len(body) > MaxClaim {
		return nil, invalid("the body is over %d bytes", MaxClaim)
	}
	members, err := object(body, "", claimFields)
	if err != nil {
		return nil, err
	}
	c := &Claim{CaptureMode: CaptureNone, SystemRoots: true}
	var link, dns *member
	systemCA := true
	for i := range members {
		m := members[i]
		switch m.name {
		case "collector_url":
			c.CollectorURL, err = text(m, "")
		case "collector_token":
			c.CollectorToken, err = text(m, "")
		case "capture_mode":
			c.CaptureMode, err = text(m, "")
		case "upstream_ca_certs":
			var entries []string
			if entries, err = texts(m, ""); err == nil {
				c.Roots, err = roots(entries)
			}
		case "upstream_system_ca":
			if json.Unmarshal(m.value, &systemCA) != nil {
				err = invalid("upstream_system_ca is not a boolean")
			}
		case "environment":
			c.Environment, err = environment(m)
		case "build_link":
			link = &members[i]
		case "upstream_dns":
			dns = &members[i]
		}
		if err != nil {
			return nil, err
		}
	}
	// What the claim says of the system's roots matters only beside roots
	// of its own (CLAIM-27).
	c.SystemRoots = systemCA || len(c.Roots) == 0
	switch c.CaptureMode {
	case "", CaptureNone:
		c.CaptureMode = CaptureNone
	case CaptureHeaders, CaptureBodies, CaptureAll:
	default:
		// The Go relay accepts any other value and captures nothing (D5);
		// this one refuses it, a value that cannot be used.
		return nil, invalid("capture_mode %q is none of headers, bodies, all and none", c.CaptureMode)
	}
	if link != nil {
		if c.BuildLink, err = buildLink(*link); err != nil {
			return nil, err
		}
	}
	if dns != nil {
		if c.UpstreamDNS, err = upstreamDNS(*dns, c.BuildLink); err != nil {
			return nil, err
		}
	}
	if c.CollectorURL == "" {
		return nil, invalid("collector_url is required")
	}
	if c.Tunnel() && !tunnel {
		return nil, invalid("collector_url selects the tunnel, but none is open")
	}
	return c, nil
}

// roots reads upstream_ca_certs. An entry that holds no PEM certificate is
// refused: the Go relay ignores it (D5), a value that cannot be used.
func roots(entries []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for i, e := range entries {
		rest := []byte(e)
		n := 0
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, invalid("upstream_ca_certs[%d]: %v", i, err)
			}
			out = append(out, cert)
			n++
		}
		if n == 0 {
			return nil, invalid("upstream_ca_certs[%d] holds no PEM certificate", i)
		}
	}
	return out, nil
}

func environment(m member) (*Environment, error) {
	members, err := object(m.value, "environment: ", environmentFields)
	if err != nil {
		return nil, err
	}
	env := &Environment{}
	for _, e := range members {
		switch e.name {
		case "type":
			env.Type, err = text(e, "environment.")
		case "payload":
			env.Payload, err = bytesField(e, "environment.")
		case "metadata":
			env.Metadata, err = bytesField(e, "environment.")
		}
		if err != nil {
			return nil, err
		}
	}
	return env, nil
}

// buildLink checks CLAIM-29's rules, whatever the relay's mode.
func buildLink(m member) (*BuildLink, error) {
	members, err := object(m.value, "build_link: ", buildLinkFields)
	if err != nil {
		return nil, err
	}
	bad := func(format string, a ...any) error {
		return invalid("build_link: "+format, a...)
	}
	values := map[string]string{}
	for _, e := range members {
		if values[e.name], err = text(e, "build_link: "); err != nil {
			return nil, err
		}
	}
	for _, f := range buildLinkFields {
		if values[f] == "" {
			return nil, bad("%s is required", f)
		}
	}
	prefix, err := netip.ParsePrefix(values["prefix"])
	if err != nil {
		return nil, bad("prefix %q is not a network in CIDR form", values["prefix"])
	}
	link := &BuildLink{Prefix: prefix}
	for _, f := range []struct {
		name string
		to   *netip.Addr
	}{{"relay", &link.Relay}, {"guest", &link.Guest}} {
		a, err := netip.ParseAddr(values[f.name])
		if err != nil {
			return nil, bad("%s %q is not an address", f.name, values[f.name])
		}
		*f.to = a
	}
	for _, a := range []netip.Addr{prefix.Addr(), link.Relay, link.Guest} {
		if !a.Is4() {
			return nil, bad("%s is not an IPv4 address", a)
		}
		if reserved(a) {
			return nil, bad("%s is in a range a build link may not use", a)
		}
	}
	if prefix.Masked() != prefix {
		return nil, bad("prefix %s is not its own network address", prefix)
	}
	if prefix.Bits() < 8 || prefix.Bits() > 30 {
		return nil, bad("prefix %s is not from /8 to /30", prefix)
	}
	broadcast := lastAddr(prefix)
	for _, f := range []struct {
		name string
		a    netip.Addr
	}{{"relay", link.Relay}, {"guest", link.Guest}} {
		if !prefix.Contains(f.a) || f.a == prefix.Addr() || f.a == broadcast {
			return nil, bad("%s %s is not a host address of %s", f.name, f.a, prefix)
		}
	}
	if link.Relay == link.Guest {
		return nil, bad("relay and guest are the same address")
	}
	return link, nil
}

// reserved is 0.0.0.0/8, loopback, link-local, multicast and class E.
func reserved(a netip.Addr) bool {
	b := a.As4()
	return b[0] == 0 || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || b[0] >= 240
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// upstreamDNS checks CLAIM-30's rules, whatever the relay's mode.
func upstreamDNS(m member, link *BuildLink) ([]netip.Addr, error) {
	entries, err := texts(m, "upstream_dns: ")
	if err != nil {
		return nil, invalid("upstream_dns: not an array of strings")
	}
	if len(entries) == 0 {
		return nil, invalid("upstream_dns: the list is empty")
	}
	out := make([]netip.Addr, 0, len(entries))
	for _, e := range entries {
		a, err := netip.ParseAddr(e)
		switch {
		case err != nil:
			return nil, invalid("upstream_dns: %q is not an address written without a port", e)
		case !a.Is4():
			return nil, invalid("upstream_dns: %s is not an IPv4 address", a)
		case a.IsUnspecified(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			return nil, invalid("upstream_dns: %s is not the address of a resolver", a)
		case link != nil && link.Prefix.Contains(a):
			return nil, invalid("upstream_dns: %s is inside the build link %s", a, link.Prefix)
		}
		out = append(out, a)
	}
	return out, nil
}

// resolvers are the claim's servers when it names them, and otherwise the
// nameservers of the configuration the relay was started with, less
// 127.0.0.1, the relay's own addresses and any address in its build link
// (CLAIM-31, CLAIM-32).
func resolvers(c *Claim, conf []netip.Addr, own []netip.Addr) ([]netip.Addr, error) {
	if c.UpstreamDNS != nil {
		return c.UpstreamDNS, nil
	}
	if conf == nil {
		return nil, Refused("upstream_dns is absent and the relay has no resolver configuration")
	}
	var out []netip.Addr
	for _, a := range conf {
		switch {
		case a == netip.AddrFrom4([4]byte{127, 0, 0, 1}), slices.Contains(own, a):
		case c.BuildLink != nil && c.BuildLink.Prefix.Contains(a):
		default:
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, Refused("upstream_dns is absent and the relay's resolver configuration names no usable nameserver")
	}
	return out, nil
}
