package sandbox

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The tests are tier 0: none creates a namespace or a link, or starts a
// process. What does is run by hand as root (stage 6) and by the relay
// targets in buildwarden/buildwarden's conformance workflow.

func TestUpstreamLinks(t *testing.T) {
	seen := map[netip.Addr]int{}
	for s := range Slots {
		relay, harness := Upstream(s)
		if relay.Bits() != 30 || harness.Bits() != 30 || relay.Masked() != harness.Masked() {
			t.Fatalf("slot %d: %v and %v are not one /30", s, relay, harness)
		}
		if !LinkRange.Contains(relay.Addr()) || !LinkRange.Contains(harness.Addr()) {
			t.Fatalf("slot %d: %v or %v is outside %v", s, relay, harness, LinkRange)
		}
		for _, a := range []netip.Addr{relay.Addr(), harness.Addr()} {
			if o, ok := seen[a]; ok {
				t.Fatalf("slots %d and %d both have %v", o, s, a)
			}
			seen[a] = s
		}
		if c := Claim(s); c.Addr() != relay.Addr() || c.Port() != ClaimPort {
			t.Errorf("slot %d: claim endpoint %v, want %v:%d", s, c, relay.Addr(), ClaimPort)
		}
	}
	if r, h := Upstream(0); r.String() != "100.64.0.1/30" || h.String() != "100.64.0.2/30" {
		t.Errorf("slot 0: %v, %v", r, h)
	}
	if r, h := Upstream(Slots - 1); r.String() != "100.64.0.253/30" || h.String() != "100.64.0.254/30" {
		t.Errorf("the last slot: %v, %v", r, h)
	}
}

// TestRanges checks that the parts of the plan do not meet: the harness's
// ranges are the documentation ranges every upstream server is in, and no
// link, build address or pre-claim address is in them.
func TestRanges(t *testing.T) {
	if len(HarnessRanges) != len(upstream.DocumentationRanges) {
		t.Fatalf("HarnessRanges %v, want the documentation ranges %v", HarnessRanges, upstream.DocumentationRanges)
	}
	if err := upstream.CheckAddress(UpstreamHarness); err != nil {
		t.Error(err)
	}
	if !strings.Contains(ResolvConf, "nameserver "+UpstreamHarness.String()+"\n") {
		t.Errorf("ResolvConf %q does not name %v", ResolvConf, UpstreamHarness)
	}
	for _, p := range []netip.Prefix{LinkRange, LauncherRelay.Masked(), PreClaim.Masked()} {
		for _, h := range HarnessRanges {
			if p.Overlaps(h) {
				t.Errorf("%v overlaps the harness's %v", p, h)
			}
		}
	}
	if LinkRange.Overlaps(LauncherRelay.Masked()) || LinkRange.Overlaps(PreClaim.Masked()) || LauncherRelay.Masked().Overlaps(PreClaim.Masked()) {
		t.Errorf("the link range, the launcher's build link and the pre-claim address meet")
	}
	if LauncherRelay.Masked() != LauncherHarness.Masked() {
		t.Errorf("%v and %v are not on one link", LauncherRelay, LauncherHarness)
	}
}

func TestBuildLink(t *testing.T) {
	link := func(p, r, g string) *target.BuildLink { return &target.BuildLink{Prefix: p, Relay: r, Guest: g} }
	tests := []struct {
		name    string
		r       target.Relay
		want    Link
		wantErr string
	}{
		{name: "frames", r: target.Relay{Link: "frames", BuildLink: link("10.100.0.0/30", "10.100.0.1", "10.100.0.2")}, want: Link{Kind: "frames"}},
		{
			name: "ip with a build_link", r: target.Relay{Link: "ip", BuildLink: link("10.100.0.0/30", "10.100.0.1", "10.100.0.2")},
			want: Link{Kind: "ip", Relay: PreClaim, Harness: netip.MustParsePrefix("10.100.0.2/30")},
		},
		{name: "ip by the launcher", r: target.Relay{Link: "ip", AddressByLauncher: true}, want: Link{Kind: "ip", Relay: LauncherRelay, Harness: LauncherHarness}},
		{name: "frames by the launcher", r: target.Relay{Link: "frames", AddressByLauncher: true}, wantErr: "a relay on a frames link takes its address from the claim's build_link"},
		{name: "in a documentation range", r: target.Relay{Link: "ip", BuildLink: link("192.0.2.0/30", "192.0.2.1", "192.0.2.2")}, wantErr: "relay.build_link 192.0.2.0/30 overlaps 192.0.2.0/24, which the sandbox uses"},
		{name: "around a documentation range", r: target.Relay{Link: "frames", BuildLink: link("203.0.0.0/16", "203.0.0.1", "203.0.0.2")}, wantErr: "overlaps 203.0.113.0/24"},
		{name: "in the link range", r: target.Relay{Link: "ip", BuildLink: link("100.64.0.0/30", "100.64.0.1", "100.64.0.2")}, wantErr: "overlaps 100.64.0.0/24"},
		{name: "on the pre-claim address", r: target.Relay{Link: "ip", BuildLink: link("10.0.2.0/30", "10.0.2.1", "10.0.2.2")}, wantErr: "overlaps 10.0.2.0/24"},
		{name: "an unknown kind", r: target.Relay{Link: "vsock"}, wantErr: `relay.link "vsock" is none of frames, ip`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildLink(&tt.r)
			switch {
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			case got != tt.want:
				t.Errorf("BuildLink = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNames(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range []struct{ pid, id int }{{1, 1}, {1, 2}, {2, 1}, {4194304, 1}, {4194304, 0xfffff}, {12, 34}} {
		n := NamesFor(c.pid, c.id)
		for _, name := range []string{n.Build, n.Upstream} {
			if len(name) > 15 {
				t.Errorf("%q is longer than an interface name may be", name)
			}
			if seen[name] {
				t.Errorf("%q is the name of two links", name)
			}
			seen[name] = true
		}
		// A vm-mode relay takes the first interface but lo in sorted
		// order as its build interface.
		if n.Build >= n.Upstream {
			t.Errorf("%q does not sort before %q", n.Build, n.Upstream)
		}
		if seen[n.Container] {
			t.Errorf("%q is the name of two containers", n.Container)
		}
		seen[n.Container] = true
	}
	if n := NamesFor(12, 34); n.Container != "bw-conformance-12-34" || n.Build != "bwbc-22" || n.Upstream != "bwuc-22" {
		t.Errorf("NamesFor(12, 34) = %+v", n)
	}
}

func TestBook(t *testing.T) {
	var b book[string]
	if _, ok := b.newest(); ok {
		t.Fatal("an empty book has a newest instance")
	}
	s0, id0, _ := b.take()
	s1, id1, _ := b.take()
	if s0 != 0 || s1 != 1 || id0 == id1 {
		t.Fatalf("slots %d and %d, ids %d and %d", s0, s1, id0, id1)
	}
	b.add("a")
	b.add("b")
	if n, _ := b.newest(); n != "b" {
		t.Errorf("newest %q, want b", n)
	}
	b.release("b", s1)
	if n, _ := b.newest(); n != "a" {
		t.Errorf("newest after b's release %q, want a", n)
	}
	// The lowest free slot is taken first, and an instance number is
	// never given twice.
	s, id, _ := b.take()
	if s != 1 || id == id0 || id == id1 {
		t.Errorf("slot %d id %d after a release, want slot 1 and a new id", s, id)
	}
	b.add("c")
	b.release("a", s0)
	if n, _ := b.newest(); n != "c" {
		t.Errorf("newest %q, want c", n)
	}
	for range Slots - 1 {
		if _, _, err := b.take(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := b.take(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("holds %d instances already", Slots)) {
		t.Errorf("a take past the last slot: %v", err)
	}
}

func TestBookConcurrent(t *testing.T) {
	var b book[int]
	var mu sync.Mutex
	var slots []int
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			s, _, err := b.take()
			if err != nil {
				t.Error(err)
				return
			}
			b.add(i)
			mu.Lock()
			slots = append(slots, s)
			mu.Unlock()
		})
	}
	wg.Wait()
	sort.Ints(slots)
	for i, s := range slots {
		if s != i {
			t.Fatalf("slots %v, want 0 to 31 once each", slots)
		}
	}
}

// procLine is a line of /proc/net/tcp or tcp6 for a socket at a:port in
// state st, its address written as the kernel writes it: 32-bit words in
// hexadecimal, each in the host's byte order.
func procLine(a netip.Addr, port uint16, st string) string {
	b := a.AsSlice()
	var w strings.Builder
	for i := 0; i < len(b); i += 4 {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], binary.NativeEndian.Uint32(b[i:]))
		w.WriteString(strings.ToUpper(hex.EncodeToString(x[:])))
	}
	zero := strings.Repeat("0", len(b)*2)
	return fmt.Sprintf("   0: %s:%04X %s:0000 %s 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0", w.String(), port, zero, st)
}

func TestListening(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	claim := netip.MustParseAddr("100.64.0.1")
	other := netip.MustParseAddr("100.64.0.5")
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{name: "on the address", lines: []string{procLine(claim, 8301, "0A")}, want: true},
		{name: "on every IPv4 address", lines: []string{procLine(netip.IPv4Unspecified(), 8301, "0A")}, want: true},
		{name: "on every address, tcp6", lines: []string{procLine(netip.IPv6Unspecified(), 8301, "0A")}, want: true},
		{name: "on the address, mapped", lines: []string{procLine(netip.AddrFrom16(claim.As16()), 8301, "0A")}, want: true},
		{name: "another port", lines: []string{procLine(claim, 8300, "0A")}},
		{name: "another address", lines: []string{procLine(other, 8301, "0A")}},
		{name: "a connection, not a listener", lines: []string{procLine(claim, 8301, "01")}},
		{name: "among others", lines: []string{procLine(claim, 80, "0A"), procLine(claim, 8301, "06"), procLine(claim, 8301, "0A")}, want: true},
		{name: "nothing", lines: nil},
		{name: "a line that is not one", lines: []string{"   0: zz:20AD 00000000:0000 0A", "   1: 0100:20AD 00000000:0000 0A", "garbage"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := header + "\n" + strings.Join(tt.lines, "\n") + "\n"
			if got := listening(table, claim, 8301); got != tt.want {
				t.Errorf("listening = %v, want %v, in\n%s", got, tt.want, table)
			}
		})
	}
}

func TestProbe(t *testing.T) {
	refused := errors.New("unshare: operation not permitted")
	ok := func() error { return nil }
	no := func() error { return refused }
	tests := []struct {
		name     string
		p        Probe
		launcher string
		wantErr  string
	}{
		{name: "root", p: Probe{Euid: 0, NetNS: ok}, launcher: "exec"},
		{name: "root, oci", p: Probe{Euid: 0, NetNS: ok}, launcher: "oci"},
		{name: "in its own user namespace", p: Probe{Euid: 0, InUserNS: true, NetNS: ok}, launcher: "exec"},
		{
			name: "root without the capabilities", p: Probe{Euid: 0, NetNS: no}, launcher: "exec",
			wantErr: "this process runs as root, and creating a network namespace failed (unshare: operation not permitted); it needs CAP_SYS_ADMIN and CAP_NET_ADMIN",
		},
		{
			name: "a restricted user namespace", p: Probe{Euid: 0, InUserNS: true, NetNS: no}, launcher: "exec",
			wantErr: "re-ran itself in a user namespace of its own, and creating a network namespace there failed (unshare: operation not permitted); the host restricts what an unprivileged user namespace may do, so run as root",
		},
		{
			name: "a user, not re-run", p: Probe{Euid: 1000, NetNS: no}, launcher: "exec",
			wantErr: "this process runs as uid 1000, not in a user namespace of its own, and creating a network namespace failed",
		},
		{name: "oci as a user", p: Probe{Euid: 1000, NetNS: ok}, launcher: "oci", wantErr: "the oci launcher needs root"},
		{name: "oci in a user namespace", p: Probe{Euid: 0, InUserNS: true, NetNS: ok}, launcher: "oci", wantErr: "runs as uid 0 in a user namespace of its own"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.check(tt.launcher)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatal(err)
			case tt.wantErr == "":
			case err == nil || !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
			case !errors.Is(err, ErrPrivilege) || !strings.HasPrefix(err.Error(), ErrPrivilege.Error()+": "):
				t.Errorf("error %v does not start with ErrPrivilege's text", err)
			}
		})
	}
}

func TestReexecs(t *testing.T) {
	relay := func(launcher string) target.File { return target.File{Role: "relay", Launcher: launcher} }
	tests := []struct {
		name     string
		f        target.File
		euid     int
		inUserNS bool
		want     bool
	}{
		{name: "an exec relay as a user", f: relay("exec"), euid: 1000, want: true},
		{name: "an exec relay as root", f: relay("exec"), euid: 0},
		{name: "the re-run command", f: relay("exec"), euid: 0, inUserNS: true},
		{name: "the re-run command, mapped otherwise", f: relay("exec"), euid: 1000, inUserNS: true},
		{name: "an oci relay as a user", f: relay("oci"), euid: 1000},
		{name: "an external relay", f: relay("external"), euid: 1000},
		{name: "a collector", f: target.File{Role: "collector", Launcher: "exec"}, euid: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reexecs(tt.f, tt.euid, tt.inUserNS); got != tt.want {
				t.Errorf("reexecs = %v, want %v", got, tt.want)
			}
		})
	}
}
