package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// fake is an attachment whose instances are records of their starts.
type fake struct {
	d        target.Declared
	mu       sync.Mutex
	starts   []attach.Params
	stopped  int
	closed   bool
	startErr error
}

type fakeInstance struct {
	f   *fake
	n   int
	end string
}

func (f *fake) Declared() target.Declared { return f.d }

func (f *fake) Network(s attach.Side) (attach.Network, error) {
	if s != attach.Claim {
		return nil, attach.ErrNoSide
	}
	return attach.Host(netip.MustParseAddr("127.0.0.1")), nil
}

func (f *fake) Start(_ context.Context, p attach.Params) (attach.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.starts = append(f.starts, p)
	return &fakeInstance{f: f, n: len(f.starts)}, nil
}

func (f *fake) Close() error { f.closed = true; return nil }

func (i *fakeInstance) Claim() attach.Endpoint {
	return attach.Endpoint{Address: fmt.Sprintf("127.0.0.1:%d", 4000+i.n)}
}
func (i *fakeInstance) ReadBack(context.Context) (string, error) { return "", errors.New("none") }
func (i *fakeInstance) Log() []byte                              { return []byte(fmt.Sprintf("instance %d wrote this\n", i.n)) }
func (i *fakeInstance) Exit() string                             { return i.end }
func (i *fakeInstance) Stop() error {
	i.f.mu.Lock()
	i.f.stopped++
	i.f.mu.Unlock()
	i.end = "stopped"
	return nil
}

func relay(fresh bool) *fake {
	return &fake{d: target.Declared{Role: "relay", Launcher: "exec", Mode: "host", FreshInstances: fresh}}
}

var runner = Runner{Spec: "relay-claim", Version: "v0.1.0", Harness: "v0.1.0", Models: []string{"relay-claim v0.1.0"}}

func TestRun(t *testing.T) {
	var ranOther bool
	cases := []Case{
		{Name: "passes", Cites: []string{"CLAIM-1"}, Role: "relay", Run: func(t *T) {
			in := t.Instance(attach.Params{})
			if in.Claim().Address == "" {
				t.Errorf("no claim endpoint")
			}
		}},
		{Name: "fails", Cites: []string{"CLAIM-2", "CLAIM-3"}, Role: "relay", Run: func(t *T) {
			t.Instance(attach.Params{})
			t.Logf("asked for %s", "a claim")
			t.Errorf("first failure")
			t.Errorf("second\nfailure")
		}},
		{Name: "fatal", Cites: []string{"CLAIM-4"}, Role: "relay", Run: func(t *T) {
			t.Fatalf("stops here")
			t.Errorf("never reached")
		}},
		{Name: "panics", Cites: []string{"CLAIM-5"}, Role: "relay", Run: func(t *T) { panic("boom") }},
		{Name: "not in host mode", Cites: []string{"CLAIM-6"}, Role: "relay",
			Applies: func(d target.Declared) string {
				if d.Mode == "host" {
					return "a host-mode relay has no build interface"
				}
				return ""
			},
			Run: func(t *T) { t.Errorf("ran a case that does not apply") }},
		{Name: "a collector's", Cites: []string{"CLAIM-7"}, Role: "collector", Run: func(t *T) { ranOther = true }},
	}
	a := relay(true)
	rep := runner.Run(context.Background(), "relay-host.toml", a, cases)
	if ranOther {
		t.Error("ran a case of another role")
	}
	if !a.closed {
		t.Error("the attachment was not closed")
	}
	if len(a.starts) != 1 || a.stopped != 1 {
		t.Errorf("%d starts and %d stops, want one shared instance started and stopped", len(a.starts), a.stopped)
	}
	var out bytes.Buffer
	if err := rep.Write(&out); err != nil {
		t.Fatal(err)
	}
	want := "relay-claim v0.1.0, conformance v0.1.0, against relay-host.toml (relay, exec)\n" +
		"models written from: relay-claim v0.1.0\n" +
		"pass\trelay-claim v0.1.0\tconformance v0.1.0\tpasses\tCLAIM-1\n" +
		"fail\trelay-claim v0.1.0\tconformance v0.1.0\tfails\tCLAIM-2 CLAIM-3\n" +
		"\tfirst failure\n" +
		"\tsecond\n\tfailure\n" +
		"\tlog: asked for a claim\n" +
		"\tinstance 1 (running when the case ended), its output:\n\tinstance 1 wrote this\n" +
		"fail\trelay-claim v0.1.0\tconformance v0.1.0\tfatal\tCLAIM-4\n" +
		"\tstops here\n" +
		"fail\trelay-claim v0.1.0\tconformance v0.1.0\tpanics\tCLAIM-5\n" +
		"\tthe case panicked: boom\n" +
		"n/a\trelay-claim v0.1.0\tconformance v0.1.0\tnot in host mode\tCLAIM-6\tnot applicable: a host-mode relay has no build interface\n" +
		"relay-claim v0.1.0, conformance v0.1.0, against relay-host.toml: 1 passed, 3 failed, 1 not applicable\n"
	if out.String() != want {
		t.Errorf("report:\n%s\nwant:\n%s", out.String(), want)
	}
	if !rep.Failed() {
		t.Error("a report with failures has not failed")
	}
}

func TestInstances(t *testing.T) {
	tokenless := attach.Params{NoClaimToken: true}
	var seen []string
	use := func(p attach.Params) func(t *T) {
		return func(t *T) { seen = append(seen, t.Instance(p).Claim().Address) }
	}
	cases := []Case{
		{Name: "shares", Role: "relay", Run: use(attach.Params{})},
		{Name: "ends", Role: "relay", Ends: true, Run: use(attach.Params{})},
		{Name: "shares again", Role: "relay", Run: use(attach.Params{})},
		{Name: "shares another start", Role: "relay", Run: use(tokenless)},
		{Name: "ends again", Role: "relay", Ends: true, Run: func(t *T) {
			use(attach.Params{})(t)
			use(attach.Params{})(t)
		}},
	}
	a := relay(true)
	rep := runner.Run(context.Background(), "t", a, cases)
	if rep.Failed() {
		t.Fatalf("failed: %+v", rep)
	}
	want := []string{"127.0.0.1:4001", "127.0.0.1:4002", "127.0.0.1:4001", "127.0.0.1:4003", "127.0.0.1:4004", "127.0.0.1:4005"}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Errorf("instances %q, want %q", seen, want)
	}
	if a.stopped != 5 {
		t.Errorf("%d instances stopped, want 5", a.stopped)
	}

	one := relay(false)
	seen = nil
	rep = runner.Run(context.Background(), "t", one, cases)
	_, failed, na := rep.Counts()
	if failed != 0 || na != 2 {
		t.Errorf("one instance: %d failed and %d not applicable, want 0 and 2", failed, na)
	}
	if rep.Cases[1].Reason != "the target is one instance, and the case ends the instance it runs against" {
		t.Errorf("reason %q", rep.Cases[1].Reason)
	}
}

func TestStartFailure(t *testing.T) {
	a := relay(true)
	a.startErr = errors.New("no relay binary")
	rep := runner.Run(context.Background(), "t", a, []Case{{Name: "c", Role: "relay", Run: func(t *T) {
		t.Instance(attach.Params{})
		t.Errorf("went on after the start failed")
	}}})
	if got := rep.Cases[0].Failures; len(got) != 1 || got[0] != "starting the component under test: no relay binary" {
		t.Errorf("failures %q", got)
	}
}

func TestNetwork(t *testing.T) {
	rep := runner.Run(context.Background(), "t", relay(true), []Case{{Name: "c", Role: "relay", Run: func(t *T) {
		if t.Network(attach.Claim).Address().String() != "127.0.0.1" {
			t.Errorf("claim side")
		}
		t.Network(attach.Build)
	}}})
	if got := rep.Cases[0].Failures; len(got) != 1 || !strings.HasPrefix(got[0], "the build side: ") {
		t.Errorf("failures %q", got)
	}
}

func TestCleanupAndTempDir(t *testing.T) {
	var order []string
	var dir string
	rep := runner.Run(context.Background(), "t", relay(true), []Case{{Name: "c", Role: "relay", Run: func(t *T) {
		dir = t.TempDir()
		t.Cleanup(func() { order = append(order, "first") })
		t.Cleanup(func() { order = append(order, "second") })
		t.Cleanup(func() { panic("in a cleanup") })
	}}})
	if strings.Join(order, " ") != "second first" {
		t.Errorf("cleanups ran as %q", order)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary directory is left: %v", err)
	}
	if got := rep.Cases[0].Failures; len(got) != 1 || got[0] != "a cleanup panicked: in a cleanup" {
		t.Errorf("failures %q", got)
	}
}

func TestTimeLimit(t *testing.T) {
	r := runner
	r.Limit = 20 * time.Millisecond
	rep := r.Run(context.Background(), "t", relay(true), []Case{
		{Name: "returns at its limit", Role: "relay", Run: func(t *T) { <-t.Context().Done() }},
		{Name: "within its limit", Role: "relay", Run: func(t *T) {}},
	})
	if got := rep.Cases[0].Failures; len(got) != 1 || got[0] != "the case ran past its time limit of 20ms" {
		t.Errorf("failures %q", got)
	}
	if rep.Cases[1].Result != Pass {
		t.Errorf("the next case: %v", rep.Cases[1].Result)
	}
}

func TestNoCases(t *testing.T) {
	rep := Runner{Spec: "relay-claim", Version: "v0.1.0", Harness: "v0.1.0"}.Run(context.Background(), "collector-disk.toml",
		&fake{d: target.Declared{Role: "collector", Launcher: "exec"}},
		[]Case{{Name: "relay only", Role: "relay", Run: func(*T) {}}})
	var out bytes.Buffer
	if err := rep.Write(&out); err != nil {
		t.Fatal(err)
	}
	want := "relay-claim v0.1.0, conformance v0.1.0, against collector-disk.toml (collector, exec)\n" +
		"models written from: none yet\n" +
		"the suite has no cases for a collector target; nothing was run\n" +
		"relay-claim v0.1.0, conformance v0.1.0, against collector-disk.toml: 0 passed, 0 failed, 0 not applicable\n"
	if out.String() != want {
		t.Errorf("report:\n%s\nwant:\n%s", out.String(), want)
	}
	if rep.Failed() {
		t.Error("a run with no cases has failed")
	}
}

func TestCheck(t *testing.T) {
	run := func(*T) {}
	if err := Check([]Case{{Name: "a", Role: "relay", Run: run}, {Name: "b", Role: "collector", Run: run}}); err != nil {
		t.Fatal(err)
	}
	err := Check([]Case{
		{Role: "relay", Run: run},
		{Name: "a", Role: "relay", Run: run},
		{Name: "a", Role: "driver", Run: run},
		{Name: "b", Role: "relay"},
	})
	for _, want := range []string{
		"case 1 has no name",
		`two cases are named "a"`,
		`case "a": role "driver" is not one this harness knows ([relay collector])`,
		`case "b" has nothing to run`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not contain %q", err, want)
		}
	}
}
