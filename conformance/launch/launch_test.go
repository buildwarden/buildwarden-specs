package launch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// helperEnv marks the test binary started as the component under test: it
// then does what its arguments say instead of running the tests.
const helperEnv = "BW_LAUNCH_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "" {
		os.Exit(m.Run())
	}
	args := os.Args[1:]
	// Only the variables the tests set are printed: a platform may add its
	// own to a process's environment (Windows adds SYSTEMROOT).
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "BW_") || strings.HasPrefix(e, "WARDEN_") {
			env = append(env, e)
		}
	}
	slices.Sort(env)
	fmt.Fprintf(os.Stderr, "args: %s\nenv: %s\n", strings.Join(args, " "), strings.Join(env, " "))
	for i, a := range args {
		switch {
		case a == "wait":
			select {}
		case strings.HasPrefix(a, "exit="):
			n, _ := strconv.Atoi(strings.TrimPrefix(a, "exit="))
			os.Exit(n)
		case a == "write" && i+1 < len(args):
			if err := os.WriteFile(filepath.Join(args[i+1], "stored.txt"), []byte("stored"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		case a == "endpoint":
			fmt.Fprint(os.Stdout, "127.0.0.1:4100\nsecond line\n")
		case a == "not-an-endpoint":
			fmt.Fprint(os.Stdout, "relay is ready\n")
		}
	}
	os.Exit(0)
}

// self is the test binary, as a TOML literal string.
func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return "'" + exe + "'"
}

func parse(t *testing.T, text string) target.File {
	t.Helper()
	f, err := target.Parse(filepath.Join(t.TempDir(), "t.toml"), text)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func collectorTarget(t *testing.T, extra, readBack string) target.File {
	return parse(t, `role = "collector"
os = ["linux", "darwin", "windows"]
launcher = "exec"
[exec]
argv = [`+self(t)+`, "--relay", "{claim}", "--dir", "{out}", ["--context", "{context}"], ["--script", "{script}"], "--capture={capture}"`+extra+`]
env = { BW_LAUNCH_HELPER = "1", WARDEN_CLAIM_TOKEN = "{token}" }
[collector]
attachment = "claims"
forms = { no_script = true, no_context = true }
`+readBack)
}

func wait(t *testing.T, in attach.Instance) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for in.Exit() == "" {
		if time.Now().After(deadline) {
			t.Fatal("the component did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExecCollector(t *testing.T) {
	tests := []struct {
		name     string
		extra    string
		params   attach.Params
		wantArgs string
		wantEnv  string
		wantExit string
	}{
		{
			name:     "every placeholder given",
			params:   attach.Params{Claim: "127.0.0.1:9", Token: "tk", Out: "o", Context: "c", Script: "s", Capture: "all"},
			wantArgs: "args: --relay 127.0.0.1:9 --dir o --context c --script s --capture=all\n",
			wantEnv:  "env: BW_LAUNCH_HELPER=1 WARDEN_CLAIM_TOKEN=tk\n",
			wantExit: "exit status 0",
		},
		{
			name:     "no script, no context, no token",
			params:   attach.Params{Claim: "127.0.0.1:9", Out: "o", Capture: "none"},
			wantArgs: "args: --relay 127.0.0.1:9 --dir o --capture=none\n",
			wantEnv:  "env: BW_LAUNCH_HELPER=1\n",
			wantExit: "exit status 0",
		},
		{
			name:     "an exit status is kept",
			extra:    `, "exit=3"`,
			params:   attach.Params{Claim: "127.0.0.1:9", Out: "o", Capture: "none"},
			wantArgs: "args: --relay 127.0.0.1:9 --dir o --capture=none exit=3\n",
			wantEnv:  "env: BW_LAUNCH_HELPER=1\n",
			wantExit: "exit status 3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Attach(collectorTarget(t, tt.extra, ""))
			if err != nil {
				t.Fatal(err)
			}
			in, err := a.Start(context.Background(), tt.params)
			if err != nil {
				t.Fatal(err)
			}
			wait(t, in)
			if err := in.Stop(); err != nil {
				t.Fatal(err)
			}
			if got := string(in.Log()); got != tt.wantArgs+tt.wantEnv {
				t.Errorf("log %q, want %q", got, tt.wantArgs+tt.wantEnv)
			}
			if got := in.Exit(); got != tt.wantExit {
				t.Errorf("exit %q, want %q", got, tt.wantExit)
			}
			if in.Claim() != (attach.Endpoint{}) {
				t.Errorf("a collector has a claim endpoint: %+v", in.Claim())
			}
		})
	}
}

func TestExecCollectorPassEnv(t *testing.T) {
	t.Setenv("BW_LAUNCH_PASSED", "yes")
	t.Setenv("BW_LAUNCH_NOT_PASSED", "no")
	f := collectorTarget(t, "", "")
	f.Exec.PassEnv = []string{"BW_LAUNCH_PASSED", "BW_LAUNCH_UNSET"}
	a, err := Attach(f)
	if err != nil {
		t.Fatal(err)
	}
	in, err := a.Start(context.Background(), attach.Params{Claim: "c:1", Out: "o", Capture: "none"})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, in)
	if got, want := string(in.Log()), "env: BW_LAUNCH_HELPER=1 BW_LAUNCH_PASSED=yes\n"; !strings.HasSuffix(got, want) {
		t.Errorf("log %q, want it to end %q", got, want)
	}
}

func TestExecCollectorStop(t *testing.T) {
	a, err := Attach(collectorTarget(t, `, "wait"`, ""))
	if err != nil {
		t.Fatal(err)
	}
	in, err := a.Start(context.Background(), attach.Params{Claim: "c:1", Out: "o", Capture: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if in.Exit() != "" {
		t.Fatalf("exited before Stop: %s", in.Exit())
	}
	if err := in.Stop(); err != nil {
		t.Fatal(err)
	}
	if in.Exit() == "" {
		t.Fatal("no exit after Stop")
	}
	if err := in.Stop(); err != nil {
		t.Fatalf("a second Stop: %v", err)
	}
}

func TestExecCollectorStartErrors(t *testing.T) {
	a, err := Attach(collectorTarget(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(context.Background(), attach.Params{Claim: "c:1", Capture: "none"}); err == nil || !strings.Contains(err.Error(), "exec.argv: {out} has no value in this start") {
		t.Errorf("error %v for a start without {out}", err)
	}
	missing := parse(t, `role = "collector"
os = ["linux"]
launcher = "exec"
[exec]
argv = ["./absent-collector", "{claim}", ["{script}"], ["{context}"]]
[collector]
attachment = "claims"
forms = { no_script = true, no_context = true }
`)
	a, err = Attach(missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(context.Background(), attach.Params{Claim: "c:1"}); err == nil || !strings.Contains(err.Error(), "absent-collector") {
		t.Errorf("error %v for a missing program, want one naming it", err)
	}
}

func TestExecCollectorReadBack(t *testing.T) {
	ctx := context.Background()
	params := attach.Params{Claim: "c:1", Out: filepath.Join(t.TempDir(), "out"), Capture: "none"}

	a, err := Attach(collectorTarget(t, "", `read_back = { dir = "{out}" }`))
	if err != nil {
		t.Fatal(err)
	}
	in, err := a.Start(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, in)
	if dir, err := in.ReadBack(ctx); err != nil || dir != params.Out {
		t.Errorf("ReadBack = %q, %v; want %q", dir, err, params.Out)
	}

	f := collectorTarget(t, "", "")
	f.Collector.ReadBack = &target.ReadBack{Argv: []string{strings.Trim(self(t), "'"), "write", "{dir}"}}
	f.Exec.Env = nil
	t.Setenv(helperEnv, "1")
	a, err = Attach(f)
	if err != nil {
		t.Fatal(err)
	}
	in, err = a.Start(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, in)
	dir, err := in.ReadBack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "stored.txt")); err != nil || string(b) != "stored" {
		t.Errorf("the read-back command's file: %q, %v", b, err)
	}
	if err := in.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the read-back directory is left after Stop: %v", err)
	}

	a, err = Attach(collectorTarget(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	in, err = a.Start(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, in)
	if _, err := in.ReadBack(ctx); err == nil || !strings.Contains(err.Error(), "the target declares no read-back") {
		t.Errorf("error %v from a target with no read-back", err)
	}
}

func TestExecCollectorNetwork(t *testing.T) {
	a, err := Attach(collectorTarget(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	n, err := a.Network(attach.Claim)
	if err != nil {
		t.Fatal(err)
	}
	if n.Address() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("claim side address %s, want 127.0.0.1", n.Address())
	}
	for _, s := range []attach.Side{attach.Build, attach.Upstream} {
		if _, err := a.Network(s); !errors.Is(err, attach.ErrNoSide) {
			t.Errorf("Network(%s) error %v, want ErrNoSide", s, err)
		}
	}
	if !a.Declared().Capture || a.Declared().Role != "collector" {
		t.Errorf("Declared() = %+v", a.Declared())
	}
}

func TestNotBuilt(t *testing.T) {
	tests := map[string]string{
		"an oci collector": `role = "collector"
os = ["linux"]
launcher = "oci"
[oci]
runtime = "docker"
image = "i"
args = ["--relay", "{claim}", "--context", "{context}", "--script", "{script}"]
[collector]
attachment = "claims"
`,
		"a collector that listens": `role = "collector"
os = ["linux"]
launcher = "external"
[external]
url = "https://c.example/"
session_token = ["s"]
[collector]
attachment = "listens"
`,
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Attach(parse(t, text)); !errors.Is(err, ErrNotBuilt) {
				t.Fatalf("error %v, want ErrNotBuilt", err)
			}
		})
	}
}

func externalTarget(t *testing.T, how string) target.File {
	return parse(t, `role = "relay"
os = ["linux"]
launcher = "external"
[external]
`+how+`
upstream = "198.51.100.1"
[relay]
mode = "vm"
link = "ip"
build_link = { prefix = "192.0.2.0/30", relay = "192.0.2.1", guest = "192.0.2.2" }
`)
}

func TestExternalRelay(t *testing.T) {
	ctx := context.Background()
	a, err := Attach(externalTarget(t, "claim = \"127.0.0.1:8301\"\ntoken = \"secret\""))
	if err != nil {
		t.Fatal(err)
	}
	in, err := a.Start(ctx, attach.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := in.Claim(), (attach.Endpoint{Address: "127.0.0.1:8301", Token: "secret"}); got != want {
		t.Errorf("Claim() = %+v, want %+v", got, want)
	}
	if in.Stop() != nil || in.Exit() != "" {
		t.Error("an external relay is stopped by the harness")
	}
	if _, err := in.ReadBack(ctx); err == nil {
		t.Error("an external relay has a read-back")
	}
	if _, err := a.Start(ctx, attach.Params{NoClaimToken: true}); err == nil || !strings.Contains(err.Error(), "cannot be started without one") {
		t.Errorf("error %v for a start without a token", err)
	}
	up, err := a.Network(attach.Upstream)
	if err != nil || up.Address() != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("Network(Upstream) = %v, %v", up, err)
	}
	if _, err := a.Network(attach.Build); err != nil {
		t.Errorf("Network(Build): %v", err)
	}
}

func TestExternalRelayRequest(t *testing.T) {
	t.Setenv(helperEnv, "1")
	ctx := context.Background()
	a, err := Attach(externalTarget(t, "request = ["+self(t)+", \"endpoint\"]"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Declared().FreshInstances {
		t.Error("a relay asked for on demand does not declare fresh instances")
	}
	in, err := a.Start(ctx, attach.Params{NoClaimToken: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Claim(); got != (attach.Endpoint{Address: "127.0.0.1:4100"}) {
		t.Errorf("Claim() = %+v", got)
	}
	if !strings.Contains(string(in.Log()), "second line") {
		t.Errorf("log %q does not keep what the request printed after the endpoint", in.Log())
	}

	for how, wantErr := range map[string]string{
		`"not-an-endpoint"`: `printed "relay is ready" as its first line, which is not a claim endpoint`,
		`"exit=4"`:          "exit status 4",
	} {
		a, err := Attach(externalTarget(t, "request = ["+self(t)+", "+how+"]"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Start(ctx, attach.Params{}); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("request %s: error %v, want one containing %q", how, err, wantErr)
		}
	}
}

func TestProgram(t *testing.T) {
	f := target.File{Path: filepath.Join("targets", "t.toml")}
	tests := map[string]string{
		"collector":                         "collector",
		"../dist/collector":                 filepath.Join("dist", "collector"),
		filepath.Join(t.TempDir(), "relay"): filepath.Join(t.TempDir(), "relay"),
	}
	for in, want := range tests {
		if filepath.IsAbs(in) {
			want = in
		}
		if got := program(f, in); got != want {
			t.Errorf("program(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogBuffer(t *testing.T) {
	var l logBuffer
	fmt.Fprint(&l, "first\n")
	if string(l.Bytes()) != "first\n" {
		t.Fatalf("log %q", l.Bytes())
	}
	l.Write(make([]byte, LogLimit))
	l.Write([]byte("last\n"))
	b := l.Bytes()
	if !strings.HasPrefix(string(b), "[earlier output dropped]\n") || !strings.HasSuffix(string(b), "last\n") {
		t.Errorf("a full log starts %q and ends %q", b[:30], b[len(b)-5:])
	}
	if len(b) != len("[earlier output dropped]\n")+LogLimit {
		t.Errorf("a full log holds %d bytes", len(b))
	}
}
