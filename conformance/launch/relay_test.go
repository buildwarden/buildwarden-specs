package launch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/sandbox"
)

// The relay launchers' tests are tier 0: they check the command lines the
// launchers build and what an attachment declares, and none builds a sandbox
// or calls a container runtime: a runtime's answers are played by a script.

const (
	execRelay = `role = "relay"
os = ["linux"]
launcher = "exec"
[exec]
argv = ["bin/relay", "-mode", "vm", "-claim-addr", "{claim}"]
env = { WARDEN_CLAIM_TOKEN = "{token}", RUST_LOG = "info" }
pass_env = ["BW_TEST_PASSED", "BW_TEST_UNSET"]
[relay]
mode = "vm"
link = "ip"
build_link = { prefix = "10.100.0.0/30", relay = "10.100.0.1", guest = "10.100.0.2" }
`
	ociRelay = `role = "relay"
os = ["linux"]
launcher = "oci"
[oci]
runtime = "docker"
image = "buildwarden-relay:conformance"
args = ["-claim-addr", "{claim}", ["-token", "{token}"]]
env = { WARDEN_CLAIM_TOKEN = "{token}" }
[relay]
mode = "container"
link = "ip"
address_by_launcher = true
`
)

func TestExecCommand(t *testing.T) {
	t.Setenv("BW_TEST_PASSED", "yes")
	f := parse(t, execRelay)
	argv, env, err := execCommand(f, map[string]string{"claim": "100.64.0.1:8301", "token": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bin/relay", "-mode", "vm", "-claim-addr", "100.64.0.1:8301"}; !slices.Equal(argv, want) {
		t.Errorf("argv %q, want %q", argv, want)
	}
	if want := []string{"RUST_LOG=info", "WARDEN_CLAIM_TOKEN=tok", "BW_TEST_PASSED=yes"}; !slices.Equal(env, want) {
		t.Errorf("env %q, want %q", env, want)
	}
	// Without a token the variable that holds it is not set at all.
	_, env, err = execCommand(f, map[string]string{"claim": "100.64.0.1:8301"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"RUST_LOG=info", "BW_TEST_PASSED=yes"}; !slices.Equal(env, want) {
		t.Errorf("env without a token %q, want %q", env, want)
	}
}

func TestOCIRun(t *testing.T) {
	f := parse(t, ociRelay)
	got := ociRun(f.OCI, "bw-conformance-7-3", "/sandbox/resolv.conf", []string{"WARDEN_CLAIM_TOKEN=tok"}, []string{"-claim-addr", ociClaim})
	want := []string{
		"run", "--rm", "--name", "bw-conformance-7-3", "--network", "none", "--pull", "never",
		"--volume", "/sandbox/resolv.conf:/etc/resolv.conf:ro",
		"--env", "WARDEN_CLAIM_TOKEN",
		"buildwarden-relay:conformance", "-claim-addr", "0.0.0.0:8301",
	}
	if !slices.Equal(got, want) {
		t.Errorf("ociRun =\n%q\nwant\n%q", got, want)
	}
	if got := ociInspect("n"); !slices.Equal(got, []string{"inspect", "--format", "{{.State.Pid}}", "n"}) {
		t.Errorf("ociInspect = %q", got)
	}
	if got := ociRemove("n"); !slices.Equal(got, []string{"rm", "--force", "n"}) {
		t.Errorf("ociRemove = %q", got)
	}
	if ociClaim != "0.0.0.0:8301" || sandbox.ClaimPort != 8301 {
		t.Errorf("ociClaim %q", ociClaim)
	}
}

// TestRemoveContainer checks that a container the runtime is already removing,
// or has removed, is not an error when the harness removes it: an oci relay
// that exits by itself after a failed start is removed by the runtime's --rm,
// and its case does not fail for it (H1 of the hosted run 43841571312).
func TestRemoveContainer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the runtime's script is a shell script")
	}
	tests := []struct {
		name, out, wantErr string
		code               int
	}{
		{name: "removed", out: "n"},
		{name: "docker, already being removed", out: "Error response from daemon: removal of container n is already in progress", code: 1},
		{name: "docker, gone", out: "Error response from daemon: No such container: n", code: 1},
		{name: "podman, gone", out: "Error: no container with name or ID \"n\" found: no such container", code: 1},
		{name: "another error", out: "Error response from daemon: permission denied", code: 1, wantErr: "removing the container n: exit status 1: Error response from daemon: permission denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := filepath.Join(t.TempDir(), "docker")
			args := filepath.Join(filepath.Dir(rt), "args")
			script := "#!/bin/sh\necho \"$@\" > '" + args + "'\necho '" + strings.ReplaceAll(tt.out, "'", "'\\''") + "' >&2\nexit " + strconv.Itoa(tt.code) + "\n"
			if err := os.WriteFile(rt, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			err := removeContainer(rt, "n")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("removeContainer: %v", err)
			case tt.wantErr != "" && (err == nil || strings.TrimSpace(err.Error()) != tt.wantErr):
				t.Errorf("removeContainer = %v, want %q", err, tt.wantErr)
			}
			if b, err := os.ReadFile(args); err != nil || string(b) != "rm --force n\n" {
				t.Errorf("the runtime ran with %q (%v), want rm --force n", b, err)
			}
		})
	}
}

func TestClaimHeld(t *testing.T) {
	tests := []struct {
		name, text, wantErr string
	}{
		{name: "in argv", text: execRelay},
		{name: "in oci.args", text: ociRelay},
		{name: "in env", text: strings.Replace(strings.Replace(execRelay, `, "-claim-addr", "{claim}"]`, `]`, 1), `RUST_LOG = "info"`, `CLAIM = "{claim}"`, 1)},
		{name: "nowhere", text: strings.Replace(execRelay, `, "-claim-addr", "{claim}"]`, `]`, 1), wantErr: "exec.argv holds no {claim} outside an optional group, and no variable of its env holds one"},
		{name: "only in a group", text: strings.Replace(execRelay, `"-claim-addr", "{claim}"]`, `["-claim-addr", "{claim}"]]`, 1), wantErr: "exec.argv holds no {claim}"},
		{name: "nowhere, oci", text: strings.Replace(ociRelay, `"-claim-addr", "{claim}", `, ``, 1), wantErr: "oci.args holds no {claim}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := claimHeld(parse(t, tt.text))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatal(err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSandboxRelayDeclared(t *testing.T) {
	a := &sandboxRelay{f: parse(t, ociRelay)}
	d := a.Declared()
	if d.Address != sandbox.LauncherRelay.Addr().String() || !d.AddressByLauncher || !d.ResolverConfig || !d.FreshInstances {
		t.Errorf("an oci relay declares %+v", d)
	}
	if !d.ClaimToken || !d.NoClaimToken {
		t.Errorf("a relay whose token is optional declares ClaimToken %v, NoClaimToken %v", d.ClaimToken, d.NoClaimToken)
	}
	if d := (&sandboxRelay{f: parse(t, execRelay)}).Declared(); d.Address != "" || d.BuildLink == nil {
		t.Errorf("a vm relay with a build_link declares %+v", d)
	}
	host := strings.NewReplacer(`"vm"`, `"host"`, `link = "ip"`, `link = "frames"`).Replace(execRelay)
	if _, err := (&sandboxRelay{f: parse(t, host)}).Network(attach.Build); !errors.Is(err, attach.ErrNoSide) {
		t.Errorf("a frames relay's build side: %v, want ErrNoSide", err)
	}
}

// TestStartToken checks that a relay whose command line requires {token}
// is not started without one, before anything is built for it.
func TestStartToken(t *testing.T) {
	f := parse(t, strings.Replace(execRelay, `"{claim}"]`, `"{claim}", "-token", "{token}"]`, 1))
	in := &relayInstance{f: f}
	if err := in.start(context.Background(), attach.Params{NoClaimToken: true}); err == nil || !strings.Contains(err.Error(), "requires {token}") {
		t.Errorf("start without a token: %v", err)
	}
}

// fakeInspect writes a runtime whose inspect of a container's process ID
// answers, call by call, with each of answers in turn and then with the last
// one: "-" for no such container, any other text as the process ID. Its
// inspect of the container's state prints state. It counts its calls in
// counter, so that its answers follow the calls and not the clock.
func fakeInspect(t *testing.T, state string, answers ...string) string {
	t.Helper()
	dir := t.TempDir()
	rt := filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" +
		"if [ \"$3\" = '{{json .State}}' ]; then echo '" + state + "'; exit 0; fi\n" +
		"n=$(cat '" + dir + "/count' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '" + dir + "/count'\n" +
		"case $n in\n"
	for i, a := range answers {
		pat := strconv.Itoa(i + 1)
		if i == len(answers)-1 {
			pat = "*"
		}
		if a == "-" {
			script += pat + ") echo 'Error: No such object: n' >&2; exit 1;;\n"
		} else {
			script += pat + ") echo '" + a + "';;\n"
		}
	}
	script += "esac\n"
	if err := os.WriteFile(rt, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestContainerPID drives containerPID with a fake runtime: the bound it is
// given, the phases it records, and the message of each failure, which says
// that the runtime, not the relay, did not get as far as running.
func TestContainerPID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the runtime's script is a shell script")
	}
	// The runtime has a target's own command's bound, longer than the
	// relay's own, which runs from when the container is running.
	if containerLimit != CommandLimit || containerLimit <= sandbox.StartLimit {
		t.Errorf("containerLimit %s, want CommandLimit %s, beyond sandbox.StartLimit %s", containerLimit, CommandLimit, sandbox.StartLimit)
	}
	f := parse(t, ociRelay)
	never := "the relay under test was never running"
	timedOut := "the runtime docker did not start the container n within 1m0s: " + never
	tests := []struct {
		name    string
		answers []string
		exited  bool
		pid     int
		listed  bool
		wantErr string
	}{
		{name: "running after a delay", answers: []string{"-", "-", "0", "0", "4242"}, pid: 4242, listed: true},
		{name: "never listed", answers: []string{"-"}, wantErr: timedOut},
		{name: "listed, no process", answers: []string{"-", "0"}, listed: true, wantErr: timedOut},
		{name: "run exited", answers: []string{"-"}, exited: true, wantErr: "docker run n exited before the container was running: " + never},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := fakeInspect(t, "{}", tt.answers...)
			in := &relayInstance{f: f, done: make(chan struct{})}
			if tt.exited {
				close(in.done)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A timeout case stands for the limit running out by cancelling
			// once every answer has been given, so that its outcome follows
			// the fake's calls and the one-minute limit is only a failure bound.
			var fired <-chan struct{}
			if tt.wantErr != "" && !tt.exited {
				fired = cancelPastAnswers(ctx, cancel, rt, len(tt.answers))
			}
			ph := ociPhases{run: time.Now()}
			pid, err := in.containerPID(ctx, rt, "n", time.Minute, &ph)
			if fired != nil {
				select {
				case <-fired:
				default:
					t.Fatalf("containerPID = %d, %v before the fake gave all of %q", pid, err, tt.answers)
				}
			}
			switch {
			case tt.wantErr == "" && (err != nil || pid != tt.pid):
				t.Fatalf("containerPID = %d, %v; want %d", pid, err, tt.pid)
			case tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr):
				t.Fatalf("containerPID = %d, %v; want the error %q", pid, err, tt.wantErr)
			}
			if got := !ph.listed.IsZero(); got != tt.listed {
				t.Errorf("listed recorded %v, want %v", got, tt.listed)
			}
			if got := !ph.running.IsZero(); got != (tt.pid > 0) {
				t.Errorf("running recorded %v, want %v", got, tt.pid > 0)
			}
			if tt.pid > 0 && (ph.listed.Before(ph.run) || ph.running.Before(ph.listed)) {
				t.Errorf("phases out of order: %+v", ph)
			}
		})
	}
}

// cancelPastAnswers calls cancel once the fake runtime rt has been called
// for more than n inspects, and closes the channel it returns when it has.
// It waits for the call after the n-th, not the n-th itself: containerPID
// inspects one call at a time, so only then has it taken in the n-th
// answer, which a cancel during that call would kill unread.
func cancelPastAnswers(ctx context.Context, cancel context.CancelFunc, rt string, n int) <-chan struct{} {
	fired := make(chan struct{})
	count := filepath.Join(filepath.Dir(rt), "count")
	go func() {
		for ctx.Err() == nil {
			b, _ := os.ReadFile(count)
			if c, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && c > n {
				close(fired)
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	return fired
}

// TestOCIStartReport checks what a failed oci start prints of its phases and
// of the runtime's state.
func TestOCIStartReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the runtime's script is a shell script")
	}
	run := time.Date(2026, 11, 22, 19, 57, 12, 0, time.UTC)
	ph := ociPhases{run: run, listed: run.Add(1200 * time.Millisecond), running: run.Add(29 * time.Second)}
	want := "run started at 19:57:12.000; inspect first returned the container after 1.2s; the container had a process after 29s; the claim endpoint answered not reached"
	if got := ph.String(); got != want {
		t.Errorf("phases\n%s\nwant\n%s", got, want)
	}
	state := `{"Status":"created","Running":false,"Pid":0}`
	if got := ociState(fakeInspect(t, state, "-"), "n"); got != state {
		t.Errorf("ociState = %q, want %q", got, state)
	}
}
