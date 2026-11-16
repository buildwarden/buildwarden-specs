package launch

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/sandbox"
)

// The relay launchers' tests are tier 0: they check the command lines the
// launchers build and what an attachment declares, and none builds a sandbox
// or calls a container runtime.

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
