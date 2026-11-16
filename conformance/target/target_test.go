package target

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The disk collector's and the Go relay's target files as the format has
// them, which the error cases below each break in one way.
const (
	collectorDisk = `
role = "collector"
os = ["linux", "darwin", "windows"]
launcher = "exec"

[exec]
argv = ["../../dist/conformance/collector", "--relay", "{claim}", "--dir", "{out}",
        ["--context", "{context}"], ["--script", "{script}"], "--capture", "{capture}"]
env = { WARDEN_CLAIM_TOKEN = "{token}" }
pass_env = ["PATH", "SYSTEMROOT"]

[collector]
attachment = "claims"
forms = { no_script = true, no_context = true }
read_back = { dir = "{out}" }
`
	relayHost = `
role = "relay"
os = ["linux"]
launcher = "exec"

[exec]
argv = ["relay", "-mode", "host", "-claim-addr", "{claim}"]
env = { WARDEN_CLAIM_TOKEN = "{token}" }

[relay]
mode = "host"
link = "frames"
build_link = { prefix = "192.0.2.0/30", relay = "192.0.2.1", guest = "192.0.2.2" }
`
	relayExternal = `
role = "relay"
os = ["linux"]
launcher = "external"

[external]
claim = "127.0.0.1:8301"
token = "secret"
upstream = "198.51.100.1"

[relay]
mode = "vm"
link = "ip"
build_link = { prefix = "192.0.2.0/30", relay = "192.0.2.1", guest = "192.0.2.2" }
`
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		text string
		want Declared
	}{
		{
			name: "the disk collector",
			text: collectorDisk,
			want: Declared{
				Role: "collector", Launcher: "exec", Attachment: "claims",
				Forms: Forms{NoScript: true, NoContext: true}, Capture: true, ReadBack: true, FreshInstances: true,
			},
		},
		{
			name: "a host-mode relay",
			text: relayHost,
			want: Declared{
				Role: "relay", Launcher: "exec", Mode: "host", Link: "frames",
				BuildLink:      &BuildLink{Prefix: "192.0.2.0/30", Relay: "192.0.2.1", Guest: "192.0.2.2"},
				ResolverConfig: true, ClaimToken: true, NoClaimToken: true, FreshInstances: true,
			},
		},
		{
			name: "a relay whose token is a required argument",
			text: strings.Replace(relayHost, `"{claim}"]`, `"{claim}", "-token", "{token}"]`, 1),
			want: Declared{
				Role: "relay", Launcher: "exec", Mode: "host", Link: "frames",
				BuildLink:      &BuildLink{Prefix: "192.0.2.0/30", Relay: "192.0.2.1", Guest: "192.0.2.2"},
				ResolverConfig: true, ClaimToken: true, FreshInstances: true,
			},
		},
		{
			name: "an external relay",
			text: relayExternal,
			want: Declared{
				Role: "relay", Launcher: "external", Mode: "vm", Link: "ip",
				BuildLink:  &BuildLink{Prefix: "192.0.2.0/30", Relay: "192.0.2.1", Guest: "192.0.2.2"},
				ClaimToken: true,
			},
		},
		{
			name: "an external relay asked for on demand, with its address assigned",
			text: `role = "relay"
os = ["linux"]
launcher = "external"
[external]
request = ["new-relay", "--json"]
address = "203.0.113.7"
upstream = "198.51.100.1"
[relay]
mode = "container"
link = "ip"
address_by_launcher = true
`,
			want: Declared{
				Role: "relay", Launcher: "external", Mode: "container", Link: "ip",
				AddressByLauncher: true, NoClaimToken: true, FreshInstances: true,
			},
		},
		{
			name: "an oci relay",
			text: `role = "relay"
os = ["linux"]
launcher = "oci"
[oci]
runtime = "docker"
image = "buildwarden-relay:conformance"
env = { WARDEN_CLAIM_TOKEN = "{token}" }
[relay]
mode = "container"
link = "ip"
address_by_launcher = true
`,
			want: Declared{
				Role: "relay", Launcher: "oci", Mode: "container", Link: "ip", AddressByLauncher: true,
				ResolverConfig: true, ClaimToken: true, NoClaimToken: true, FreshInstances: true,
			},
		},
		{
			name: "a collector that listens",
			text: `role = "collector"
os = ["linux"]
launcher = "external"
[external]
url = "https://collector.example/"
session_token = ["new-session"]
[collector]
attachment = "listens"
`,
			want: Declared{Role: "collector", Launcher: "external", Attachment: "listens"},
		},
		{
			name: "a collector with a read-back command and literal braces",
			text: `role = "collector"
os = ["windows"]
launcher = "exec"
[exec]
argv = ["c.exe", "--relay={claim}", "--context", "{context}", "--script", "{script}", "--json={{}}"]
[collector]
attachment = "claims"
read_back = { argv = ["export", "{out}", "{dir}"] }
`,
			want: Declared{Role: "collector", Launcher: "exec", Attachment: "claims", ReadBack: true, FreshInstances: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse("t.toml", tt.text)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.Declared(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Declared() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr string
	}{
		{name: "not TOML", text: "role = relay\n", wantErr: "target file t.toml: toml:"},
		{name: "no role", text: "", wantErr: "role is missing; it is one of relay, collector"},
		{name: "unknown role", text: `role = "driver"`, wantErr: `role "driver" is not one this harness knows (relay, collector)`},
		{name: "role of the wrong type", text: "role = 1\n", wantErr: "target file t.toml: toml:"},
		{name: "a version", text: "version = \"v0.1.0\"\n" + collectorDisk, wantErr: `key "version": a target file names no specification and no version`},
		{name: "a relay's version", text: strings.Replace(relayHost, "[relay]\n", "[relay]\nversion = \"v1\"\n", 1), wantErr: `key "relay.version": a target file names no specification and no version`},
		{name: "a specification", text: "specification = \"relay-claim\"\n" + collectorDisk, wantErr: `key "specification": a target file names no specification and no version`},
		{name: "an unknown key", text: strings.Replace(collectorDisk, "pass_env", "passenv", 1), wantErr: `key "exec.passenv" is not one the target-file format names`},
		{name: "no os", text: strings.Replace(collectorDisk, `os = ["linux", "darwin", "windows"]`, "", 1), wantErr: "os is missing"},
		{name: "an unknown os", text: strings.Replace(collectorDisk, `"darwin"`, `"plan9"`, 1), wantErr: `os "plan9" is not one this harness knows (linux, darwin, windows)`},
		{name: "an os twice", text: strings.Replace(collectorDisk, `"darwin"`, `"linux"`, 1), wantErr: `os names "linux" twice`},
		{name: "no launcher", text: strings.Replace(collectorDisk, `launcher = "exec"`, "", 1), wantErr: "launcher is missing; it is one of exec, oci, external"},
		{name: "an unknown launcher", text: strings.Replace(collectorDisk, `launcher = "exec"`, `launcher = "vm-image"`, 1), wantErr: `launcher "vm-image" is not one this harness knows (exec, oci, external)`},
		{name: "a launcher without its table", text: relayHost[:strings.Index(relayHost, "[exec]")] + relayHost[strings.Index(relayHost, "[relay]"):], wantErr: `launcher "exec" needs the table [exec]`},
		{name: "another launcher's table", text: relayHost + "[oci]\nimage = \"x\"\n", wantErr: `the table [oci] is for launcher "oci", and this target's launcher is "exec"`},
		{name: "a relay without [relay]", text: relayHost[:strings.Index(relayHost, "[relay]")], wantErr: "a relay target needs the table [relay]"},
		{name: "a relay with [collector]", text: relayHost + "[collector]\nattachment = \"claims\"\n", wantErr: "the table [collector] is for a collector target"},
		{name: "a collector with [relay]", text: collectorDisk + "[relay]\nmode = \"host\"\n", wantErr: "the table [relay] is for a relay target"},
		{name: "a collector without [collector]", text: collectorDisk[:strings.Index(collectorDisk, "[collector]")], wantErr: "a collector target needs the table [collector]"},
		{name: "no mode", text: strings.Replace(relayHost, `mode = "host"`, "", 1), wantErr: "relay.mode is missing; it is one of host, vm, container"},
		{name: "an unknown mode", text: strings.Replace(relayHost, `mode = "host"`, `mode = "bare"`, 1), wantErr: `relay.mode "bare" is not one this harness knows`},
		{name: "an unknown link", text: strings.Replace(relayHost, `link = "frames"`, `link = "vsock"`, 1), wantErr: `relay.link "vsock" is not one this harness knows (frames, ip)`},
		{name: "neither build_link nor address_by_launcher", text: relayHost[:strings.Index(relayHost, "build_link")], wantErr: "[relay] needs the table build_link"},
		{name: "both build_link and address_by_launcher", text: relayHost + "address_by_launcher = true\n", wantErr: "[relay] has both build_link and address_by_launcher"},
		{name: "a build_link prefix that is not one", text: strings.Replace(relayHost, `"192.0.2.0/30"`, `"192.0.2.0"`, 1), wantErr: `relay.build_link.prefix "192.0.2.0" is not a network in CIDR form`},
		{name: "a build_link address that is not one", text: strings.Replace(relayHost, `guest = "192.0.2.2"`, `guest = "guest"`, 1), wantErr: `relay.build_link.guest "guest" is not an IP address`},
		{name: "a build_link address outside the prefix", text: strings.Replace(relayHost, `relay = "192.0.2.1"`, `relay = "192.0.2.9"`, 1), wantErr: "relay.build_link.relay 192.0.2.9 is not inside prefix 192.0.2.0/30"},
		{name: "no argv", text: strings.Replace(relayHost, `argv = ["relay", "-mode", "host", "-claim-addr", "{claim}"]`, "", 1), wantErr: "exec.argv is missing"},
		{name: "a program that is a placeholder", text: strings.Replace(relayHost, `["relay",`, `["{claim}",`, 1), wantErr: "exec.argv: its first element is the program, a plain string"},
		{name: "a program that is a group", text: strings.Replace(relayHost, `["relay",`, `[["relay", "{token}"],`, 1), wantErr: "exec.argv: its first element is the program, a plain string"},
		{name: "a command line that is not an array", text: strings.Replace(relayHost, `argv = [`, `argv = "relay" #`, 1), wantErr: "a command line is an array of strings and of arrays of strings"},
		{name: "a command line holding a number", text: strings.Replace(relayHost, `"host", "-claim-addr"`, `"host", 4, "-claim-addr"`, 1), wantErr: "element 4 of a command line is a int64"},
		{name: "a group holding a number", text: strings.Replace(relayHost, `"-claim-addr", "{claim}"]`, `["-claim-addr", 1]]`, 1), wantErr: "element 4 of a command line: an optional group holds strings only"},
		{name: "an empty group", text: strings.Replace(relayHost, `"{claim}"]`, `"{claim}", []]`, 1), wantErr: "exec.argv: element 6 is an empty optional group"},
		{name: "a group with no placeholder", text: strings.Replace(relayHost, `"{claim}"]`, `"{claim}", ["-v"]]`, 1), wantErr: "exec.argv: element 6 is an optional group with no placeholder"},
		{name: "an unknown placeholder", text: strings.Replace(relayHost, `"{claim}"]`, `"{claim}", "{out}"]`, 1), wantErr: "exec.argv: {out} is not a placeholder here, which takes {claim}, {token}"},
		{name: "a placeholder that is not a name", text: strings.Replace(relayHost, `"{claim}"]`, `"{Claim}"]`, 1), wantErr: `exec.argv: "{Claim}" holds {Claim}, which is not a placeholder name`},
		{name: "a brace left open", text: strings.Replace(relayHost, `"{claim}"]`, `"{claim"]`, 1), wantErr: `exec.argv: "{claim" has a { with no }; write {{ for a literal {`},
		{name: "a brace never opened", text: strings.Replace(relayHost, `"{claim}"]`, `"claim}"]`, 1), wantErr: `exec.argv: "claim}" has a } with no {; write }} for a literal }`},
		{name: "an unknown placeholder in env", text: strings.Replace(relayHost, `"{token}"`, `"{script}"`, 1), wantErr: "exec.env.WARDEN_CLAIM_TOKEN: {script} is not a placeholder here"},
		{name: "an env name that is not one", text: strings.Replace(relayHost, `WARDEN_CLAIM_TOKEN =`, `"A=B" =`, 1), wantErr: `exec.env: "A=B" is not an environment variable name`},
		{name: "oci without a runtime", text: "role = \"relay\"\nos = [\"linux\"]\nlauncher = \"oci\"\n[oci]\nimage = \"i\"\n[relay]\nmode = \"container\"\nlink = \"ip\"\naddress_by_launcher = true\n", wantErr: "oci.runtime is missing: an oci target names the container runtime that runs it"},
		{name: "oci without an image", text: "role = \"relay\"\nos = [\"linux\"]\nlauncher = \"oci\"\n[oci]\nruntime = \"docker\"\n[relay]\nmode = \"container\"\nlink = \"ip\"\naddress_by_launcher = true\n", wantErr: "oci.image is missing"},
		{name: "an external relay with neither claim nor request", text: strings.Replace(relayExternal, `claim = "127.0.0.1:8301"`, "", 1), wantErr: "an external relay needs external.claim"},
		{name: "an external relay with both claim and request", text: strings.Replace(relayExternal, `token =`, "request = [\"r\"]\ntoken =", 1), wantErr: "external has both claim and request"},
		{name: "an external claim that is not host:port", text: strings.Replace(relayExternal, `"127.0.0.1:8301"`, `"127.0.0.1"`, 1), wantErr: `external.claim "127.0.0.1" is not host:port`},
		{name: "an external request with a placeholder", text: strings.Replace(relayExternal, `claim = "127.0.0.1:8301"`, `request = ["r", "{claim}"]`, 1), wantErr: "external.request: {claim} is not a placeholder here, which takes none"},
		{name: "an external relay on a frames link", text: strings.Replace(relayExternal, `link = "ip"`, `link = "frames"`, 1), wantErr: `an external relay's relay.link must be "ip"`},
		{name: "an external relay without upstream", text: strings.Replace(relayExternal, `upstream = "198.51.100.1"`, "", 1), wantErr: "external.upstream is missing"},
		{name: "an external relay with a collector's url", text: strings.Replace(relayExternal, `token =`, "url = \"u\"\ntoken =", 1), wantErr: "external.url and external.session_token are for a collector that listens"},
		{name: "an external relay assigned its address without naming it", text: strings.Replace(strings.Replace(relayExternal, `build_link = { prefix = "192.0.2.0/30", relay = "192.0.2.1", guest = "192.0.2.2" }`, "address_by_launcher = true", 1), "", "", 1), wantErr: "external.address is missing (an external relay with address_by_launcher names its own address)"},
		{name: "an external relay naming an address it was not assigned", text: strings.Replace(relayExternal, `token =`, "address = \"192.0.2.1\"\ntoken =", 1), wantErr: "external.address is for a relay with address_by_launcher"},
		{name: "no attachment", text: strings.Replace(collectorDisk, `attachment = "claims"`, "", 1), wantErr: "collector.attachment is missing; it is one of claims, listens"},
		{name: "an unknown attachment", text: strings.Replace(collectorDisk, `attachment = "claims"`, `attachment = "dials"`, 1), wantErr: `collector.attachment "dials" is not one this harness knows (claims, listens)`},
		{name: "a collector that claims, external", text: "role = \"collector\"\nos = [\"linux\"]\nlauncher = \"external\"\n[external]\nurl = \"u\"\n[collector]\nattachment = \"claims\"\n", wantErr: `a collector that claims is started against a claim address, so its launcher is "exec" or "oci"`},
		{name: "a collector that listens, launched", text: strings.Replace(collectorDisk, `attachment = "claims"`, `attachment = "listens"`, 1), wantErr: `a collector that listens is already serving, so its launcher is "external", not "exec"`},
		{name: "a collector that listens, without a url", text: "role = \"collector\"\nos = [\"linux\"]\nlauncher = \"external\"\n[external]\nsession_token = [\"s\"]\n[collector]\nattachment = \"listens\"\n", wantErr: "a collector that listens needs external.url"},
		{name: "a collector that listens, without session_token", text: "role = \"collector\"\nos = [\"linux\"]\nlauncher = \"external\"\n[external]\nurl = \"u\"\n[collector]\nattachment = \"listens\"\n", wantErr: "external.session_token is missing"},
		{name: "a collector that listens, with a relay's claim", text: "role = \"collector\"\nos = [\"linux\"]\nlauncher = \"external\"\n[external]\nurl = \"u\"\nsession_token = [\"s\"]\nclaim = \"h:1\"\n[collector]\nattachment = \"listens\"\n", wantErr: "external.claim, request, token, address and upstream are for a relay"},
		{name: "a collector that claims without {claim}", text: strings.Replace(collectorDisk, `"--relay", "{claim}", `, "", 1), wantErr: "a collector that claims is started against the harness's claim address, so its command line holds {claim}"},
		{name: "a collector without {script}", text: strings.Replace(collectorDisk, `["--script", "{script}"], `, "", 1), wantErr: "the command line holds no {script}, so the harness cannot give the collector a script"},
		{name: "no_script with {script} required", text: strings.Replace(collectorDisk, `["--script", "{script}"]`, `"--script", "{script}"`, 1), wantErr: "collector.forms.no_script is declared, so {script} is only in optional groups"},
		{name: "{context} in a group without no_context", text: strings.Replace(collectorDisk, "no_context = true", "no_context = false", 1), wantErr: "{context} is in an optional group, which is how a collector is started without one; declare collector.forms.no_context"},
		{name: "an unknown form", text: strings.Replace(collectorDisk, "no_context = true", "no_context = true, no_ledger = true", 1), wantErr: `key "collector.forms.no_ledger" is not one the target-file format names`},
		{name: "an empty read-back", text: strings.Replace(collectorDisk, `read_back = { dir = "{out}" }`, "read_back = {}", 1), wantErr: "collector.read_back needs dir"},
		{name: "a read-back with dir and argv", text: strings.Replace(collectorDisk, `read_back = { dir = "{out}" }`, `read_back = { dir = "{out}", argv = ["x"] }`, 1), wantErr: "collector.read_back has both dir and argv"},
		{name: "a read-back dir with an unknown placeholder", text: strings.Replace(collectorDisk, `dir = "{out}"`, `dir = "{dir}"`, 1), wantErr: "collector.read_back.dir: {dir} is not a placeholder here, which takes {out}"},
		{name: "a read-back command with an unknown placeholder", text: strings.Replace(collectorDisk, `dir = "{out}"`, `argv = ["x", "{claim}"]`, 1), wantErr: "collector.read_back.argv: {claim} is not a placeholder here, which takes {out}, {dir}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("t.toml", tt.text)
			if err == nil {
				t.Fatalf("no error; want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector-disk.toml")
	if err := os.WriteFile(path, []byte(collectorDisk), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != path || !f.RunsOn("windows") || f.RunsOn("freebsd") {
		t.Errorf("Read = %+v", f)
	}
	if _, err := Read(filepath.Join(t.TempDir(), "absent.toml")); err == nil || !strings.Contains(err.Error(), "absent.toml") {
		t.Fatalf("error %v for a missing file, want one naming it", err)
	}
}
