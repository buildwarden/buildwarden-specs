// Package target reads a target file: the TOML file that describes a
// component under test to the harness. A target file names the component's
// role, the launcher that starts it or reaches it, the host operating systems
// it can run on, and the attachment points the suites need. It names no
// specification and no version: the command that is run says what the
// component is tested against.
//
// The format, key by key:
//
//	role     = "relay" | "collector"                 required
//	os       = ["linux", "darwin", "windows"]        required, the hosts it runs on
//	launcher = "exec" | "oci" | "external"           required
//
//	[exec]                                           launcher "exec": a program
//	argv     = ["path", "--flag", "{placeholder}", ["--opt", "{script}"]]
//	env      = { NAME = "value with {placeholders}" }
//	pass_env = ["PATH"]                              the harness's variables it is given
//
//	[oci]                                            launcher "oci": an image
//	runtime  = "docker"                              the container runtime that runs it
//	image    = "buildwarden-relay:conformance"
//	args     = [...]                                 as exec's argv, after the image
//	env      = { ... }
//
//	[external]                                       launcher "external": already running
//	claim    = "host:port"                           a relay: its claim endpoint, or
//	request  = ["program", ...]                      a command that prints a fresh relay's
//	token    = "..."                                 the relay's claim token, if it has one
//	address  = "192.0.2.1"                           the relay's own address, with address_by_launcher
//	upstream = "198.51.100.1"                        where the harness's upstream servers listen
//	url      = "https://..."                         a "listens" collector: its base URL
//	session_token = ["program", ...]                 and a command that prints a session token
//
//	[relay]                                          role "relay"
//	mode     = "host" | "vm" | "container"
//	link     = "frames" | "ip"
//	address_by_launcher = true                       or the table build_link, not both
//	[relay.build_link]                               sent as the claim's build_link
//	prefix = "192.0.2.0/30"; relay = "192.0.2.1"; guest = "192.0.2.2"
//
//	[collector]                                      role "collector"
//	attachment = "claims" | "listens"
//	[collector.forms]                                what it can be started as
//	no_script = false; no_context = false; no_bootstrap = false; no_token = false
//	serves_after_completion = false
//	[collector.read_back]                            optional: what it stored
//	dir  = "{out}"                                   a directory in the disk layout, or
//	argv = ["program", "{out}", "{dir}"]             a command that writes one into {dir}
//
// A key the format does not name is an error, so a misspelt key is never
// silently left out.
//
// A relay target whose launcher is exec or oci is started in the Linux
// sandbox (package sandbox), which chooses its claim endpoint: its command
// line holds {claim}, outside an optional group or in a variable of its env;
// its build_link is outside the ranges the sandbox uses; and an oci relay's
// link is "ip". The sandbox gives an exec relay a frames link as its file
// descriptor 3.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// The values each enumerated key takes. Roles, launchers and attachments are
// not closed sets of the format: a later harness may know more, and a file
// that names one this harness does not know is an error that lists the ones
// it does.
var (
	Roles       = []string{"relay", "collector"}
	Launchers   = []string{"exec", "oci", "external"}
	OSes        = []string{"linux", "darwin", "windows"}
	Modes       = []string{"host", "vm", "container"}
	Links       = []string{"frames", "ip"}
	Attachments = []string{"claims", "listens"}
)

// File is what a target file says.
type File struct {
	// Path is the file the target was read from. Relative program paths in
	// it are relative to the file's directory.
	Path string `toml:"-"`

	Role     string   `toml:"role"`
	OS       []string `toml:"os"`
	Launcher string   `toml:"launcher"`

	Exec     *Exec     `toml:"exec"`
	OCI      *OCI      `toml:"oci"`
	External *External `toml:"external"`

	Relay     *Relay     `toml:"relay"`
	Collector *Collector `toml:"collector"`
}

// Exec is the exec launcher's table: the program that is the component, run
// with exactly the environment it names.
type Exec struct {
	Argv Argv              `toml:"argv"`
	Env  map[string]string `toml:"env"`
	// PassEnv names variables of the harness's own environment that the
	// program is given as well, such as PATH or, on Windows, SYSTEMROOT.
	// Nothing else of the harness's environment reaches it.
	PassEnv []string `toml:"pass_env"`
}

// OCI is the oci launcher's table: an image run by the container runtime it
// names. The harness has no default runtime.
type OCI struct {
	Runtime string            `toml:"runtime"`
	Image   string            `toml:"image"`
	Args    Argv              `toml:"args"`
	Env     map[string]string `toml:"env"`
}

// External is the external launcher's table: a component that is already
// running, given by its addresses.
type External struct {
	// Claim is a relay's claim endpoint, host:port. With it the target is
	// one relay, which allows only the cases that do not end it.
	Claim string `toml:"claim"`
	// Request is a command that asks for a fresh relay and prints its claim
	// endpoint, host:port, as the first line of its standard output.
	Request []string `toml:"request"`
	// Token is the relay's claim token, when it was started with one.
	Token string `toml:"token"`
	// Address is the relay's own address on its build link, given when
	// whoever started it assigned it (Relay.AddressByLauncher).
	Address string `toml:"address"`
	// Upstream is the address of this host, reachable from the relay, on
	// which the harness's resolver and origin servers listen.
	Upstream string `toml:"upstream"`
	// URL is a "listens" collector's base URL.
	URL string `toml:"url"`
	// SessionToken is a command that prints a session token for a
	// "listens" collector, one for each case.
	SessionToken []string `toml:"session_token"`
}

// Relay is what a relay target declares.
type Relay struct {
	// Mode is the relay's mode, which selects the cases whose expected
	// result differs by mode.
	Mode string `toml:"mode"`
	// Link is the kind of its build link: "frames", a socket carrying one
	// Ethernet frame per datagram, or "ip", a kernel interface.
	Link string `toml:"link"`
	// BuildLink is what the harness sends as the claim's build_link.
	BuildLink *BuildLink `toml:"build_link"`
	// AddressByLauncher says that the relay's address is assigned by its
	// launcher, and the harness sends no build_link.
	AddressByLauncher bool `toml:"address_by_launcher"`
}

// BuildLink is a claim's build_link: the segment's network and the relay's
// and the build environment's addresses on it.
type BuildLink struct {
	Prefix string `toml:"prefix"`
	Relay  string `toml:"relay"`
	Guest  string `toml:"guest"`
}

// Collector is what a collector target declares.
type Collector struct {
	// Attachment is how the harness's relay reaches the collector:
	// "claims", the collector is also the claimant and is started against
	// a claim address; or "listens", it is already serving at a base URL.
	Attachment string `toml:"attachment"`
	// Forms are what it can be started as.
	Forms Forms `toml:"forms"`
	// ReadBack, when given, is how the harness reads what the collector
	// stored, after the session's completion.
	ReadBack *ReadBack `toml:"read_back"`
}

// Forms are the forms a collector can be started as. For the script and the
// context the harness starts the form without one by leaving out the
// optional group of the command line that holds its placeholder; the others
// are what the collector is as its command line starts it.
type Forms struct {
	NoScript              bool `toml:"no_script"`
	NoContext             bool `toml:"no_context"`
	NoBootstrap           bool `toml:"no_bootstrap"`
	NoToken               bool `toml:"no_token"`
	ServesAfterCompletion bool `toml:"serves_after_completion"`
}

// ReadBack is a collector's read-back: a directory in the disk layout, or a
// command that writes one into the directory {dir}.
type ReadBack struct {
	Dir  string   `toml:"dir"`
	Argv []string `toml:"argv"`
}

// Read reads and checks the target file at path.
func Read(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("target file: %w", err)
	}
	return Parse(path, string(b))
}

// Parse decodes and checks a target file's text; path is the file it was
// read from, named in errors and the base of relative program paths.
func Parse(path, text string) (File, error) {
	var f File
	md, err := toml.Decode(text, &f)
	if err == nil {
		err = undecoded(md)
	}
	if err == nil {
		err = f.check()
	}
	if err != nil {
		return File{}, fmt.Errorf("target file %s: %w", path, err)
	}
	f.Path = path
	return f, nil
}

func undecoded(md toml.MetaData) error {
	keys := md.Undecoded()
	if len(keys) == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	k := keys[0]
	switch k[len(k)-1] {
	case "specification", "specifications", "spec", "version", "versions":
		return fmt.Errorf("key %q: a target file names no specification and no version; the command that is run says what the component is tested against", k.String())
	}
	return fmt.Errorf("key %q is not one the target-file format names", k.String())
}

func oneOf(key, value string, known []string) error {
	list := strings.Join(known, ", ")
	switch {
	case value == "":
		return fmt.Errorf("%s is missing; it is one of %s", key, list)
	case !slices.Contains(known, value):
		return fmt.Errorf("%s %q is not one this harness knows (%s)", key, value, list)
	}
	return nil
}

func (f File) check() error {
	if err := oneOf("role", f.Role, Roles); err != nil {
		return err
	}
	if len(f.OS) == 0 {
		return fmt.Errorf("os is missing; it lists the host operating systems the target runs on, of %s", strings.Join(OSes, ", "))
	}
	for i, o := range f.OS {
		if err := oneOf("os", o, OSes); err != nil {
			return err
		}
		if slices.Contains(f.OS[:i], o) {
			return fmt.Errorf("os names %q twice", o)
		}
	}
	if err := oneOf("launcher", f.Launcher, Launchers); err != nil {
		return err
	}
	tables := map[string]bool{"exec": f.Exec != nil, "oci": f.OCI != nil, "external": f.External != nil}
	for _, l := range Launchers {
		switch {
		case l == f.Launcher && !tables[l]:
			return fmt.Errorf("launcher %q needs the table [%s]", l, l)
		case l != f.Launcher && tables[l]:
			return fmt.Errorf("the table [%s] is for launcher %q, and this target's launcher is %q", l, l, f.Launcher)
		}
	}
	switch f.Role {
	case "relay":
		if f.Collector != nil {
			return errors.New("the table [collector] is for a collector target, and this target's role is relay")
		}
		return f.checkRelay()
	default:
		if f.Relay != nil {
			return errors.New("the table [relay] is for a relay target, and this target's role is collector")
		}
		return f.checkCollector()
	}
}

func (f File) checkRelay() error {
	r := f.Relay
	if r == nil {
		return errors.New("a relay target needs the table [relay]")
	}
	if err := oneOf("relay.mode", r.Mode, Modes); err != nil {
		return err
	}
	if err := oneOf("relay.link", r.Link, Links); err != nil {
		return err
	}
	switch {
	case r.BuildLink == nil && !r.AddressByLauncher:
		return errors.New("[relay] needs the table build_link, which the harness sends as the claim's build_link, or address_by_launcher = true")
	case r.BuildLink != nil && r.AddressByLauncher:
		return errors.New("[relay] has both build_link and address_by_launcher; it is one or the other")
	case r.BuildLink != nil:
		if err := r.BuildLink.check(); err != nil {
			return err
		}
	}
	switch f.Launcher {
	case "exec":
		return checkArgv("exec.argv", f.Exec.Argv, f.Exec.Env, relayPlaceholders, true)
	case "oci":
		if err := checkOCI(f.OCI); err != nil {
			return err
		}
		return checkArgv("oci.args", f.OCI.Args, f.OCI.Env, relayPlaceholders, false)
	}
	e := f.External
	if e.URL != "" || len(e.SessionToken) > 0 {
		return errors.New("external.url and external.session_token are for a collector that listens, and this target is a relay")
	}
	switch {
	case e.Claim == "" && len(e.Request) == 0:
		return errors.New("an external relay needs external.claim, its claim endpoint, or external.request, a command that prints a fresh relay's")
	case e.Claim != "" && len(e.Request) > 0:
		return errors.New("external has both claim and request; it is one or the other")
	case e.Claim != "":
		if err := hostPort("external.claim", e.Claim); err != nil {
			return err
		}
	default:
		if err := plainArgv("external.request", e.Request, nil); err != nil {
			return err
		}
	}
	if r.Link == "frames" {
		return errors.New("an external relay's relay.link must be \"ip\": a frames link is a socket that the relay's launcher hands it")
	}
	if _, err := addr("external.upstream", e.Upstream); err != nil {
		return err
	}
	switch {
	case r.AddressByLauncher:
		if _, err := addr("external.address", e.Address); err != nil {
			return fmt.Errorf("%w (an external relay with address_by_launcher names its own address)", err)
		}
	case e.Address != "":
		return errors.New("external.address is for a relay with address_by_launcher; this relay's address is relay.build_link.relay")
	}
	return nil
}

func (f File) checkCollector() error {
	c := f.Collector
	if c == nil {
		return errors.New("a collector target needs the table [collector]")
	}
	if err := oneOf("collector.attachment", c.Attachment, Attachments); err != nil {
		return err
	}
	if c.ReadBack != nil {
		rb := c.ReadBack
		switch {
		case rb.Dir == "" && len(rb.Argv) == 0:
			return errors.New("collector.read_back needs dir, a directory in the disk layout, or argv, a command that writes one into {dir}")
		case rb.Dir != "" && len(rb.Argv) > 0:
			return errors.New("collector.read_back has both dir and argv; it is one or the other")
		case rb.Dir != "":
			if err := checkText("collector.read_back.dir", rb.Dir, []string{"out"}); err != nil {
				return err
			}
		default:
			if err := plainArgv("collector.read_back.argv", rb.Argv, []string{"out", "dir"}); err != nil {
				return err
			}
		}
	}
	if c.Attachment == "listens" {
		if f.Launcher != "external" {
			return fmt.Errorf("a collector that listens is already serving, so its launcher is \"external\", not %q", f.Launcher)
		}
		e := f.External
		if e.Claim != "" || len(e.Request) > 0 || e.Token != "" || e.Address != "" || e.Upstream != "" {
			return errors.New("external.claim, request, token, address and upstream are for a relay; a collector that listens has url and session_token")
		}
		if e.URL == "" {
			return errors.New("a collector that listens needs external.url, its base URL")
		}
		return plainArgv("external.session_token", e.SessionToken, nil)
	}
	var argv Argv
	var env map[string]string
	switch f.Launcher {
	case "exec":
		if err := checkArgv("exec.argv", f.Exec.Argv, f.Exec.Env, collectorPlaceholders, true); err != nil {
			return err
		}
		argv, env = f.Exec.Argv, f.Exec.Env
	case "oci":
		if err := checkOCI(f.OCI); err != nil {
			return err
		}
		if err := checkArgv("oci.args", f.OCI.Args, f.OCI.Env, collectorPlaceholders, false); err != nil {
			return err
		}
		argv, env = f.OCI.Args, f.OCI.Env
	default:
		return errors.New("a collector that claims is started against a claim address, so its launcher is \"exec\" or \"oci\", not \"external\"")
	}
	where := map[string]string{}
	for _, a := range argv {
		for _, w := range a.Words {
			for _, n := range placeholderNames(w) {
				if a.Optional {
					where[n] += "o"
				} else {
					where[n] += "r"
				}
			}
		}
	}
	for _, v := range env {
		for _, n := range placeholderNames(v) {
			where[n] += "r"
		}
	}
	if where["claim"] == "" {
		return errors.New("a collector that claims is started against the harness's claim address, so its command line holds {claim}")
	}
	for _, p := range []struct {
		name string
		no   bool
		key  string
	}{
		{"script", c.Forms.NoScript, "no_script"},
		{"context", c.Forms.NoContext, "no_context"},
	} {
		w := where[p.name]
		switch {
		case w == "":
			return fmt.Errorf("the command line holds no {%s}, so the harness cannot give the collector a %s", p.name, p.name)
		case p.no && strings.Contains(w, "r"):
			return fmt.Errorf("collector.forms.%s is declared, so {%s} is only in optional groups of the command line, which the harness leaves out to start it without one", p.key, p.name)
		case !p.no && strings.Contains(w, "o"):
			return fmt.Errorf("{%s} is in an optional group, which is how a collector is started without one; declare collector.forms.%s or move it out of the group", p.name, p.key)
		}
	}
	return nil
}

func checkOCI(o *OCI) error {
	switch {
	case o.Runtime == "":
		return errors.New("oci.runtime is missing: an oci target names the container runtime that runs it, and the harness has no default")
	case o.Image == "":
		return errors.New("oci.image is missing")
	}
	return nil
}

func (b *BuildLink) check() error {
	p, err := netip.ParsePrefix(b.Prefix)
	if err != nil {
		return fmt.Errorf("relay.build_link.prefix %q is not a network in CIDR form", b.Prefix)
	}
	for _, a := range []struct{ key, v string }{{"relay", b.Relay}, {"guest", b.Guest}} {
		ip, err := addr("relay.build_link."+a.key, a.v)
		if err != nil {
			return err
		}
		if !p.Contains(ip) {
			return fmt.Errorf("relay.build_link.%s %s is not inside prefix %s", a.key, a.v, b.Prefix)
		}
	}
	return nil
}

func addr(key, v string) (netip.Addr, error) {
	if v == "" {
		return netip.Addr{}, fmt.Errorf("%s is missing", key)
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s %q is not an IP address", key, v)
	}
	return a, nil
}

func hostPort(key, v string) error {
	if host, port, err := net.SplitHostPort(v); err != nil || host == "" || port == "" {
		return fmt.Errorf("%s %q is not host:port", key, v)
	}
	return nil
}
