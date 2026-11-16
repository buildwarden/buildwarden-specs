package target

import "slices"

// Declared is what a component under test declares to the cases: the
// state a case is not applicable by. A case is reported not applicable only
// for what is here, never for what happened when it ran. A target file
// gives it through File.Declared; an attachment with no target file behind
// it (the harness's own roles under go test) builds it itself.
type Declared struct {
	// Role is the role of the component under test.
	Role string
	// Launcher names the launcher, or is empty where no launcher stands
	// behind the attachment.
	Launcher string

	// Mode, Link, BuildLink and AddressByLauncher are a relay's: see Relay.
	Mode              string
	Link              string
	BuildLink         *BuildLink
	AddressByLauncher bool
	// Address is the relay's own address on its build link where its
	// launcher assigns it (AddressByLauncher), and empty where the harness
	// cannot know it before a lease. A case on an "ip" link connects to it,
	// or to BuildLink's relay.
	Address string
	// ResolverConfig says that the relay is started with a resolver
	// configuration the harness gives it, which the cases for an absent
	// upstream_dns need. An external relay is not.
	ResolverConfig bool
	// ClaimToken says whether the relay can be started with a claim token,
	// and NoClaimToken whether it can be started without one.
	ClaimToken   bool
	NoClaimToken bool

	// Attachment, Forms, Capture and ReadBack are a collector's: see
	// Collector. Capture says that the harness can choose its capture mode.
	Attachment string
	Forms      Forms
	Capture    bool
	ReadBack   bool

	// FreshInstances says that the harness can have a fresh instance for
	// each case that ends one. Without it the target is one instance, and
	// a case that ends its instance is not applicable.
	FreshInstances bool
}

// Declared is what the file declares.
func (f File) Declared() Declared {
	d := Declared{Role: f.Role, Launcher: f.Launcher}
	var argv Argv
	var env map[string]string
	switch f.Launcher {
	case "exec":
		argv, env = f.Exec.Argv, f.Exec.Env
		d.FreshInstances = true
	case "oci":
		argv, env = f.OCI.Args, f.OCI.Env
		d.FreshInstances = true
	case "external":
		d.FreshInstances = len(f.External.Request) > 0
	}
	// required are the placeholders a start cannot leave without a value.
	var names, required []string
	for _, a := range argv {
		for _, w := range a.Words {
			names = append(names, placeholderNames(w)...)
			if !a.Optional {
				required = append(required, placeholderNames(w)...)
			}
		}
	}
	for _, v := range env {
		names = append(names, placeholderNames(v)...)
	}
	if r := f.Relay; r != nil {
		d.Mode, d.Link, d.BuildLink, d.AddressByLauncher = r.Mode, r.Link, r.BuildLink, r.AddressByLauncher
		if f.Launcher == "external" {
			d.Address = f.External.Address
			d.ClaimToken = f.External.Token != ""
			d.NoClaimToken = !d.ClaimToken
		} else {
			d.ResolverConfig = true
			d.ClaimToken = slices.Contains(names, "token")
			d.NoClaimToken = !slices.Contains(required, "token")
		}
	}
	if c := f.Collector; c != nil {
		d.Attachment, d.Forms, d.ReadBack = c.Attachment, c.Forms, c.ReadBack != nil
		d.Capture = slices.Contains(names, "capture")
	}
	return d
}

// RunsOn reports whether the file declares the host operating system goos.
func (f File) RunsOn(goos string) bool { return slices.Contains(f.OS, goos) }
