package sandbox

import (
	"errors"
	"fmt"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// ErrPrivilege is wrapped by the error for a sandbox that this process may
// not build.
var ErrPrivilege = errors.New("the sandbox needs root or unprivileged user namespaces")

// UserNSEnv is set in the environment of the command Reexec re-runs in a user
// namespace of its own, so that it builds the sandbox there and does not
// re-run itself again.
const UserNSEnv = "BW_CONFORMANCE_USERNS"

// Probe is what the sandbox learns of this process before it builds anything.
// New uses the host's; the tests inject theirs.
type Probe struct {
	// Euid is the process's effective user ID.
	Euid int
	// InUserNS says that the process is the command Reexec re-ran.
	InUserNS bool
	// NetNS creates a network namespace and drops it: the first thing a
	// sandbox does, and the one that needs the privilege.
	NetNS func() error
}

// check is nil when this process may build the sandbox for the launcher
// named, and otherwise an error that names what is missing.
func (p Probe) check(launcher string) error {
	if launcher == "oci" && (p.Euid != 0 || p.InUserNS) {
		who := fmt.Sprintf("uid %d", p.Euid)
		if p.InUserNS {
			who += " in a user namespace of its own"
		}
		return fmt.Errorf("%w: the oci launcher needs root, since the harness joins the network namespace the container runtime made to give the container its links, and this process runs as %s", ErrPrivilege, who)
	}
	err := p.NetNS()
	switch {
	case err == nil:
		return nil
	case p.InUserNS:
		return fmt.Errorf("%w: this process re-ran itself in a user namespace of its own, and creating a network namespace there failed (%v); the host restricts what an unprivileged user namespace may do, so run as root", ErrPrivilege, err)
	case p.Euid == 0:
		return fmt.Errorf("%w: this process runs as root, and creating a network namespace failed (%v); it needs CAP_SYS_ADMIN and CAP_NET_ADMIN", ErrPrivilege, err)
	}
	return fmt.Errorf("%w: this process runs as uid %d, not in a user namespace of its own, and creating a network namespace failed (%v)", ErrPrivilege, p.Euid, err)
}

// reexecs reports whether a command that runs the target f, as effective user
// euid, re-runs itself in a user namespace of its own: an exec relay, not run
// as root, by a command that is not already the re-run one.
func reexecs(f target.File, euid int, inUserNS bool) bool {
	return f.Role == "relay" && f.Launcher == "exec" && euid != 0 && !inUserNS
}
