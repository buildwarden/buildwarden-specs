//go:build !linux

package sandbox

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// errNotLinux is every namespace operation's error off Linux: the sandbox is
// Linux namespaces, and the relay targets that need it declare os linux.
var errNotLinux = errors.New("the sandbox is built from Linux namespaces, and this host is " + runtime.GOOS)

func newNetNS() (*os.File, error)               { return nil, errNotLinux }
func inNS(*os.File, func() error) error         { return errNotLinux }
func startIn(*os.File, string, *exec.Cmd) error { return errNotLinux }
func socketPair() (*os.File, net.Conn, error)   { return nil, nil, errNotLinux }
func linkUp(string) error                       { return errNotLinux }
func addAddr(string, netip.Prefix) error        { return errNotLinux }
func addVeth(string, string, *os.File) error    { return errNotLinux }
func addDefaultRoute(netip.Addr) error          { return errNotLinux }
func addLinkRoute(string, netip.Prefix) error   { return errNotLinux }
func addLocalRoute(netip.Prefix) error          { return errNotLinux }
func delLink(string) error                      { return errNotLinux }

// Reexec is nil off Linux, where no relay target runs.
func Reexec(target.File, []string) *exec.Cmd { return nil }
