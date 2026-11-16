//go:build linux

package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// onThread runs f on an OS thread of its own, which is thrown away after it:
// f changes the thread's namespaces, and a goroutine that ends locked to its
// thread ends the thread with it, so no other goroutine runs in them.
func onThread(f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		done <- f()
	}()
	return <-done
}

// newNetNS creates a network namespace and returns the file that holds it.
func newNetNS() (*os.File, error) {
	var ns *os.File
	err := onThread(func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("unshare: %w", err)
		}
		var err error
		ns, err = os.Open("/proc/thread-self/ns/net")
		return err
	})
	return ns, err
}

// inNS runs f in the network namespace ns: a socket f makes is in it.
func inNS(ns *os.File, f func() error) error {
	return onThread(func() error {
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("setns: %w", err)
		}
		return f()
	})
}

// startIn starts cmd in the network namespace ns and in a mount namespace of
// its own, in which resolv is bound over /etc/resolv.conf and /sys is a sysfs
// of ns. The process is forked from the thread that holds both.
func startIn(ns *os.File, resolv string, cmd *exec.Cmd) error {
	return onThread(func() error {
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return fmt.Errorf("the relay's mount namespace: unshare: %w", err)
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return fmt.Errorf("the relay's mount namespace: making / private: %w", err)
		}
		if err := unix.Mount(resolv, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("binding %s over /etc/resolv.conf: %w", resolv, err)
		}
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("the relay's network namespace: setns: %w", err)
		}
		if err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			return fmt.Errorf("mounting the relay's /sys: %w", err)
		}
		return cmd.Start()
	})
}

// socketPair is a frame link: a datagram socket pair, the relay's end as a
// file to inherit and the harness's as a connection.
func socketPair() (*os.File, net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	}
	relay := os.NewFile(uintptr(fds[0]), "frames-relay")
	h := os.NewFile(uintptr(fds[1]), "frames-harness")
	c, err := net.FileConn(h)
	_ = h.Close()
	if err != nil {
		_ = relay.Close()
		return nil, nil, err
	}
	return relay, c, nil
}

// Reexec is the command that runs args again in a user namespace of its own,
// in which this process's user is root, when the sandbox for the target f
// needs it (an exec relay, by a process that is not root), and nil
// otherwise. The command is this program: the sandbox starts no other.
func Reexec(f target.File, args []string) *exec.Cmd {
	if !reexecs(f, os.Geteuid(), os.Getenv(UserNSEnv) != "") {
		return nil
	}
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Env = append(os.Environ(), UserNSEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
	}
	return cmd
}
