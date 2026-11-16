// Package sandbox is what the exec and oci launchers start a relay under test
// in on Linux: network namespaces that are the relay's whole world, built by
// the harness itself over rtnetlink, with no program run but the relay the
// target file names and, for oci, the container runtime it names.
//
// One Sandbox belongs to one attachment. It holds the harness's namespace,
// where the harness's roles listen and dial on the claim side and the
// upstream, and in which every address of the documentation ranges is local
// (HarnessRanges): a case starts its resolvers on port 53 and its origins on
// 80 and 443 at any of them, as package upstream allows, and a host-mode
// relay, which refuses to dial loopback, private and link-local addresses,
// reaches them. Each Instance is one start of the relay and has namespaces of
// its own:
//
//   - the relay's, holding its build link (when the link is "ip") and then
//     its upstream link, a veth pair to the harness's namespace addressed
//     from LinkRange, on which it serves its claim endpoint (Claim) and over
//     which its default route goes. An exec relay gets a new namespace; an
//     oci relay's is its container's, started with no network of the
//     runtime's, which the sandbox joins and gives the same links;
//   - on an "ip" link, the build environment's, at the other end of the
//     build link's veth pair, where the harness's build environment listens
//     and dials. The attachment's build side is the newest open instance's:
//     the runner claims only a fresh instance, which its case ends, so the
//     instance a case claimed is the newest.
//
// On a "frames" link the relay gets one end of a datagram socket pair as file
// descriptor 3, and the harness keeps the other.
//
// The relay's interfaces are created in a fixed order, the build link's first
// and the upstream's second, and their names sort the same way. A
// container-mode relay that takes the first non-loopback IPv4 address it
// finds as its own (the Go relay's relay.DetectSelfIP) therefore takes its
// build address, and a vm-mode relay that takes the first interface of
// /sys/class/net in sorted order but lo takes its build interface.
//
// An exec relay is started in a mount namespace of its own in which
// /etc/resolv.conf is the sandbox's resolver configuration (ResolvConf) and
// /sys is a sysfs of the relay's network namespace; an oci relay has the file
// mounted into its container by the runtime.
//
// Every namespace is held by a file descriptor and has no name on the file
// system; every link is named after the harness process and the instance
// (Names), so two harness processes run on one host at once. An instance's
// links and namespaces are removed when it is closed, and the harness's
// namespace when the sandbox is.
//
// Building it needs root (CAP_SYS_ADMIN and CAP_NET_ADMIN) or, for an exec
// relay, unprivileged user namespaces, in which case the command re-runs
// itself in a user namespace of its own (Reexec). A sandbox that cannot be
// built is an error that names what is missing, never a skip. On other
// operating systems New is an error: the relay targets declare os linux.
package sandbox
