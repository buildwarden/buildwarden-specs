# Changelog

The harness the six specifications' suites share, released as the tags
`conformance/vX.Y.Z`. The newest version comes first. A change to this
directory adds the version it will be released as, and raises the `replace`
line of `go.work` to it.

## v0.2.1

- A capturing stack, `netstack.Stack.Capture` (the in-process relay's),
  keeps no TCP TIME-WAIT. gVisor hands a SYN that reuses the 4-tuple of a
  connection in TIME-WAIT only to a listening endpoint, never to a
  forwarder, so the in-process relay ignored a reconnection from a source
  port the build environment had used before for 60 s, against GUEST-6, and
  a case's dial gave up at its 10 s. A stack that only dials keeps gVisor's
  default.
- The oci launcher bounds the runtime's start of a relay's container by
  `CommandLimit` (60 s), the bound of a target's own command, not the
  relay's `sandbox.StartLimit`, which still runs from when the container is
  running; that failure says the runtime did not start the container and
  the relay under test was never running. Each oci start records when the
  runtime's run started, when inspect first returned the container, when it
  had a process and when the claim endpoint answered, and a failed start
  prints them with the runtime's inspect state of the container.

## v0.2.0

- The `release` workflow's check of the tag it releases, `speccheck tag`,
  accepts a pre-release, `<directory>/vX.Y.Z-dev.N` or
  `<directory>/vX.Y.Z-rc.N`, on a program trunk it names with `-program`,
  when its X.Y.Z is the version at the head of the directory's
  `CHANGELOG.md` and, with `-pushed`, newer than every release of the
  directory; any other suffix is refused. For a specification's tag it also
  checks that the harness version its `go.mod` requires is tagged, and a
  release's is a release.
- `speccheck release -program` (the Makefile's `PROGRAM`, which `ci` sets on
  `program/**`) holds a program trunk's change to the next minor after each
  changed directory's newest release, and a changed specification, while
  the harness's head is unreleased, to the pre-release of it the tree's
  harness is: its newest tag, or the next `-dev` tag when the change touches
  the harness. `speccheck modules` accepts a `go.work` replace line at a
  pre-release of the harness's head only when a `go.mod` requires it, and
  requires one for each a `go.mod` requires.
- `speccheck release` measures a changed directory's head against its newest
  release, not its newest tag, so a program trunk's pre-release tags do not
  stop `main` from releasing a patch or a minor below them.

## v0.1.0

- The first release: the target-file format and its launchers, the runner and
  its report, the roles each suite drives a component through, the in-process
  attachment that runs every suite against the harness's own relay and
  collector under `go test`, the checks `ci` runs, and the `release`
  workflow's check of the tag it releases.
