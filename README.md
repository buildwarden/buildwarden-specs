# buildwarden-specs

Seam specifications for BuildWarden and their conformance suites.

A *seam* is a boundary between two of BuildWarden's components that another
implementation may take the place of one side of. Each specification here says
what crosses one seam, in numbered requirements, and comes with a suite of
cases that checks an implementation against them. The project, its
documentation and its issue tracker are in
[buildwarden/buildwarden](https://github.com/buildwarden/buildwarden); the
book's [Component seams](https://buildwarden.github.io/buildwarden/concepts/seams.html)
page says which package implements each seam there.

## Specifications

Each directory is one specification: its document `v1.md`, its JSON Schemas
and OpenAPI descriptions, its suite in `cases/`, the command that runs the
suite, and its `CHANGELOG.md`. A release of a specification is a tag
`<directory>/vX.Y.Z` on `main` (**Releases**, below).

| Seam | Specification | Requirement prefix | Newest release |
|---|---|---|---|
| 1, the claim | [`relay-claim`](relay-claim/v1.md) | `CLAIM` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/relay-claim/v0.1.0) |
| 2, the outputs a collector stores | [`collector-outputs`](collector-outputs/v1.md) | `COLLOUT` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/collector-outputs/v0.1.0) |
| 2, the inputs and signals a collector serves | [`collector-inputs`](collector-inputs/v1.md) | `COLLIN` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/collector-inputs/v0.1.0) |
| 3, the relay's guest API | [`relay-guest-api`](relay-guest-api/v1.md) | `GUEST` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/relay-guest-api/v0.1.0) |
| 5, the executor's `initialize` | [`executor-initialize`](executor-initialize/v1.md) | `INIT` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/executor-initialize/v0.1.0) |
| 6, the bootstrap config | [`bootstrap-config`](bootstrap-config/v1.md) | `BOOTCFG` | [`v0.1.0`](https://github.com/buildwarden/buildwarden-specs/releases/tag/bootstrap-config/v0.1.0) |

`conformance/` is not a specification: it is the harness the six suites share,
a Go module released under its own tags `conformance/vX.Y.Z`, with no
requirements and no binaries of its own.

The build ledger's format and its metadata schemas (seam 4) are specified in
[buildwarden/buildwarden under `specs/`](https://github.com/buildwarden/buildwarden/tree/main/specs)
and move here at milestone M6. Until then these directory names are reserved
for them: `build-ledger/`, `metadata-<name>/` and `environment-<type>/`. The
name `driver-contract/` is reserved for the driver contract (seam 9).

## Implementations

| Implementation | Repository | Implements |
|---|---|---|
| The Go relay, `cmd/relay` | [buildwarden/buildwarden](https://github.com/buildwarden/buildwarden) | `relay-claim` (relay), `collector-outputs` and `collector-inputs` (relay), `relay-guest-api`, `bootstrap-config` (carrier) |
| The disk collector, `cmd/collector` | [buildwarden/buildwarden](https://github.com/buildwarden/buildwarden) | `collector-outputs` and `collector-inputs` (collector), `bootstrap-config` (producer), `relay-claim` (claimant) |
| The executor, `cmd/warden-io` | [buildwarden/buildwarden](https://github.com/buildwarden/buildwarden) | `executor-initialize`, `bootstrap-config` (reader) |

## Conventions

These hold in every specification directory.

- **The document.** `v<N>.md` is version `N` of the protocol or format. Every
  document has the same sections, in this order: Scope and roles; Transport;
  Messages and fields; Ordering; Errors; Limits; Versioning; Conformance; and
  Known divergences, where what the reference implementation does differs from
  a rule or a comment of its own repository. Its header links the book's page
  for the concept and names the reference implementation.
- **Requirements.** Each normative statement uses the RFC 2119 words and is
  numbered. Its identifier is the specification's prefix, a hyphen and a
  decimal number with no leading zero: `CLAIM-7`. A requirement is stated in
  a paragraph or a list item that starts with its identifier in bold followed
  by a full stop, `**CLAIM-7.** The relay MUST ...`; an identifier elsewhere
  in the text, or inside a code block, refers to one and states nothing. An
  identifier is unique in its document and is never given to another
  requirement, also after the one it named is removed. A document states only
  requirements with its own prefix, and names another specification by its
  directory and section.
- **Requirements that no case checks** are listed in the directory's
  `not-machine-checked.txt`, one to a line: the identifier, a space and the
  reason. Blank lines and lines that start with `#` are ignored. Every
  requirement is cited by a case of the directory's own suite or listed
  there.
- **Cases.** A suite is the package `cases/` of its directory's module, which
  exports its cases as `Cases`. Each case is a `runner.Case` of the harness and
  names, in its `Cites` field, the requirements it checks, which are its own
  specification's only. It also names the role of the component it runs
  against (`Role`, `relay` or `collector`); whether it ends the instance it
  runs against (`Ends`), so that it is given a fresh one while the cases that
  leave theirs usable share one; and, in `Applies`, what it needs the target
  to declare, which is the only way a case is not applicable. A case reaches
  the component and the networks around it through the attachment its
  `runner.T` gives it, and never opens a socket of its own choosing.
  `executor-initialize` has no suite yet: its cases are for the item that
  changes the executor's `initialize`, and every one of its requirements is
  on its list.
- **The directory's package.** The Go package at the root of each directory
  embeds the document with its schemas and OpenAPI descriptions (`v1*`), the
  `CHANGELOG.md` and the list, so that a command built with `go install`
  carries them.
- **The command.** `cmd/bw-conformance-<directory>` runs the suite.
  `run -target <file>` runs it against the component a target file describes
  (below): the cases for the target's role, each reported as `pass`, `fail` or
  `n/a` (not applicable by what the target declares), with no skip and no
  retry; when the suite has no case for that role it says so and does not
  fail. Each case's line names its verdict, the specification and its
  version, the harness's version, the case and the requirements it cites; a
  failure is followed by what failed and the output of the instances it used,
  and the report's last line counts the verdicts. `run` exits 1 when a case
  failed or the target cannot be run on this host (a launcher this harness
  does not build yet, an `os` that does not name the host, a sandbox this
  process may not build), and 2 on a usage
  error. `requirements` lists each requirement with the cases that cite it or
  the reason it has none, and `version` prints the specification's version,
  the harness's, and the specification versions the harness's models were
  written from, which every report carries too.
- **Target files.** A target file is TOML and describes one component under
  test: its `role` (`relay` or `collector`), the host operating systems it
  runs on (`os`), its `launcher` (`exec`, a program; `oci`, an image;
  `external`, already running) with that launcher's table, and the attachment
  points of its role in `[relay]` or `[collector]`. It names no specification
  and no version. A key the format does not name is an error. Command lines
  hold placeholders, `{claim}`, `{token}` and, for a collector, `{out}`,
  `{context}`, `{script}` and `{capture}`, and an element of a command line
  that is itself an array is an optional group, given only when the start
  has a value for each placeholder in it. The `exec` program gets exactly the
  `env` the file gives, and the variables of the harness's own environment
  that `pass_env` names. The package comment of `conformance/target` gives
  the format key by key. This harness release runs a collector that claims
  by `exec`, a relay by `exec` or `oci` in the Linux sandbox (below), and a
  relay by `external`; a collector by `oci` and a collector that `listens`
  are errors that say they are not built yet.
- **The sandbox.** `conformance/sandbox` is where the `exec` and `oci`
  launchers start each instance of a relay, on Linux only: network
  namespaces that are the relay's whole world, made by the harness over
  rtnetlink with no program run but the relay the target file names and, for
  `oci`, the container runtime it names. Every address of the documentation
  ranges is the harness's, so a case starts its resolvers on port 53 and its
  origins on 80 and 443 at any of them; the relay reaches them over a link of
  its own, on whose address it serves its claim endpoint (`{claim}`). A
  `frames` link is a datagram socket pair, the relay's end its file
  descriptor 3; an `ip` link is a veth pair to a namespace of the build
  environment's, and the relay's end is created before its upstream link, so
  that a relay that takes its first address as its own takes its build
  address. An `exec` relay runs in a mount namespace with the sandbox's
  resolver configuration bound over `/etc/resolv.conf` and a sysfs of its own
  network namespace on `/sys`; an `oci` relay is run with no network of the
  runtime's (`--network none`), the file mounted in, and is given the same
  links in its container's namespace. Every link and container is named after
  the harness process and the instance and removed when the instance ends, so
  two runs share a host. Building it needs root or, for `exec`, unprivileged
  user namespaces, in which case the command re-runs itself in a user
  namespace of its own; `oci` needs root. A sandbox that cannot be built is
  an error that names what is missing, never a skip. The package comment
  gives the address plan.
- **The harness's roles.** A case drives the component under test through
  the harness's models of the roles around it, each a package of
  `conformance/`, written from the documents and sharing no code with the
  component: `claimant` claims a relay (`relay-claim`), opening the tunnel
  and serving the collector protocol on it; `collector` is the collector
  that tests a relay (`collector-outputs`, `collector-inputs`, and the
  bootstrap config it serves), startable in every form a collector target
  may declare and recording each request it received in order; `relay` is
  the harness's relay, both the relay that tests a collector (`relay-claim`'s
  relay, and the relay's side of `collector-outputs` and `collector-inputs`)
  and a relay under test in its own right, with its build side
  (`relay-guest-api`, and the relay's part of `bootstrap-config`) in each of
  the three modes; `buildenv` is the build environment, on a frame link with
  its own network stack (`netstack`, `dhcp`) or on an IP link; `upstream` is
  the relay's upstream world, its resolvers, origins and their CA; `ledger`
  verifies a ledger the relay wrote, and `ledgerwriter` writes the harness
  relay's own, each written separately from buildwarden/buildwarden's
  `specs/build-ledger/v1.md` at the commit its package comment names. Their
  package comments say how each reads what its documents leave open.
- **The in-process attachment.** `conformance/inprocess` gives the runner the
  harness's own relay, in each of its three modes, and its own collector, in
  each of its forms, from memory, on in-memory networks (`memnet`): what a
  launcher gives a real component from the kernel. A module's `go test` runs
  its suite against each of these configurations, so that a suite and the
  model written beside it cannot disagree unnoticed, with no root, namespace
  or container runtime. It is not a launcher: no target file and no command
  can name it.
- **Versions.** Each directory's `CHANGELOG.md` starts with the version its
  next release will be, `## vX.Y.Z`, newest first; a pull request that changes
  a directory adds that version, and names it in the directory's row of the
  index above. The command reads its version from there. A
  specification's `go.mod` names the harness version it is released with.

## Releases

A release is a tag `<directory>/vX.Y.Z` on a commit of `main`, one directory
to a tag, at the version at the head of that directory's `CHANGELOG.md`; a
pre-release, below, is one with a suffix on a program trunk. A tag
is never moved: a fault found after a release is fixed by a pull request and a
new release of the directory at fault.

- **A specification's release** carries its command. The `release` workflow
  builds `bw-conformance-<directory>` with
  `go install github.com/buildwarden/buildwarden-specs/<directory>/cmd/bw-conformance-<directory>@<directory>/vX.Y.Z`,
  with `CGO_ENABLED=0`, for Linux, macOS and Windows on `amd64` and `arm64`,
  and attaches the six binaries,
  `bw-conformance-<directory>_vX.Y.Z_<os>_<arch>` (`.exe` on Windows), with
  `SHA256SUMS`. A binary carries the harness its release names, and so does a
  build from a `go.mod` that names the tag: `go install` builds exactly what
  the tag serves, with the versions its `go.mod` lists.
- **The harness's release**, `conformance/vX.Y.Z`, attaches nothing. Its tag
  is pushed before the tags of the specifications that name it, because
  `go install` resolves it.
- **A pre-release** is a tag `<directory>/vX.Y.Z-dev.N` or
  `<directory>/vX.Y.Z-rc.N`, `N` counting from 1, the harness's included,
  which the development loop pushes on the program trunk
  `program/componentization`. Its commit is on the program trunk, and its
  `vX.Y.Z` is the version at the head of the directory's `CHANGELOG.md`, the
  next minor after the directory's newest release, which is what the loop's
  `wf tag-next` proposes and what `ci` requires of a program trunk's change
  (`make check-release PROGRAM=1`). So it orders above every release and
  below the release still to come; when pushed, a tag whose `vX.Y.Z` is not
  newer than every release is refused. It is built and attached as a
  release is, and published as a GitHub pre-release that is never marked
  latest, with the `CHANGELOG.md` section of `vX.Y.Z` as its notes. Any
  other suffix is refused. Only a program trunk's pins may name a
  pre-release.
- **A specification's go.mod on a program trunk** requires the harness at
  the head of `conformance/CHANGELOG.md` when that is released. When it is
  not, the harness's head has only pre-release tags and `go install`
  resolves the version the `go.mod` requires, so a changed specification
  requires the pre-release the tree's harness is: the harness's newest
  pre-release of its head, `conformance vX.Y.Z-dev.N` or `-rc.N`, or, when
  the same change touches the harness, the next `-dev` tag `wf tag-next`
  pushes for it at that merge (`make check-release PROGRAM=1` checks which).
  `go.work` then replaces that version by `./conformance` too, and a replace
  line at a pre-release no `go.mod` requires is refused. The harness's tag
  is pushed first, and the `release` workflow confirms the required harness
  version is tagged before it builds (a release's must be a release). On
  `main`, a specification requires the harness's release.
- **Main's releases ignore the pre-releases.** A change on `main` heads a
  directory above its newest release, not its newest tag, so it may still
  release a patch or a minor below the version a program trunk's
  pre-releases are of.
- **Tags are pushed one to a push,** because a push of more than three tags
  starts no workflow run. A run that was missed or that failed is made again
  by hand, `release` with the existing tag as its input, without touching
  the tag.

The `implementations` workflow, weekly and on demand, runs the newest release
of each specification's suite against each known implementation at its newest
release, and publishes the table in its run's summary. It is not a merge gate:
a specification change is merged before the code that implements it. It runs
the Go relay's image, `ghcr.io/buildwarden/relay:<tag>` at
buildwarden/buildwarden's newest release tag, with the target file
`tools/conformance/targets/relay-oci.toml` of that release, and each released
binary checked against its `SHA256SUMS`; a release that has no such file is
named so in the table and nothing is run against it.

## Working here

The seven modules form one workspace, `go.work`, whose `replace` line names
the harness version in progress, the one at the head of
`conformance/CHANGELOG.md`.

- `make check` runs everything `ci` runs.
- `make tidy` tidies each module's `go.mod` and `go.sum`. Run it instead of
  `go mod tidy`: a specification names a harness version that has no tag until
  it is released, which `go mod tidy` alone cannot resolve.
- No module here requires `github.com/buildwarden/buildwarden`: a suite that
  shared code with the Go relay would agree with its bugs.
