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
`<directory>/vX.Y.Z`; none is released yet.

| Seam | Specification | Requirement prefix | Newest release |
|---|---|---|---|
| 1, the claim | [`relay-claim`](relay-claim/v1.md) | `CLAIM` | none yet |
| 2, the outputs a collector stores | [`collector-outputs`](collector-outputs/v1.md) | `COLLOUT` | none yet |
| 2, the inputs and signals a collector serves | [`collector-inputs`](collector-inputs/v1.md) | `COLLIN` | none yet |
| 3, the relay's guest API | [`relay-guest-api`](relay-guest-api/v1.md) | `GUEST` | none yet |
| 5, the executor's `initialize` | [`executor-initialize`](executor-initialize/v1.md) | `INIT` | none yet |
| 6, the bootstrap config | [`bootstrap-config`](bootstrap-config/v1.md) | `BOOTCFG` | none yet |

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
