# Changelog

The harness the six specifications' suites share, released as the tags
`conformance/vX.Y.Z`. The newest version comes first. A change to this
directory adds the version it will be released as, and raises the `replace`
line of `go.work` to it.

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
  changed directory's newest release, and lets a specification require a
  pre-release of the harness's head; `speccheck modules` accepts `go.work`
  replace lines at such pre-releases and requires one for each a `go.mod`
  requires.

## v0.1.0

- The first release: the target-file format and its launchers, the runner and
  its report, the roles each suite drives a component through, the in-process
  attachment that runs every suite against the harness's own relay and
  collector under `go test`, the checks `ci` runs, and the `release`
  workflow's check of the tag it releases.
