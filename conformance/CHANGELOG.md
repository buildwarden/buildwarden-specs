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
  `CHANGELOG.md` and is not yet tagged; any other suffix is refused. A
  release without a suffix is checked as before.

## v0.1.0

- The first release: the target-file format and its launchers, the runner and
  its report, the roles each suite drives a component through, the in-process
  attachment that runs every suite against the harness's own relay and
  collector under `go test`, the checks `ci` runs, and the `release`
  workflow's check of the tag it releases.
