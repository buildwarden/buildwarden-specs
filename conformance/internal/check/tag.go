package check

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// Tag checks a release tag against the repository fsys as it is at the
// tagged commit, which is what the release workflow checks before it builds
// anything: the tag is <dir>/vX.Y.Z, where dir is the harness's directory or
// one of the specification directories specs, and that version is the one at
// the head of the directory's CHANGELOG.md. It returns the directory and the
// version. That the tagged commit is on main is read from git by the caller.
func Tag(fsys fs.FS, tag string, specs []string) (dir, version string, err error) {
	dir, version, ok := strings.Cut(tag, "/")
	if !ok || strings.Contains(version, "/") {
		return "", "", fmt.Errorf("the tag %q is not <directory>/vX.Y.Z", tag)
	}
	if dir != Harness && !slices.Contains(specs, dir) {
		return "", "", fmt.Errorf("the tag %q names %s, which is not the harness's directory or one of the specifications: %s %s",
			tag, dir, Harness, strings.Join(specs, " "))
	}
	file := path.Join(dir, spec.ChangelogFile)
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", file, err)
	}
	head, err := spec.ChangelogVersion(b)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", file, err)
	}
	if version != head {
		return "", "", fmt.Errorf("%s: names %s at its head, and the tag is %s: a release is the version at the head of its directory's CHANGELOG.md",
			file, head, tag)
	}
	return dir, version, nil
}
