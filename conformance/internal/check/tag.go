package check

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// prerelease is a pre-release version: vX.Y.Z-dev.N or vX.Y.Z-rc.N, N
// counting from 1, with no leading zero and no build metadata. Its first
// group is vX.Y.Z, the release it comes before.
var prerelease = regexp.MustCompile(`^(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-(?:dev|rc)\.[1-9][0-9]*$`)

// release is a release version, vX.Y.Z with no suffix, its three numbers
// in its groups.
var release = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// PrereleaseOf returns the release vX.Y.Z that the version v comes before
// when v is a pre-release, vX.Y.Z-dev.N or vX.Y.Z-rc.N, and whether it is.
func PrereleaseOf(v string) (string, bool) {
	m := prerelease.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// IsRelease says whether the version v is a release, vX.Y.Z with no suffix.
func IsRelease(v string) bool {
	return release.MatchString(v)
}

// Releases returns the versions that are releases, vX.Y.Z with no suffix,
// dropping the pre-releases and anything else.
func Releases(versions []string) []string {
	var out []string
	for _, v := range versions {
		if IsRelease(v) {
			out = append(out, v)
		}
	}
	return out
}

// NextRelease is the version a program change to a directory is released
// as, given the versions of the directory's tags: the next minor after its
// newest release, pre-releases ignored, or v0.1.0 when it has none. It is
// the version the loop's wf tag-next proposes pre-releases of, so a program
// trunk heads a changed directory's CHANGELOG.md with it.
func NextRelease(versions []string) string {
	newest := Newest(Releases(versions))
	if newest == "" {
		return "v0.1.0"
	}
	m := release.FindStringSubmatch(newest)
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return "v0.1.0"
	}
	return fmt.Sprintf("v%s.%d.0", m[1], minor+1)
}

// Tagged is what a tag names, once Tag has checked it.
type Tagged struct {
	// Dir is the directory: the harness's, or a specification's.
	Dir string
	// Version is the tag without its directory: vX.Y.Z, vX.Y.Z-dev.N or
	// vX.Y.Z-rc.N.
	Version string
	// Release is the version without its suffix, vX.Y.Z: the version itself
	// for a release, and the release a pre-release comes before.
	Release string
	// Prerelease says whether the version has a suffix.
	Prerelease bool
}

// Tag checks a release tag against the repository fsys as it is at the
// tagged commit, which is what the release workflow checks before it builds
// anything. The tag is <dir>/<version>, where dir is the harness's directory
// or one of the specification directories specs, and the version is one of:
//
//   - vX.Y.Z, a release: the version at the head of the directory's
//     CHANGELOG.md;
//   - vX.Y.Z-dev.N or vX.Y.Z-rc.N, a pre-release, N counting from 1: its
//     vX.Y.Z is the version at the head of the directory's CHANGELOG.md,
//     the release it is a pre-release of, so that it orders below that
//     release and its notes are that version's section.
//
// Any other suffix is refused. Which ref the tagged commit must be on, main
// for a release and a program trunk for a pre-release, and that a
// pre-release's vX.Y.Z is not already released, are read from git by the
// caller.
func Tag(fsys fs.FS, tag string, specs []string) (Tagged, error) {
	dir, version, ok := strings.Cut(tag, "/")
	if !ok || strings.Contains(version, "/") {
		return Tagged{}, fmt.Errorf("the tag %q is not <directory>/vX.Y.Z", tag)
	}
	if dir != Harness && !slices.Contains(specs, dir) {
		return Tagged{}, fmt.Errorf("the tag %q names %s, which is not the harness's directory or one of the specifications: %s %s",
			tag, dir, Harness, strings.Join(specs, " "))
	}
	t := Tagged{Dir: dir, Version: version, Release: version}
	if strings.Contains(version, "-") {
		r, ok := PrereleaseOf(version)
		if !ok {
			return Tagged{}, fmt.Errorf("the tag %q has a suffix that is not -dev.N or -rc.N: a pre-release is <directory>/vX.Y.Z-dev.N or <directory>/vX.Y.Z-rc.N, N counting from 1", tag)
		}
		t.Release, t.Prerelease = r, true
	}
	file := path.Join(dir, spec.ChangelogFile)
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return Tagged{}, fmt.Errorf("%s: %w", file, err)
	}
	head, err := spec.ChangelogVersion(b)
	if err != nil {
		return Tagged{}, fmt.Errorf("%s: %w", file, err)
	}
	if t.Release != head {
		if t.Prerelease {
			return Tagged{}, fmt.Errorf("%s: names %s at its head, and the tag %s is a pre-release of %s: a pre-release is of the version at the head of its directory's CHANGELOG.md",
				file, head, tag, t.Release)
		}
		return Tagged{}, fmt.Errorf("%s: names %s at its head, and the tag is %s: a release is the version at the head of its directory's CHANGELOG.md",
			file, head, tag)
	}
	return t, nil
}
