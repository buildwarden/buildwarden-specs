package check

import (
	"io/fs"
	"path"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// WorkFile is the workspace file at the repository's root.
const WorkFile = "go.work"

// Modules runs the module checks that need no tool but a parser, over the
// harness and the specification directories specs of the repository fsys:
// each go.mod declares its own directory's module path, requires no module
// of the kit and carries no replace line; go.work uses exactly these
// modules, and its replace lines are the harness's, pointing it at
// ./conformance: one at the version at the head of conformance/CHANGELOG.md,
// and one at each pre-release of that version, vX.Y.Z-dev.N or -rc.N, that
// a specification's go.mod requires, which a program trunk's go.mod may (see
// Release). A workspace module can only be replaced at a version, and a
// required version with no tag yet builds only through such a line. That
// go.mod and go.sum are what make tidy writes is the Makefile's check-tidy.
func Modules(fsys fs.FS, specs []string) error {
	var p problems
	dirs := append([]string{Harness}, specs...)
	for _, dir := range dirs {
		file := path.Join(dir, goModFile)
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			p.add(file, err)
			continue
		}
		mf, err := modfile.Parse(file, b, nil)
		if err != nil {
			p.add(file, err)
			continue
		}
		if want := Module + "/" + dir; mf.Module == nil || mf.Module.Mod.Path != want {
			p.addf(file, "does not declare the module %s", want)
		}
		for _, r := range mf.Require {
			if r.Mod.Path == Kit || strings.HasPrefix(r.Mod.Path, Kit+"/") {
				p.addf(file, "requires %s, a module of the kit; a suite that shared code with the Go relay would agree with its bugs", r.Mod.Path)
			}
		}
		for _, r := range mf.Replace {
			p.addf(file, "carries a replace line for %s; only go.work may replace the harness", r.Old.Path)
		}
	}

	harness, err := harnessVersion(fsys)
	p.add(path.Join(Harness, spec.ChangelogFile), err)
	b, err := fs.ReadFile(fsys, WorkFile)
	if err != nil {
		p.add(WorkFile, err)
		return p.err()
	}
	wf, err := modfile.ParseWork(WorkFile, b, nil)
	if err != nil {
		p.add(WorkFile, err)
		return p.err()
	}
	var used []string
	for _, u := range wf.Use {
		used = append(used, strings.TrimPrefix(path.Clean(u.Path), "./"))
	}
	for _, dir := range dirs {
		if !slices.Contains(used, dir) {
			p.addf(WorkFile, "does not use ./%s", dir)
		}
	}
	for _, u := range used {
		if !slices.Contains(dirs, u) {
			p.addf(WorkFile, "uses ./%s, which is not one of the seven modules", u)
		}
	}
	harnessPath := Module + "/" + Harness
	var found bool
	var replaced []string
	for _, r := range wf.Replace {
		if r.Old.Path != harnessPath {
			p.addf(WorkFile, "replaces %s; its replace lines are the harness's", r.Old.Path)
			continue
		}
		replaced = append(replaced, r.Old.Version)
		if r.Old.Version == harness {
			found = true
		} else if of, ok := PrereleaseOf(r.Old.Version); harness != "" && (!ok || of != harness) {
			p.addf(WorkFile, "replaces the harness at %q, and the head of conformance/CHANGELOG.md is %s: the harness is replaced at that version and its pre-releases only", r.Old.Version, harness)
		}
		if path.Clean(r.New.Path) != Harness || r.New.Version != "" {
			p.addf(WorkFile, "replaces the harness by %s, want ./%s", r.New.Path, Harness)
		}
	}
	if !found {
		p.addf(WorkFile, "has no replace line for %s at the version in progress", harnessPath)
	}
	if harness != "" {
		for _, dir := range specs {
			v, err := HarnessRequired(fsys, dir)
			if err != nil {
				continue // reported above
			}
			if of, ok := PrereleaseOf(v); ok && of == harness && !slices.Contains(replaced, v) {
				p.addf(WorkFile, "has no replace line for the harness at %s, which %s requires", v, path.Join(dir, goModFile))
			}
		}
	}
	return p.err()
}

// HarnessRequired is the harness version the go.mod of the directory dir
// requires, or "" when it requires none.
func HarnessRequired(fsys fs.FS, dir string) (string, error) {
	file := path.Join(dir, goModFile)
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", err
	}
	mf, err := modfile.Parse(file, b, nil)
	if err != nil {
		return "", err
	}
	for _, r := range mf.Require {
		if r.Mod.Path == Module+"/"+Harness {
			return r.Mod.Version, nil
		}
	}
	return "", nil
}

// harnessVersion is the version at the head of conformance/CHANGELOG.md.
func harnessVersion(fsys fs.FS) (string, error) {
	b, err := fs.ReadFile(fsys, path.Join(Harness, spec.ChangelogFile))
	if err != nil {
		return "", err
	}
	return spec.ChangelogVersion(b)
}

// DirRelease is what the release check needs to know of one module
// directory.
type DirRelease struct {
	// Dir is the directory: a specification's, or the harness's.
	Dir string
	// Changed says whether the change under check touches the directory.
	Changed bool
	// Tags are the versions of its tags <dir>/vX.Y.Z that exist.
	Tags []string
}

// Release runs the release checks over the repository fsys: each directory
// the change touches has, at the head of its CHANGELOG.md, a version higher
// than its newest tag, and a specification among them names in its go.mod
// the harness at the version at the head of conformance/CHANGELOG.md.
//
// With program, the change is a program trunk's, whose directories the loop
// tags as pre-releases (wf tag-next): a changed directory's head is then
// exactly NextRelease of its tags, the next minor after its newest release,
// which is the version tag-next proposes pre-releases of; and a changed
// specification's go.mod may instead require a pre-release of the harness's
// head, vX.Y.Z-dev.N or -rc.N, because on a program trunk the harness's head
// has only pre-release tags, and a specification's pre-release is built from
// the version its go.mod requires. Only a program trunk may: main's
// specifications name the harness's release.
func Release(fsys fs.FS, dirs []DirRelease, program bool) error {
	var p problems
	harness, err := harnessVersion(fsys)
	p.add(path.Join(Harness, spec.ChangelogFile), err)
	for _, d := range dirs {
		if !d.Changed {
			continue
		}
		file := path.Join(d.Dir, spec.ChangelogFile)
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			p.add(file, err)
			continue
		}
		v, err := spec.ChangelogVersion(b)
		if err != nil {
			p.add(file, err)
			continue
		}
		if newest := Newest(d.Tags); newest != "" && semver.Compare(v, newest) <= 0 {
			p.addf(file, "names %s at its head, and %s/%s is already tagged: a change to %s adds a newer version", v, d.Dir, newest, d.Dir)
		} else if next := NextRelease(d.Tags); program && v != next {
			p.addf(file, "names %s at its head, and a program trunk's change to %s heads it with %s, the next minor after its newest release, which the loop's pre-release tags %s/%s-dev.N are of", v, d.Dir, next, d.Dir, next)
		}
		if d.Dir == Harness || harness == "" {
			continue
		}
		mod := path.Join(d.Dir, goModFile)
		got, err := HarnessRequired(fsys, d.Dir)
		if err != nil {
			p.add(mod, err)
			continue
		}
		if got == harness {
			continue
		}
		if of, ok := PrereleaseOf(got); ok && of == harness {
			if !program {
				p.addf(mod, "requires the harness at %q, a pre-release, and the head of conformance/CHANGELOG.md is %s: only a program trunk's specification requires a pre-release of the harness", got, harness)
			}
			continue
		}
		if program {
			p.addf(mod, "requires the harness at %q, and the head of conformance/CHANGELOG.md is %s: a program trunk's specification requires %s or a pre-release of it, %s-dev.N or %s-rc.N", got, harness, harness, harness, harness)
			continue
		}
		p.addf(mod, "requires the harness at %q, and the head of conformance/CHANGELOG.md is %s", got, harness)
	}
	return p.err()
}

// Newest returns the highest of the versions, ignoring any that is not a
// semantic version, or "" when there is none.
func Newest(versions []string) string {
	newest := ""
	for _, v := range versions {
		if semver.IsValid(v) && (newest == "" || semver.Compare(v, newest) > 0) {
			newest = v
		}
	}
	return newest
}
