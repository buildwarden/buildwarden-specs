// Command speccheck runs the repository's own checks, the ones ci runs
// beside go vet, go test and the coverage check of each suite. It is run
// from the repository's root by the Makefile:
//
//	speccheck docs <directory>...
//	speccheck modules <directory>...
//	speccheck release -base <ref> [-program] <directory>...
//	speccheck tag -main <ref> [-program <ref>]... [-pushed] <tag> <directory>...
//
// The directories are the specifications'; the harness's is implied where a
// check reads it. docs runs the checks that read documents only; modules,
// the module checks a parser can make; release, the release checks of the
// change from the merge base of <ref> and HEAD to the working tree, with
// -program those of a program trunk's change (check.Release). tag is the
// release workflow's check of the tag it releases: the checkout is at the
// tagged commit, the tag's vX.Y.Z is the version at the head of its
// directory's CHANGELOG.md, and a specification's go.mod requires a harness
// version that is tagged, a release's a release. A release,
// <directory>/vX.Y.Z, is on the -main ref. A pre-release,
// <directory>/vX.Y.Z-dev.N or -rc.N, is on one of the -program refs, the
// program trunks; with -pushed, given when the tag has just been pushed and
// not on a rerun, its vX.Y.Z is also newer than every release of its
// directory.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/check"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	usage := "usage:\n  speccheck docs <directory>...\n  speccheck modules <directory>...\n  speccheck release -base <ref> [-program] <directory>...\n  speccheck tag -main <ref> [-program <ref>]... [-pushed] <tag> <directory>...\n"
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	repo := os.DirFS(".")
	var err error
	switch args[0] {
	case "docs":
		err = check.Docs(repo, args[1:])
	case "modules":
		err = check.Modules(repo, args[1:])
	case "release":
		fset := flag.NewFlagSet("release", flag.ContinueOnError)
		fset.SetOutput(stderr)
		base := fset.String("base", "", "the ref the change is measured from, such as origin/main")
		program := fset.Bool("program", false, "the change is a program trunk's, whose directories the loop tags as pre-releases")
		if fset.Parse(args[1:]) != nil || *base == "" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		err = release(repo, *base, *program, fset.Args())
	case "tag":
		fset := flag.NewFlagSet("tag", flag.ContinueOnError)
		fset.SetOutput(stderr)
		onto := fset.String("main", "", "the ref a release's commit must be on, such as origin/main")
		var programs []string
		fset.Func("program", "a program trunk a pre-release's commit may be on, such as origin/program/componentization; may be given more than once", func(ref string) error {
			if ref == "" {
				return errors.New("an empty ref")
			}
			programs = append(programs, ref)
			return nil
		})
		pushed := fset.Bool("pushed", false, "the tag has just been pushed: a pre-release's vX.Y.Z must be newer than every release of its directory (left out on a rerun)")
		if fset.Parse(args[1:]) != nil || *onto == "" || fset.NArg() == 0 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		err = tag(repo, *onto, programs, *pushed, fset.Arg(0), fset.Args()[1:])
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "speccheck %s:\n%v\n", args[0], err)
		return 1
	}
	fmt.Fprintf(stdout, "speccheck %s: ok\n", args[0])
	return 0
}

// release gathers from git what the release check needs: for the harness
// and each specification, whether the change touches it and which tags it
// has.
func release(repo fs.FS, base string, program bool, specs []string) error {
	mb, err := git("merge-base", base, "HEAD")
	if err != nil {
		return fmt.Errorf("the base %s: %w (the release check needs the history and the tags; in a workflow, a checkout with fetch-depth 0)", base, err)
	}
	mb = strings.TrimSpace(mb)
	var dirs []check.DirRelease
	for _, dir := range append([]string{check.Harness}, specs...) {
		changed, err := git("diff", "--name-only", mb, "--", dir)
		if err != nil {
			return err
		}
		untracked, err := git("ls-files", "--others", "--exclude-standard", "--", dir)
		if err != nil {
			return err
		}
		versions, err := tagged(dir)
		if err != nil {
			return err
		}
		dirs = append(dirs, check.DirRelease{
			Dir:     dir,
			Changed: strings.TrimSpace(changed+untracked) != "",
			Tags:    versions,
		})
	}
	return check.Release(repo, dirs, program)
}

// tagged returns the versions of the directory's tags, <dir>/v*, its
// pre-releases included.
func tagged(dir string) ([]string, error) {
	tags, err := git("tag", "--list", dir+"/v*")
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, t := range strings.Fields(tags) {
		versions = append(versions, strings.TrimPrefix(t, dir+"/"))
	}
	return versions, nil
}

// tag gathers from git what the tag check needs beside the files: that the
// working tree is the tagged commit's, so the files read are the release's;
// for a release, that the commit is on onto, the ref of main; for a
// pre-release, that the commit is on one of programs, the refs of the
// program trunks, and, when pushed, that its vX.Y.Z is newer than every
// release of its directory, so that it orders above what is released and
// below the release still to come; and for a specification's tag, that the
// harness version its go.mod requires is tagged, so that go install can
// resolve it, a release's being a release. The newer-than check is left out
// of a rerun by hand, which rebuilds a tag that exists, even once its
// release has been tagged.
func tag(repo fs.FS, onto string, programs []string, pushed bool, name string, specs []string) error {
	commit, err := git("rev-parse", "--verify", "refs/tags/"+name+"^{commit}")
	if err != nil {
		return fmt.Errorf("the tag %s: %w", name, err)
	}
	commit = strings.TrimSpace(commit)
	head, err := git("rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(head) != commit {
		return fmt.Errorf("the checkout is at %s and the tag %s at %s: check out the tag", strings.TrimSpace(head), name, commit)
	}
	dirty, err := git("status", "--porcelain")
	if err != nil {
		return err
	}
	if strings.TrimSpace(dirty) != "" {
		return fmt.Errorf("the working tree differs from the tag %s:\n%s", name, strings.TrimRight(dirty, "\n"))
	}
	t, err := check.Tag(repo, name, specs)
	if err != nil {
		return err
	}
	if !t.Prerelease {
		if _, err := git("merge-base", "--is-ancestor", commit, onto); err != nil {
			return fmt.Errorf("the tag %s is not on %s: a release is a tag on main (%w)", name, onto, err)
		}
		return harnessTagged(repo, t)
	}
	if len(programs) == 0 {
		return fmt.Errorf("the tag %s is a pre-release, and no program trunk is named (-program): a pre-release is a tag on a program trunk", name)
	}
	on := false
	for _, ref := range programs {
		if _, err := git("rev-parse", "--verify", "--quiet", ref+"^{commit}"); err != nil {
			return fmt.Errorf("the program trunk %s: %w (the checkout needs the program trunks; in a workflow, a checkout with fetch-depth 0)", ref, err)
		}
		if _, err := git("merge-base", "--is-ancestor", commit, ref); err == nil {
			on = true
			break
		}
	}
	if !on {
		return fmt.Errorf("the tag %s is not on %s: a pre-release is a tag on a program trunk", name, strings.Join(programs, " or "))
	}
	if pushed {
		versions, err := tagged(t.Dir)
		if err != nil {
			return err
		}
		if newest := check.Newest(check.Releases(versions)); newest != "" {
			switch c := semver.Compare(t.Release, newest); {
			case c == 0 || slices.Contains(versions, t.Release):
				return fmt.Errorf("the tag %s is a pre-release of %s/%s, which is already released: a pre-release comes before its release", name, t.Dir, t.Release)
			case c < 0:
				return fmt.Errorf("the tag %s is a pre-release of %s, and %s/%s is already released: a pre-release is of a version newer than every release of its directory", name, t.Release, t.Dir, newest)
			}
		}
	}
	return harnessTagged(repo, t)
}

// harnessTagged checks that the harness version a specification's tagged
// go.mod requires has its tag, which go install resolves when it builds the
// tag: a release's requirement is a release, and a pre-release's may be a
// pre-release of the harness on the program trunk, whose tag the loop
// pushes before the specifications'. The harness's own tag requires none.
func harnessTagged(repo fs.FS, t check.Tagged) error {
	if t.Dir == check.Harness {
		return nil
	}
	mod := t.Dir + "/go.mod"
	v, err := check.HarnessRequired(repo, t.Dir)
	if err != nil {
		return fmt.Errorf("%s: %w", mod, err)
	}
	if v == "" {
		return fmt.Errorf("%s: requires no harness (%s/%s)", mod, check.Module, check.Harness)
	}
	if !t.Prerelease && !check.IsRelease(v) {
		return fmt.Errorf("%s: requires the harness at %s, and the tag %s/%s is a release: a release requires a released harness", mod, v, t.Dir, t.Version)
	}
	if _, err := git("rev-parse", "--verify", "--quiet", "refs/tags/"+check.Harness+"/"+v); err != nil {
		return fmt.Errorf("%s: requires the harness at %s, and %s/%s has no tag: push the harness's tag first, then this one (go install resolves the harness at the version the go.mod requires)", mod, v, check.Harness, v)
	}
	return nil
}

func git(args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", errors.New(strings.TrimSpace("git " + strings.Join(args, " ") + ": " + err.Error() + ": " + errb.String()))
	}
	return out.String(), nil
}
