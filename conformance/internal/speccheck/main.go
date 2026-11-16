// Command speccheck runs the repository's own checks, the ones ci runs
// beside go vet, go test and the coverage check of each suite. It is run
// from the repository's root by the Makefile:
//
//	speccheck docs <directory>...
//	speccheck modules <directory>...
//	speccheck release -base <ref> <directory>...
//	speccheck tag -main <ref> <tag> <directory>...
//
// The directories are the specifications'; the harness's is implied where a
// check reads it. docs runs the checks that read documents only; modules,
// the module checks a parser can make; release, the release checks of the
// change from the merge base of <ref> and HEAD to the working tree. tag is
// the release workflow's check of the tag it releases: the checkout is at
// the tagged commit, that commit is on <ref>, and the tag is the version at
// the head of its directory's CHANGELOG.md.
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
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/check"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	usage := "usage:\n  speccheck docs <directory>...\n  speccheck modules <directory>...\n  speccheck release -base <ref> <directory>...\n  speccheck tag -main <ref> <tag> <directory>...\n"
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
		if fset.Parse(args[1:]) != nil || *base == "" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		err = release(repo, *base, fset.Args())
	case "tag":
		fset := flag.NewFlagSet("tag", flag.ContinueOnError)
		fset.SetOutput(stderr)
		onto := fset.String("main", "", "the ref the tagged commit must be on, such as origin/main")
		if fset.Parse(args[1:]) != nil || *onto == "" || fset.NArg() == 0 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		err = tag(repo, *onto, fset.Arg(0), fset.Args()[1:])
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
func release(repo fs.FS, base string, specs []string) error {
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
		tags, err := git("tag", "--list", dir+"/v*")
		if err != nil {
			return err
		}
		var versions []string
		for _, t := range strings.Fields(tags) {
			versions = append(versions, strings.TrimPrefix(t, dir+"/"))
		}
		dirs = append(dirs, check.DirRelease{
			Dir:     dir,
			Changed: strings.TrimSpace(changed+untracked) != "",
			Tags:    versions,
		})
	}
	return check.Release(repo, dirs)
}

// tag gathers from git what the tag check needs beside the files: that the
// working tree is the tagged commit's, so the files read are the release's,
// and that the commit is on onto, the ref of main.
func tag(repo fs.FS, onto, name string, specs []string) error {
	commit, err := git("rev-parse", "--verify", "refs/tags/"+name+"^{commit}")
	if err != nil {
		return fmt.Errorf("the tag %s: %w", name, err)
	}
	head, err := git("rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(head) != strings.TrimSpace(commit) {
		return fmt.Errorf("the checkout is at %s and the tag %s at %s: check out the tag", strings.TrimSpace(head), name, strings.TrimSpace(commit))
	}
	dirty, err := git("status", "--porcelain")
	if err != nil {
		return err
	}
	if strings.TrimSpace(dirty) != "" {
		return fmt.Errorf("the working tree differs from the tag %s:\n%s", name, strings.TrimRight(dirty, "\n"))
	}
	if _, err := git("merge-base", "--is-ancestor", strings.TrimSpace(commit), onto); err != nil {
		return fmt.Errorf("the tag %s is not on %s: a release is a tag on main (%w)", name, onto, err)
	}
	_, _, err = check.Tag(repo, name, specs)
	return err
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
