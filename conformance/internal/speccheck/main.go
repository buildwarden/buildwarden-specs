// Command speccheck runs the repository's own checks, the ones ci runs
// beside go vet, go test and the coverage check of each suite. It is run
// from the repository's root by the Makefile:
//
//	speccheck docs <directory>...
//	speccheck modules <directory>...
//	speccheck release -base <ref> <directory>...
//
// The directories are the specifications'; the harness's is implied where a
// check reads it. docs runs the checks that read documents only; modules,
// the module checks a parser can make; release, the release checks of the
// change from the merge base of <ref> and HEAD to the working tree.
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
	usage := "usage:\n  speccheck docs <directory>...\n  speccheck modules <directory>...\n  speccheck release -base <ref> <directory>...\n"
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

func git(args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", errors.New(strings.TrimSpace("git " + strings.Join(args, " ") + ": " + err.Error() + ": " + errb.String()))
	}
	return out.String(), nil
}
