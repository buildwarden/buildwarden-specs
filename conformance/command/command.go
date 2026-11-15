// Package command is the body of every bw-conformance-<directory> command:
// each specification's cmd/ is one call to Main with its specification and
// its suite.
package command

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// Exit statuses of Main.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// Main runs the subcommand args name for the specification s and its
// suite, and returns the process's exit status.
func Main(s spec.Spec, cases []runner.Case, args []string, stdout, stderr io.Writer) int {
	name := "bw-conformance-" + s.Directory
	usage := func() {
		fmt.Fprintf(stderr, "usage:\n  %s run -target <file>\n  %s requirements\n  %s version\n", name, name, name)
	}
	if len(args) == 0 {
		usage()
		return ExitUsage
	}
	var err error
	switch args[0] {
	case "run":
		err = run(s, cases, args[1:], stdout, stderr)
	case "requirements":
		err = requirements(s, cases, args[1:], stdout, stderr)
	case "version":
		err = version(s, args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		usage()
		return ExitOK
	default:
		fmt.Fprintf(stderr, "%s: unknown subcommand %q\n", name, args[0])
		usage()
		return ExitUsage
	}
	var ue usageError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "%s %s: %v\n", name, args[0], err)
		return ExitUsage
	default:
		fmt.Fprintf(stderr, "%s %s: %v\n", name, args[0], err)
		return ExitFail
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// flags parses a subcommand's flags; a subcommand takes no positional
// argument.
func flags(fset *flag.FlagSet, args []string, stderr io.Writer) error {
	fset.SetOutput(stderr)
	if err := fset.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if fset.NArg() > 0 {
		return usageError{fmt.Sprintf("unexpected argument %q", fset.Arg(0))}
	}
	return nil
}

func run(s spec.Spec, cases []runner.Case, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("run", flag.ContinueOnError)
	targetFile := fset.String("target", "", "the target file that describes the component under test")
	if err := flags(fset, args, stderr); err != nil {
		return err
	}
	if *targetFile == "" {
		return usageError{"-target is required"}
	}
	l, err := s.Load()
	if err != nil {
		return err
	}
	if len(cases) == 0 {
		fmt.Fprintf(stdout, "%s %s: the suite has no cases yet; nothing was run against %s\n", s.Directory, l.Version, *targetFile)
		return nil
	}
	return fmt.Errorf("%s %s has %d cases, and this harness cannot run cases yet", s.Directory, l.Version, len(cases))
}

func requirements(s spec.Spec, cases []runner.Case, args []string, stdout, stderr io.Writer) error {
	if err := flags(flag.NewFlagSet("requirements", flag.ContinueOnError), args, stderr); err != nil {
		return err
	}
	l, err := s.Load()
	if err != nil {
		return err
	}
	citedBy := map[string][]string{}
	for _, c := range cases {
		for _, id := range c.Cites {
			citedBy[id] = append(citedBy[id], c.Name)
		}
	}
	reasons := map[string]string{}
	for _, u := range l.Unchecked {
		reasons[u.ID] = u.Reason
	}
	fmt.Fprintf(stdout, "%s %s (%s)\n", s.Directory, l.Version, s.Document)
	if len(l.Requirements) == 0 {
		fmt.Fprintln(stdout, "no requirements yet")
		return nil
	}
	for _, id := range l.Requirements {
		switch {
		case len(citedBy[id]) > 0:
			fmt.Fprintf(stdout, "%s\tcases: %s\n", id, strings.Join(citedBy[id], ", "))
		case reasons[id] != "":
			fmt.Fprintf(stdout, "%s\tnot machine-checked: %s\n", id, reasons[id])
		default:
			fmt.Fprintf(stdout, "%s\tneither cited by a case nor listed as not machine-checked\n", id)
		}
	}
	return nil
}

func version(s spec.Spec, args []string, stdout, stderr io.Writer) error {
	if err := flags(flag.NewFlagSet("version", flag.ContinueOnError), args, stderr); err != nil {
		return err
	}
	l, err := s.Load()
	if err != nil {
		return err
	}
	h, err := conformance.Version()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %s\nconformance %s\n", s.Directory, l.Version, h)
	if len(conformance.Models) == 0 {
		fmt.Fprintln(stdout, "models written from: none yet")
		return nil
	}
	fmt.Fprintln(stdout, "models written from:")
	for _, m := range conformance.Models {
		fmt.Fprintf(stdout, "  %s %s\n", m.Directory, m.Version)
	}
	return nil
}
