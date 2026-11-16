// Package command is the body of every bw-conformance-<directory> command:
// each specification's cmd/ is one call to Main with its specification and
// its suite.
package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance"
	"github.com/buildwarden/buildwarden-specs/conformance/internal/coverage"
	"github.com/buildwarden/buildwarden-specs/conformance/launch"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
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
		fmt.Fprintf(stderr, "usage:\n  %s run -target <file>\n  %s requirements [-check]\n  %s version\n", name, name, name)
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
	case errors.Is(err, errCasesFailed):
		return ExitFail
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

// errCasesFailed is run's error when the report has a failure; the report
// has already said which.
var errCasesFailed = errors.New("cases failed")

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
	if err := runner.Check(cases); err != nil {
		return fmt.Errorf("the suite:\n%w", err)
	}
	h, err := conformance.Version()
	if err != nil {
		return err
	}
	tf, err := target.Read(*targetFile)
	if err != nil {
		return err
	}
	if !tf.RunsOn(runtime.GOOS) {
		return fmt.Errorf("%s declares os %s, and this host's is %s", *targetFile, strings.Join(tf.OS, ", "), runtime.GOOS)
	}
	r := runner.Runner{Spec: s.Directory, Version: l.Version, Harness: h, Models: conformance.ModelList()}
	if !slices.ContainsFunc(cases, func(c runner.Case) bool { return c.Role == tf.Role }) {
		return runner.Report{Spec: r.Spec, Version: r.Version, Harness: r.Harness, Models: r.Models,
			Target: *targetFile, Role: tf.Role, Launcher: tf.Launcher}.Write(stdout)
	}
	a, err := launch.Attach(tf)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep := r.Run(ctx, *targetFile, a, cases)
	if err := rep.Write(stdout); err != nil {
		return err
	}
	if rep.Failed() {
		return errCasesFailed
	}
	return nil
}

func requirements(s spec.Spec, cases []runner.Case, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("requirements", flag.ContinueOnError)
	check := fset.Bool("check", false, "list nothing; fail unless every requirement is cited by a case or listed as not machine-checked")
	if err := flags(fset, args, stderr); err != nil {
		return err
	}
	l, err := s.Load()
	if err != nil {
		return err
	}
	if *check {
		if err := runner.Check(cases); err != nil {
			return fmt.Errorf("the suite:\n%w", err)
		}
		if err := coverage.Check(s, l, cases); err != nil {
			return fmt.Errorf("the coverage check fails:\n%w", err)
		}
		fmt.Fprintf(stdout, "%s %s: %d requirements, %d cases, %d listed as not machine-checked: covered\n", s.Directory, l.Version, len(l.Requirements), len(cases), len(l.Unchecked))
		return nil
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
