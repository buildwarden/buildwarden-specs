// Package spec reads the files of one specification directory the way every
// tool here reads them: the requirements its document states, the list of
// those that no case checks, and the version at the head of its CHANGELOG.md.
// The forms it accepts are the conventions in the repository's README.
package spec

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// The files every specification directory has beside its document.
const (
	ChangelogFile = "CHANGELOG.md"
	ListFile      = "not-machine-checked.txt"
)

// Spec names one specification and holds its files.
type Spec struct {
	// Directory is the specification's directory, which is also the last
	// element of its module path: "relay-claim".
	Directory string
	// Prefix is what every one of its requirement identifiers starts with:
	// "CLAIM".
	Prefix string
	// Document is the file name of its document: "v1.md".
	Document string
	// Files holds Document, ChangelogFile and ListFile at its root.
	Files fs.FS
}

// Unchecked is a requirement that no case checks, with the reason.
type Unchecked struct {
	ID     string
	Reason string
}

// Loaded is what a specification's files say.
type Loaded struct {
	// Version is the version at the head of its CHANGELOG.md: "v0.1.0".
	Version string
	// Requirements are the identifiers its document states, in the order
	// it states them.
	Requirements []string
	// Unchecked is its list of requirements that no case checks, in the
	// list's order.
	Unchecked []Unchecked
}

// Load reads and parses the specification's three files.
func (s Spec) Load() (Loaded, error) {
	var l Loaded
	read := func(name string) ([]byte, error) {
		b, err := fs.ReadFile(s.Files, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Directory, err)
		}
		return b, nil
	}
	changelog, err := read(ChangelogFile)
	if err != nil {
		return l, err
	}
	if l.Version, err = ChangelogVersion(changelog); err != nil {
		return l, fmt.Errorf("%s/%s: %w", s.Directory, ChangelogFile, err)
	}
	doc, err := read(s.Document)
	if err != nil {
		return l, err
	}
	if l.Requirements, err = Requirements(doc, s.Prefix); err != nil {
		return l, fmt.Errorf("%s/%s: %w", s.Directory, s.Document, err)
	}
	list, err := read(ListFile)
	if err != nil {
		return l, err
	}
	if l.Unchecked, err = ParseList(list, s.Prefix); err != nil {
		return l, fmt.Errorf("%s/%s: %w", s.Directory, ListFile, err)
	}
	return l, nil
}

var (
	// idPattern is a requirement identifier: a prefix of capitals, a hyphen
	// and a decimal number with no leading zero.
	idPattern = regexp.MustCompile(`^([A-Z]+)-([1-9][0-9]*)$`)
	// statement is the start of a paragraph or list item that states a
	// requirement: its identifier in bold, followed by a full stop. The
	// identifier is captured loosely so that a malformed one is reported
	// rather than read as prose.
	statement = regexp.MustCompile(`^ {0,3}(?:[-*+] +|[0-9]+[.)] +)?\*\*([A-Za-z0-9]+-[0-9A-Za-z]+)\.\*\*`)
	fence     = regexp.MustCompile("^ {0,3}(```|~~~)")
	version   = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// CheckID reports whether id is a well-formed identifier with the prefix.
func CheckID(id, prefix string) error {
	m := idPattern.FindStringSubmatch(id)
	if m == nil {
		return fmt.Errorf("%q is not a requirement identifier (want %s-<n>, n with no leading zero)", id, prefix)
	}
	if m[1] != prefix {
		return fmt.Errorf("%q does not have this specification's prefix %s", id, prefix)
	}
	return nil
}

// Requirements returns the identifiers a document states, in order. It is an
// error for a statement to carry a malformed identifier, another
// specification's prefix, or an identifier stated before. Lines inside fenced
// code blocks state nothing.
func Requirements(doc []byte, prefix string) ([]string, error) {
	var ids []string
	seen := map[string]int{}
	var errs []error
	inFence := ""
	sc := bufio.NewScanner(bytes.NewReader(doc))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if m := fence.FindStringSubmatch(line); m != nil {
			switch inFence {
			case "":
				inFence = m[1]
			case m[1]:
				inFence = ""
			}
			continue
		}
		if inFence != "" {
			continue
		}
		m := statement.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id := m[1]
		if err := CheckID(id, prefix); err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", n, err))
			continue
		}
		if first, ok := seen[id]; ok {
			errs = append(errs, fmt.Errorf("line %d: %s is stated again (first on line %d)", n, id, first))
			continue
		}
		seen[id] = n
		ids = append(ids, id)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if inFence != "" {
		errs = append(errs, errors.New("a fenced code block is not closed"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return ids, nil
}

// ParseList parses a list of requirements that no case checks: one to a
// line, the identifier, a space and the reason. Blank lines and lines that
// start with # are ignored. It does not check that the identifiers are
// stated in the document; the coverage check does.
func ParseList(list []byte, prefix string) ([]Unchecked, error) {
	var out []Unchecked
	seen := map[string]int{}
	var errs []error
	for i, line := range strings.Split(string(list), "\n") {
		n := i + 1
		line = strings.TrimRight(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, reason, _ := strings.Cut(line, " ")
		reason = strings.TrimSpace(reason)
		if err := CheckID(id, prefix); err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", n, err))
			continue
		}
		if reason == "" {
			errs = append(errs, fmt.Errorf("line %d: %s has no reason", n, id))
			continue
		}
		if first, ok := seen[id]; ok {
			errs = append(errs, fmt.Errorf("line %d: %s is listed again (first on line %d)", n, id, first))
			continue
		}
		seen[id] = n
		out = append(out, Unchecked{ID: id, Reason: reason})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// ChangelogVersion returns the version a CHANGELOG.md names first: the
// first second-level heading, which must be a version and nothing else,
// "## v0.1.0".
func ChangelogVersion(changelog []byte) (string, error) {
	for _, line := range strings.Split(string(changelog), "\n") {
		heading, ok := strings.CutPrefix(strings.TrimRight(line, " \t\r"), "## ")
		if !ok {
			continue
		}
		heading = strings.TrimSpace(heading)
		if !version.MatchString(heading) {
			return "", fmt.Errorf("the first version heading is %q, want ## vX.Y.Z", line)
		}
		return heading, nil
	}
	return "", errors.New("no version heading (## vX.Y.Z)")
}
