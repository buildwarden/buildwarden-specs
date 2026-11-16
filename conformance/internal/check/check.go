// Package check holds the checks the repository's ci runs over the
// specification directories, beside go vet and go test. Each check returns
// every problem it finds, joined, so that one run names them all.
//
// The checks read the conventions in the repository's README, and these,
// which are the checks' own:
//
//   - The header of a document v<N>.md is its title "# <directory>, version
//     <N>" and a table whose rows include "Requirement identifiers", naming
//     the prefix as `PREFIX-<n>`, "Concept", linking the book, and
//     "Reference implementation".
//   - A JSON example in a document is a fenced code block whose info string
//     is "json". A block whose info string is "json" and the name of a schema
//     file of the same version in the same directory, "json
//     v1.config.schema.json", is an example of that schema and must validate
//     against it; a block that names none must be well-formed JSON.
//   - The part that collector-outputs and collector-inputs state alike is
//     marked in each document by the comment lines CommonBegin and
//     CommonEnd, as one or more blocks. The k-th block of one document is
//     the same text as the k-th of the other, with each requirement
//     identifier's prefix read as the same, so the identifiers' numbers
//     agree too.
package check

import (
	"errors"
	"fmt"
	"strings"
)

// Module is the module path every module here starts with: the harness's is
// Module+"/conformance", a specification's Module+"/<directory>".
const Module = "github.com/buildwarden/buildwarden-specs"

// Harness is the harness's directory, which is no specification.
const Harness = "conformance"

// Kit is the module path of the BuildWarden kit, which no module here may
// require.
const Kit = "github.com/buildwarden/buildwarden"

// problems collects the problems one check finds, each named by the file it
// is in.
type problems []error

func (p *problems) addf(file, format string, args ...any) {
	*p = append(*p, fmt.Errorf("%s: %s", file, fmt.Sprintf(format, args...)))
}

// add records err, which may join several, under file.
func (p *problems) add(file string, err error) {
	if err == nil {
		return
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		*p = append(*p, fmt.Errorf("%s: %s", file, line))
	}
}

func (p problems) err() error { return errors.Join(p...) }
