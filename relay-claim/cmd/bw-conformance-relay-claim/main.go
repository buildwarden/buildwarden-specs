// Command bw-conformance-relay-claim runs the relay-claim suite against the component a
// target file describes, lists the specification's requirements, and prints
// its version and the harness's.
package main

import (
	"os"

	"github.com/buildwarden/buildwarden-specs/conformance/command"
	relayclaim "github.com/buildwarden/buildwarden-specs/relay-claim"
	"github.com/buildwarden/buildwarden-specs/relay-claim/cases"
)

func main() {
	os.Exit(command.Main(relayclaim.Spec, cases.Cases, os.Args[1:], os.Stdout, os.Stderr))
}
