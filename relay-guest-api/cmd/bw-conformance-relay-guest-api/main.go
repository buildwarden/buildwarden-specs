// Command bw-conformance-relay-guest-api runs the relay-guest-api suite against the component a
// target file describes, lists the specification's requirements, and prints
// its version and the harness's.
package main

import (
	"os"

	"github.com/buildwarden/buildwarden-specs/conformance/command"
	relayguestapi "github.com/buildwarden/buildwarden-specs/relay-guest-api"
	"github.com/buildwarden/buildwarden-specs/relay-guest-api/cases"
)

func main() {
	os.Exit(command.Main(relayguestapi.Spec, cases.Cases, os.Args[1:], os.Stdout, os.Stderr))
}
