// Command bw-conformance-bootstrap-config runs the bootstrap-config suite against the component a
// target file describes, lists the specification's requirements, and prints
// its version and the harness's.
package main

import (
	"os"

	bootstrapconfig "github.com/buildwarden/buildwarden-specs/bootstrap-config"
	"github.com/buildwarden/buildwarden-specs/bootstrap-config/cases"
	"github.com/buildwarden/buildwarden-specs/conformance/command"
)

func main() {
	os.Exit(command.Main(bootstrapconfig.Spec, cases.Cases, os.Args[1:], os.Stdout, os.Stderr))
}
