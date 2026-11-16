// Command bw-conformance-collector-inputs runs the collector-inputs suite against the component a
// target file describes, lists the specification's requirements, and prints
// its version and the harness's.
package main

import (
	"os"

	collectorinputs "github.com/buildwarden/buildwarden-specs/collector-inputs"
	"github.com/buildwarden/buildwarden-specs/collector-inputs/cases"
	"github.com/buildwarden/buildwarden-specs/conformance/command"
)

func main() {
	os.Exit(command.Main(collectorinputs.Spec, cases.Cases, os.Args[1:], os.Stdout, os.Stderr))
}
