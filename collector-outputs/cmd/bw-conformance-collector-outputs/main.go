// Command bw-conformance-collector-outputs runs the collector-outputs suite against the component a
// target file describes, lists the specification's requirements, and prints
// its version and the harness's.
package main

import (
	"os"

	collectoroutputs "github.com/buildwarden/buildwarden-specs/collector-outputs"
	"github.com/buildwarden/buildwarden-specs/collector-outputs/cases"
	"github.com/buildwarden/buildwarden-specs/conformance/command"
)

func main() {
	os.Exit(command.Main(collectoroutputs.Spec, cases.Cases, os.Args[1:], os.Stdout, os.Stderr))
}
