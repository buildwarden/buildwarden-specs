// Command bw-conformance-executor-initialize lists the executor-initialize specification's requirements,
// each with the reason it has no case, and prints its version and the
// harness's. The specification has no suite yet, so run runs nothing.
package main

import (
	"os"

	"github.com/buildwarden/buildwarden-specs/conformance/command"
	executorinitialize "github.com/buildwarden/buildwarden-specs/executor-initialize"
)

func main() {
	os.Exit(command.Main(executorinitialize.Spec, nil, os.Args[1:], os.Stdout, os.Stderr))
}
