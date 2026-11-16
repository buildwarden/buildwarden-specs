package relayguestapi

import (
	"embed"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// files are the specification's own files. The v1* pattern takes its
// document with every schema and OpenAPI description of version 1, so that
// adding one of them changes nothing here.
//
//go:embed v1* CHANGELOG.md not-machine-checked.txt
var files embed.FS

// Spec is the relay-guest-api specification: its directory, its requirement prefix and
// its files.
var Spec = spec.Spec{
	Directory: "relay-guest-api",
	Prefix:    "GUEST",
	Document:  "v1.md",
	Files:     files,
}
