package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"an unknown subcommand", []string{"layout"}},
		{"release with no base", []string{"release", "relay-claim"}},
		{"release with an unknown flag", []string{"release", "-head", "x"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if status := run(tt.args, &stdout, &stderr); status != 2 {
				t.Errorf("status %d, want 2", status)
			}
			if !strings.Contains(stderr.String(), "speccheck release -base <ref> <directory>...") {
				t.Errorf("stderr %q has no usage", stderr.String())
			}
		})
	}
}

func TestFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"docs", "absent"}, &stdout, &stderr); status != 1 {
		t.Errorf("status %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "speccheck docs:\nabsent: open absent") {
		t.Errorf("stderr %q does not name the missing directory", stderr.String())
	}
}
