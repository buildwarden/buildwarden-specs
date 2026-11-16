package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    File
		wantErr string
	}{
		{name: "relay", content: "role = \"relay\"\n", want: File{Role: "relay"}},
		{name: "collector", content: "# a collector\nrole = \"collector\"\n", want: File{Role: "collector"}},
		{name: "no role", content: "", wantErr: "role is missing; this harness knows relay, collector"},
		{name: "unknown role", content: "role = \"driver\"\n", wantErr: `role "driver" is not one this harness knows (relay, collector)`},
		{name: "not TOML", content: "role = relay\n", wantErr: "target file"},
		{name: "role of the wrong type", content: "role = 1\n", wantErr: "target file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "t.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Read(path)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		if _, err := Read(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
			t.Fatal("no error for a missing file")
		}
	})
}
