package target

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	values := map[string]string{"claim": "127.0.0.1:4100", "out": "/o", "token": "t"}
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "plain", want: "plain"},
		{in: "{claim}", want: "127.0.0.1:4100"},
		{in: "--relay={claim}", want: "--relay=127.0.0.1:4100"},
		{in: "{out}/{token}", want: "/o/t"},
		{in: "{{claim}}", want: "{claim}"},
		{in: "{{{claim}}}", want: "{127.0.0.1:4100}"},
		{in: "{script}", wantErr: "{script} has no value in this start"},
		{in: "{claim", wantErr: "has a { with no }"},
		{in: "x}", wantErr: "has a } with no {"},
		{in: "{}", wantErr: `"{}" holds {}, which is not a placeholder name`},
	}
	for _, tt := range tests {
		got, err := Expand(tt.in, values)
		switch {
		case tt.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expand(%q) error %v, want one containing %q", tt.in, err, tt.wantErr)
			}
		case err != nil:
			t.Errorf("Expand(%q): %v", tt.in, err)
		case got != tt.want:
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExpandArgv(t *testing.T) {
	f, err := Parse("t.toml", collectorDisk)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		values  map[string]string
		want    []string
		wantEnv []string
		wantErr string
	}{
		{
			name:    "every placeholder given",
			values:  map[string]string{"claim": "c:1", "out": "o", "context": "ctx", "script": "s.sh", "capture": "all", "token": "tk"},
			want:    []string{"../../dist/conformance/collector", "--relay", "c:1", "--dir", "o", "--context", "ctx", "--script", "s.sh", "--capture", "all"},
			wantEnv: []string{"WARDEN_CLAIM_TOKEN=tk"},
		},
		{
			name:   "no script, no context and no token",
			values: map[string]string{"claim": "c:1", "out": "o", "capture": "none"},
			want:   []string{"../../dist/conformance/collector", "--relay", "c:1", "--dir", "o", "--capture", "none"},
		},
		{
			name:    "a required placeholder without a value",
			values:  map[string]string{"claim": "c:1", "capture": "none"},
			wantErr: "{out} has no value in this start",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandArgv(f.Exec.Argv, tt.values)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("argv %q, want %q", got, tt.want)
			}
			env, err := ExpandEnv(f.Exec.Env, tt.values)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(env, tt.wantEnv) {
				t.Errorf("env %q, want %q", env, tt.wantEnv)
			}
		})
	}
}

func TestExpandPlain(t *testing.T) {
	got, err := ExpandPlain([]string{"export", "{out}", "--to={dir}"}, map[string]string{"out": "o", "dir": "d"})
	if err != nil || !reflect.DeepEqual(got, []string{"export", "o", "--to=d"}) {
		t.Fatalf("ExpandPlain = %q, %v", got, err)
	}
	if _, err := ExpandPlain([]string{"export", "{dir}"}, nil); err == nil {
		t.Fatal("no error for a placeholder without a value")
	}
}
