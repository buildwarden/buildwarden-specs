package spec

import (
	"testing"
	"testing/fstest"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	s := Spec{Directory: "relay-claim", Files: fstest.MapFS{
		"v1.identity.schema.json": {Data: []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.test/relay-claim/v1.identity.schema.json",
  "type": "object",
  "properties": {"key": {"$ref": "v1.key.schema.json"}},
  "required": ["key"]
}`)},
		"v1.key.schema.json": {Data: []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.test/relay-claim/v1.key.schema.json",
  "type": "string", "pattern": "^[0-9a-f]{4}$"
}`)},
		"v1.remote.schema.json": {Data: []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.test/relay-claim/v1.remote.schema.json",
  "$ref": "https://example.org/elsewhere.json"
}`)},
		"v1.noid.schema.json": {Data: []byte(`{"type": "object"}`)},
	}}
	tests := []struct {
		name, file, body, wantErr string
	}{
		{name: "valid, through a reference to another file", file: "v1.identity.schema.json", body: `{"key":"0a1b"}`},
		{name: "invalid", file: "v1.identity.schema.json", body: `{"key":"0A1B"}`, wantErr: "does not validate against relay-claim/v1.identity.schema.json"},
		{name: "a required member absent", file: "v1.identity.schema.json", body: `{}`, wantErr: "does not validate"},
		{name: "not JSON", file: "v1.identity.schema.json", body: `{"key":`, wantErr: "is not one JSON value"},
		{name: "no such schema", file: "v1.config.schema.json", body: `{}`, wantErr: "has no schema file v1.config.schema.json"},
	}
	// The file without an $id makes every schema of its directory unusable,
	// so the cases above run without it.
	noID := s.Files.(fstest.MapFS)["v1.noid.schema.json"]
	delete(s.Files.(fstest.MapFS), "v1.noid.schema.json")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, s.Validate(tt.file, []byte(tt.body)), tt.wantErr)
		})
	}
	t.Run("nothing is fetched", func(t *testing.T) {
		checkErr(t, s.Validate("v1.remote.schema.json", []byte(`{}`)), "is not a schema file of this specification")
	})
	t.Run("a schema file without an $id", func(t *testing.T) {
		withNoID := fstest.MapFS{"v1.noid.schema.json": noID}
		checkErr(t, Spec{Directory: "d", Files: withNoID}.Validate("v1.noid.schema.json", []byte(`{}`)), "d/v1.noid.schema.json has no $id")
	})
}
