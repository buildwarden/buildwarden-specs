package check

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

// document returns a document of dir, version 1, with the prefix, every
// section, and body as the text of its Transport section.
func document(dir, prefix, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s, version 1\n\nWhat it is.\n\n| | |\n|---|---|\n| Seam | 1 |\n", dir)
	fmt.Fprintf(&b, "| Requirement identifiers | `%s-<n>` |\n", prefix)
	b.WriteString("| Concept | [The claim](https://buildwarden.github.io/buildwarden/concepts/architecture.html) in the book |\n")
	b.WriteString("| Reference implementation | The Go relay |\n\nThe key words.\n")
	for _, s := range Sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s)
		if s == "Transport" {
			b.WriteString(body)
		} else {
			b.WriteString("*Not yet written.*\n")
		}
	}
	return b.String()
}

const configSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/buildwarden/buildwarden-specs/relay-claim/v1.config.schema.json",
  "type": "object",
  "properties": {"mode": {"enum": ["host", "vm"]}},
  "required": ["mode"],
  "additionalProperties": false
}`

const identitySchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/buildwarden/buildwarden-specs/relay-claim/v1.identity.schema.json",
  "type": "object"
}`

const claimBody = "**CLAIM-1.** The relay MUST accept a claim.\n\n" +
	"- **CLAIM-2.** It MUST refuse a second.\n\n" +
	"```json v1.config.schema.json\n{\"mode\": \"host\"}\n```\n\n" +
	"```json\n{\"any\": [1, 2]}\n```\n"

const claimOpenAPI = `{
  "openapi": "3.1.0",
  "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
  "info": {"title": "relay-claim", "version": "v1"},
  "paths": {
    "/v1/claim": {
      "post": {
        "x-requirements": ["CLAIM-1"],
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "v1.config.schema.json"}}}},
        "responses": {
          "200": {
            "description": "claimed",
            "x-requirements": ["CLAIM-1"],
            "content": {"application/json; charset=utf-8": {"schema": {"$ref": "v1.identity.schema.json"}}}
          },
          "409": {"$ref": "#/components/responses/again"}
        }
      }
    }
  },
  "components": {
    "responses": {
      "again": {"description": "claimed before", "x-requirements": ["CLAIM-2"], "content": {"text/plain": {"schema": {"type": "string"}}}}
    }
  }
}`

// commonPart is the part the two collector documents state alike, with the
// prefix to fill in.
const commonPart = CommonBegin + "\n**%[1]s-1.** Every request MUST carry the token.\n\n```text\nAuthorization: Bearer <token>\n```\n" + CommonEnd + "\n"

// repo is a repository whose three specification directories pass every
// check that reads documents.
func repo() fstest.MapFS {
	fsys := fstest.MapFS{}
	add := func(dir, prefix, doc string, extra map[string]string) {
		fsys[dir+"/v1.md"] = &fstest.MapFile{Data: []byte(doc)}
		fsys[dir+"/CHANGELOG.md"] = &fstest.MapFile{Data: []byte("# Changelog\n\n## v0.1.0\n\n- First.\n")}
		fsys[dir+"/not-machine-checked.txt"] = &fstest.MapFile{Data: []byte("# The list.\n" + prefix + "-2 a person reads it\n")}
		fsys[dir+"/go.mod"] = &fstest.MapFile{Data: []byte("module " + Module + "/" + dir + "\n")}
		fsys[dir+"/spec.go"] = &fstest.MapFile{Data: []byte("package x\n")}
		fsys[dir+"/cases/cases.go"] = &fstest.MapFile{Data: []byte("package cases\n")}
		for name, data := range extra {
			fsys[dir+"/"+name] = &fstest.MapFile{Data: []byte(data)}
		}
	}
	add("relay-claim", "CLAIM", document("relay-claim", "CLAIM", claimBody), map[string]string{
		"v1.config.schema.json":   configSchema,
		"v1.identity.schema.json": identitySchema,
		"v1.openapi.json":         claimOpenAPI,
	})
	add(CollectorOutputs, "COLLOUT", document(CollectorOutputs, "COLLOUT", fmt.Sprintf(commonPart, "COLLOUT")+"\n**COLLOUT-2.** Its own.\n"), nil)
	add(CollectorInputs, "COLLIN", document(CollectorInputs, "COLLIN", fmt.Sprintf(commonPart, "COLLIN")+"\n**COLLIN-2.** Its own, and longer.\n"), nil)
	return fsys
}

var dirs = []string{"relay-claim", CollectorOutputs, CollectorInputs}

// edit returns the repository with one file's text changed by f.
func edit(name string, f func(string) string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) {
		fsys[name] = &fstest.MapFile{Data: []byte(f(string(fsys[name].Data)))}
	}
}

func replace(name, old, new string) func(fstest.MapFS) {
	return edit(name, func(s string) string {
		if !strings.Contains(s, old) {
			panic(fmt.Sprintf("%s does not contain %q", name, old))
		}
		return strings.Replace(s, old, new, 1)
	})
}

func set(name, data string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) { fsys[name] = &fstest.MapFile{Data: []byte(data)} }
}

func remove(name string) func(fstest.MapFS) {
	return func(fsys fstest.MapFS) { delete(fsys, name) }
}

func TestDocs(t *testing.T) {
	tests := []struct {
		name    string
		change  func(fstest.MapFS)
		dirs    []string
		wantErr []string
	}{
		{name: "the fixture passes"},
		{name: "skeletons pass", change: func(fsys fstest.MapFS) {
			for _, d := range dirs {
				prefix := map[string]string{"relay-claim": "CLAIM", CollectorOutputs: "COLLOUT", CollectorInputs: "COLLIN"}[d]
				fsys[d+"/v1.md"] = &fstest.MapFile{Data: []byte(document(d, prefix, "*Not yet written.*\n"))}
				fsys[d+"/not-machine-checked.txt"] = &fstest.MapFile{Data: []byte("# Nothing yet.\n")}
			}
			set("relay-claim/v1.openapi.json", strings.ReplaceAll(claimOpenAPI, `"CLAIM-2"`, `"CLAIM-1"`))(fsys)
		}, wantErr: []string{"x-requirements names CLAIM-1, which v1.md does not state"}},

		// The layout.
		{name: "a schema with a name outside the layout", change: set("relay-claim/config.schema.json", configSchema),
			wantErr: []string{"relay-claim/config.schema.json: is not a name of the layout"}},
		{name: "a part with capitals", change: set("relay-claim/v1.Config.schema.json", configSchema),
			wantErr: []string{"relay-claim/v1.Config.schema.json: is not a name of the layout"}},
		{name: "a versioned file of no kind", change: set("relay-claim/v1.notes.md", "x"),
			wantErr: []string{"relay-claim/v1.notes.md: is not a name of the layout"}},
		{name: "a schema with no document of its version", change: set("relay-claim/v2.schema.json", strings.Replace(configSchema, "v1.config", "v2", 1)),
			wantErr: []string{"relay-claim/v2.schema.json: has no document v2.md beside it"}},
		{name: "no document", change: remove("relay-claim/v1.md"),
			wantErr: []string{"relay-claim: has no document v<N>.md"}},
		{name: "no list", change: remove("relay-claim/not-machine-checked.txt"),
			wantErr: []string{"relay-claim: has no not-machine-checked.txt"}},
		{name: "no CHANGELOG.md", change: remove("relay-claim/CHANGELOG.md"),
			wantErr: []string{"relay-claim: has no CHANGELOG.md"}},
		{name: "no go.mod", change: remove("relay-claim/go.mod"),
			wantErr: []string{"relay-claim: has no go.mod"}},
		{name: "a directory that is not there", dirs: []string{"relay-claim", "absent"},
			wantErr: []string{"absent: open absent: file does not exist"}},

		// The header and the sections.
		{name: "a wrong title", change: replace("relay-claim/v1.md", "# relay-claim, version 1", "# relay-claim"),
			wantErr: []string{`relay-claim/v1.md: does not start with the title "# relay-claim, version 1"`}},
		{name: "no prefix row", change: replace("relay-claim/v1.md", "| Requirement identifiers | `CLAIM-<n>` |\n", ""),
			wantErr: []string{"relay-claim/v1.md: has no header row \"| Requirement identifiers |"}},
		{name: "no book link", change: replace("relay-claim/v1.md", "https://buildwarden.github.io/buildwarden/", "https://example.com/"),
			wantErr: []string{`relay-claim/v1.md: has no header row "Concept" linking the book`}},
		{name: "no reference implementation", change: replace("relay-claim/v1.md", "| Reference implementation | The Go relay |\n", ""),
			wantErr: []string{`relay-claim/v1.md: has no header row "Reference implementation"`}},
		{name: "a section missing", change: replace("relay-claim/v1.md", "## Limits\n", "## Bounds\n"),
			wantErr: []string{`relay-claim/v1.md: has no section "## Limits"`}},
		{name: "a section twice", change: replace("relay-claim/v1.md", "## Limits\n", "## Errors\n\n## Limits\n"),
			wantErr: []string{`relay-claim/v1.md: has the section "## Errors" 2 times`}},
		{name: "sections out of order", change: edit("relay-claim/v1.md", func(s string) string {
			s = strings.Replace(s, "## Ordering\n", "## TMP\n", 1)
			s = strings.Replace(s, "## Errors\n", "## Ordering\n", 1)
			return strings.Replace(s, "## TMP\n", "## Errors\n", 1)
		}), wantErr: []string{`relay-claim/v1.md: has the section "## Errors" (line 36) before "## Ordering" (line 40)`}},
		{name: "a section of the document's own passes", change: replace("relay-claim/v1.md", "## Limits\n", "## The disk layout\n\nText.\n\n## Limits\n")},
		{name: "a heading inside a code block is not a section", change: replace("relay-claim/v1.md", "## Limits\n", "```\n## Limits\n```\n"),
			wantErr: []string{`relay-claim/v1.md: has no section "## Limits"`}},
		{name: "two directories with one prefix", change: func(fsys fstest.MapFS) {
			set(CollectorInputs+"/v1.md", strings.ReplaceAll(string(fsys[CollectorInputs+"/v1.md"].Data), "COLLIN", "COLLOUT"))(fsys)
			set(CollectorInputs+"/not-machine-checked.txt", "COLLOUT-2 x\n")(fsys)
		}, wantErr: []string{"collector-inputs: requirement prefix COLLOUT is collector-outputs's too"}},

		// The requirements and the list.
		{name: "an identifier stated twice", change: replace("relay-claim/v1.md", "**CLAIM-2.**", "**CLAIM-1.**"),
			wantErr: []string{"relay-claim/v1.md: line", "CLAIM-1 is stated again"}},
		{name: "an identifier with another prefix", change: replace("relay-claim/v1.md", "**CLAIM-2.**", "**GUEST-2.**"),
			wantErr: []string{`"GUEST-2" does not have this specification's prefix CLAIM`}},
		{name: "a malformed identifier", change: replace("relay-claim/v1.md", "**CLAIM-2.**", "**CLAIM-02.**"),
			wantErr: []string{`"CLAIM-02" is not a requirement identifier`}},
		{name: "a listed identifier the document does not state", change: set("relay-claim/not-machine-checked.txt", "CLAIM-9 why\n"),
			wantErr: []string{"relay-claim/not-machine-checked.txt: lists CLAIM-9, which no document of relay-claim states"}},
		{name: "a listed identifier with no reason", change: set("relay-claim/not-machine-checked.txt", "CLAIM-2\n"),
			wantErr: []string{"relay-claim/not-machine-checked.txt: line 1: CLAIM-2 has no reason"}},
		{name: "a CHANGELOG.md with no version", change: set("relay-claim/CHANGELOG.md", "# Changelog\n\n## Unreleased\n"),
			wantErr: []string{`relay-claim/CHANGELOG.md: the first version heading is "## Unreleased"`}},

		// The schemas and the examples.
		{name: "a schema with the wrong $id", change: replace("relay-claim/v1.config.schema.json", "relay-claim/v1.config", "relay-claim/v1.cfg"),
			wantErr: []string{`relay-claim/v1.config.schema.json: $id is "https://github.com/buildwarden/buildwarden-specs/relay-claim/v1.cfg.schema.json", want`}},
		{name: "a schema of another dialect", change: replace("relay-claim/v1.config.schema.json", "draft/2020-12", "draft-07"),
			wantErr: []string{`relay-claim/v1.config.schema.json: $schema is "https://json-schema.org/draft-07/schema"`}},
		{name: "a schema that is not valid 2020-12", change: replace("relay-claim/v1.config.schema.json", `"type": "object"`, `"type": "record"`),
			wantErr: []string{"relay-claim/v1.config.schema.json: is not a valid JSON Schema 2020-12"}},
		{name: "a schema that is not JSON", change: set("relay-claim/v1.identity.schema.json", "{"),
			wantErr: []string{"relay-claim/v1.identity.schema.json: is not a JSON object"}},
		{name: "an example that does not validate", change: replace("relay-claim/v1.md", `{"mode": "host"}`, `{"mode": "boat"}`),
			wantErr: []string{"relay-claim/v1.md: line", "the example does not validate against v1.config.schema.json"}},
		{name: "an example that is not JSON", change: replace("relay-claim/v1.md", `{"any": [1, 2]}`, `{"any": [1, 2}`),
			wantErr: []string{"the JSON example is not JSON"}},
		{name: "an example naming a file that is not there", change: replace("relay-claim/v1.md", "```json v1.config.schema.json", "```json v1.other.schema.json"),
			wantErr: []string{"the example names v1.other.schema.json, which is not a valid schema file in relay-claim"}},
		{name: "an example naming a file of the wrong kind", change: replace("relay-claim/v1.md", "```json v1.config.schema.json", "```json v1.openapi.json"),
			wantErr: []string{`the example names "v1.openapi.json", which is not a schema file of version 1`}},
		{name: "an example naming two schemas", change: replace("relay-claim/v1.md", "```json v1.config.schema.json", "```json v1.config.schema.json v1.identity.schema.json"),
			wantErr: []string{"names more than one schema"}},
		{name: "a code block that is not JSON is not an example", change: replace("relay-claim/v1.md", "```json\n{\"any\"", "```text\n{{\"any\"")},

		// The OpenAPI files.
		{name: "an OpenAPI file that is not valid 3.1", change: replace("relay-claim/v1.openapi.json", `"description": "claimed",`, ""),
			wantErr: []string{"relay-claim/v1.openapi.json: is not a valid OpenAPI 3.1 document"}},
		{name: "an OpenAPI file of another 3.1 version", change: replace("relay-claim/v1.openapi.json", `"openapi": "3.1.0"`, `"openapi": "3.1.1"`),
			wantErr: []string{`relay-claim/v1.openapi.json: openapi is "3.1.1", want "3.1.0"`}},
		{name: "an OpenAPI file with another dialect", change: replace("relay-claim/v1.openapi.json", `"jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema"`, `"jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base"`),
			wantErr: []string{"relay-claim/v1.openapi.json: jsonSchemaDialect is"}},
		{name: "an OpenAPI file with a release's version", change: replace("relay-claim/v1.openapi.json", `"version": "v1"`, `"version": "0.1.0"`),
			wantErr: []string{`relay-claim/v1.openapi.json: info.version is "0.1.0", want "v1"`}},
		{name: "an operation with no x-requirements", change: replace("relay-claim/v1.openapi.json", `"x-requirements": ["CLAIM-1"],
        "requestBody"`, `"requestBody"`),
			wantErr: []string{"relay-claim/v1.openapi.json: POST /v1/claim has no x-requirements"}},
		{name: "a status with no x-requirements", change: replace("relay-claim/v1.openapi.json", `"x-requirements": ["CLAIM-1"],
            "content"`, `"content"`),
			wantErr: []string{"relay-claim/v1.openapi.json: POST /v1/claim response 200 has no x-requirements"}},
		{name: "a referenced status with no x-requirements", change: replace("relay-claim/v1.openapi.json", `"x-requirements": ["CLAIM-2"], `, ""),
			wantErr: []string{"POST /v1/claim response 409 has no x-requirements"}},
		{name: "an empty x-requirements", change: replace("relay-claim/v1.openapi.json", `"x-requirements": ["CLAIM-2"]`, `"x-requirements": []`),
			wantErr: []string{"POST /v1/claim response 409 has no x-requirements"}},
		{name: "an x-requirements naming an identifier the document lacks", change: replace("relay-claim/v1.openapi.json", `["CLAIM-2"]`, `["CLAIM-7"]`),
			wantErr: []string{"POST /v1/claim response 409: x-requirements names CLAIM-7, which v1.md does not state"}},
		{name: "a JSON body with a schema of its own", change: replace("relay-claim/v1.openapi.json", `{"$ref": "v1.identity.schema.json"}`, `{"type": "object"}`),
			wantErr: []string{`the application/json; charset=utf-8 body's schema is {"type":"object"}; it must be only a $ref to a schema file`,
				"relay-claim/v1.identity.schema.json: is the body of no operation"}},
		{name: "a JSON body referring to a file that is not there", change: replace("relay-claim/v1.openapi.json", `"v1.identity.schema.json"`, `"v1.reply.schema.json"`),
			wantErr: []string{`body's schema is {"$ref":"v1.reply.schema.json"}`}},
		{name: "a JSON body referring to a schema elsewhere", change: replace("relay-claim/v1.openapi.json", `"v1.identity.schema.json"`, `"../bootstrap-config/v1.schema.json"`),
			wantErr: []string{`body's schema is {"$ref":"../bootstrap-config/v1.schema.json"}`}},
		{name: "a schema in components", change: replace("relay-claim/v1.openapi.json", `"components": {`, `"components": {"schemas": {"x": {"type": "object"}},`),
			wantErr: []string{"defines schemas of its own under components.schemas"}},
		{name: "a schema file nothing refers to", change: set("relay-claim/v1.status.schema.json", strings.Replace(identitySchema, "v1.identity", "v1.status", 1)),
			wantErr: []string{"relay-claim/v1.status.schema.json: is the body of no operation of relay-claim's OpenAPI files of version 1"}},
		{name: "a JSON body with no schema passes", change: replace("relay-claim/v1.openapi.json", `"text/plain": {"schema": {"type": "string"}}`, `"application/json": {}`)},
		{name: "a schema in a directory with no OpenAPI file needs no reference", change: remove("relay-claim/v1.openapi.json")},

		// The collector documents.
		{name: "the common part differing", change: replace(CollectorInputs+"/v1.md", "MUST carry the token", "MUST carry a token"),
			wantErr: []string{"collector-outputs/v1.md: block 1 of the common part", "differs from collector-inputs/v1.md's", `"**COLLOUT-1.** Every request MUST carry the token." against "**COLLIN-1.** Every request MUST carry a token."`}},
		{name: "the common part differing in a code block", change: replace(CollectorInputs+"/v1.md", "Bearer <token>", "<token>"),
			wantErr: []string{"block 1 of the common part"}},
		{name: "the common part numbering differently", change: func(fsys fstest.MapFS) {
			replace(CollectorInputs+"/v1.md", "**COLLIN-1.**", "**COLLIN-3.**")(fsys)
		}, wantErr: []string{"block 1 of the common part"}},
		{name: "the common part unmarked in one", change: edit(CollectorInputs+"/v1.md", func(s string) string {
			return strings.NewReplacer(CommonBegin+"\n", "", CommonEnd+"\n", "").Replace(s)
		}), wantErr: []string{"collector-inputs/v1.md: marks no common part"}},
		{name: "the common part unclosed", change: replace(CollectorInputs+"/v1.md", CommonEnd+"\n", ""),
			wantErr: []string{"collector-inputs/v1.md: line", "opens a common block that is never closed"}},
		{name: "a second block in one only", change: replace(CollectorInputs+"/v1.md", "## Limits\n", CommonBegin+"\nMore.\n"+CommonEnd+"\n\n## Limits\n"),
			wantErr: []string{"collector-outputs/v1.md: has 1 blocks of the common part where collector-inputs/v1.md has 2"}},
		{name: "the common part checked only when both are named", dirs: []string{CollectorOutputs},
			change: replace(CollectorInputs+"/v1.md", "MUST carry the token", "MUST carry a token")},
		{name: "one collector document of a version only", change: func(fsys fstest.MapFS) {
			set(CollectorOutputs+"/v2.md", strings.Replace(string(fsys[CollectorOutputs+"/v1.md"].Data), "version 1", "version 2", 1))(fsys)
		}, wantErr: []string{"v2.md: collector-outputs and collector-inputs are released as a pair of documents"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := repo()
			if tt.change != nil {
				tt.change(fsys)
			}
			d := tt.dirs
			if d == nil {
				d = dirs
			}
			assertErr(t, Docs(fsys, d), tt.wantErr)
		})
	}
}

// assertErr fails unless err contains each of want, or is nil when want is
// empty.
func assertErr(t *testing.T, err error, want []string) {
	t.Helper()
	if len(want) == 0 {
		if err != nil {
			t.Fatalf("unexpected error:\n%v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("no error, want one containing %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error does not contain %q:\n%v", w, err)
		}
	}
}
