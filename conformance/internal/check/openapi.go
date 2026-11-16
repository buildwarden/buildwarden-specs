package check

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// openAPISchema is the OpenAPI Initiative's JSON Schema for OpenAPI 3.1
// documents, https://spec.openapis.org/oas/3.1/schema/2022-10-07, kept here
// byte for byte so that the check needs no network.
//
//go:embed openapi-3.1.schema.json
var openAPISchema []byte

// OpenAPISchemaID is the $id of the copy in openapi-3.1.schema.json.
const OpenAPISchemaID = "https://spec.openapis.org/oas/3.1/schema/2022-10-07"

// The fields every OpenAPI file here has the same value in.
const (
	OpenAPIVersion = "3.1.0"
	// Requirements is the extension that names, on an operation or a
	// response, the requirements that state it.
	Requirements = "x-requirements"
)

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

var openAPI = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(openAPISchema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	if err := c.AddResource(OpenAPISchemaID, doc); err != nil {
		return nil, err
	}
	return c.Compile(OpenAPISchemaID)
})

// checkOpenAPI runs the three checks on one OpenAPI file of dir, whose
// document of the same version states ids: that it is valid OpenAPI 3.1;
// that every JSON body it gives a shape is a reference to a schema file of
// the same version beside it; and that every operation and every response
// names, in x-requirements, requirements that the document states.
func checkOpenAPI(fsys fs.FS, dir, name string, ids []string, schemas []string, p *problems) {
	file := path.Join(dir, name)
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		p.add(file, err)
		return
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		p.addf(file, "is not JSON: %v", err)
		return
	}
	meta, err := openAPI()
	if err != nil {
		p.addf(file, "the OpenAPI 3.1 schema does not compile: %v", err)
		return
	}
	if err := meta.Validate(inst); err != nil {
		p.addf(file, "is not a valid OpenAPI 3.1 document: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		p.addf(file, "is not a JSON object: %v", err)
		return
	}
	n := fileVersion(name)
	if v, _ := doc["openapi"].(string); v != OpenAPIVersion {
		p.addf(file, "openapi is %q, want %q", v, OpenAPIVersion)
	}
	if v, _ := doc["jsonSchemaDialect"].(string); v != Draft202012 {
		p.addf(file, "jsonSchemaDialect is %q, want %q", v, Draft202012)
	}
	info, _ := doc["info"].(map[string]any)
	if v, _ := info["version"].(string); v != fmt.Sprintf("v%d", n) {
		p.addf(file, "info.version is %q, want %q", v, fmt.Sprintf("v%d", n))
	}
	if comps, _ := doc["components"].(map[string]any); comps != nil {
		if s, _ := comps["schemas"].(map[string]any); len(s) > 0 {
			p.addf(file, "defines schemas of its own under components.schemas; a body's shape is a schema file beside it")
		}
	}
	walkContent(doc, "", func(where, mediaType string, media map[string]any) {
		s, ok := media["schema"]
		if !ok || !isJSON(mediaType) {
			return
		}
		if ref, ok := bodyRef(s); !ok || !slices.Contains(schemas, ref) || fileVersion(ref) != n {
			got, _ := json.Marshal(s)
			p.addf(file, "%s: the %s body's schema is %s; it must be only a $ref to a schema file of version %d in %s, {\"$ref\": \"v%d.<part>.schema.json\"}", where, mediaType, got, n, dir, n)
		}
	})
	stated := map[string]bool{}
	for _, id := range ids {
		stated[id] = true
	}
	named := func(where string, v map[string]any) {
		raw, ok := v[Requirements]
		list, isList := raw.([]any)
		if !ok || !isList || len(list) == 0 {
			p.addf(file, "%s has no %s naming the requirements that state it", where, Requirements)
			return
		}
		for _, e := range list {
			id, _ := e.(string)
			if !stated[id] {
				p.addf(file, "%s: %s names %v, which v%d.md does not state", where, Requirements, e, n)
			}
		}
	}
	operations(doc, func(op string, o map[string]any, responses map[string]map[string]any) {
		named(op, o)
		for _, status := range sortedStrings(responses) {
			named(op+" response "+status, responses[status])
		}
	})
}

// checkSchemasReferred checks that every schema file of dir is the body of
// at least one operation of the directory's OpenAPI files of its version.
func checkSchemasReferred(fsys fs.FS, dir string, openapis, schemas []string, p *problems) {
	referred := map[string]bool{}
	for _, name := range openapis {
		b, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			continue // checkOpenAPI reports it
		}
		var doc map[string]any
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		operations(doc, func(_ string, o map[string]any, responses map[string]map[string]any) {
			add := func(_, _ string, media map[string]any) {
				if ref, ok := bodyRef(media["schema"]); ok {
					referred[fmt.Sprintf("%d/%s", fileVersion(name), ref)] = true
				}
			}
			if rb := deref(doc, o["requestBody"]); rb != nil {
				walkContent(rb, "", add)
			}
			for _, r := range responses {
				walkContent(r, "", add)
			}
		})
	}
	for _, s := range schemas {
		if !referred[fmt.Sprintf("%d/%s", fileVersion(s), s)] {
			p.addf(path.Join(dir, s), "is the body of no operation of %s's OpenAPI files of version %d", dir, fileVersion(s))
		}
	}
}

// operations calls f for each operation of doc's paths, by method and path,
// with its responses by status, local references resolved.
func operations(doc map[string]any, f func(op string, o map[string]any, responses map[string]map[string]any)) {
	paths, _ := doc["paths"].(map[string]any)
	for _, pth := range sortedStrings(paths) {
		item := deref(doc, paths[pth])
		for _, m := range methods {
			o, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			responses := map[string]map[string]any{}
			rs, _ := o["responses"].(map[string]any)
			for status, r := range rs {
				if strings.HasPrefix(status, "x-") {
					continue
				}
				if d := deref(doc, r); d != nil {
					responses[status] = d
				}
			}
			f(strings.ToUpper(m)+" "+pth, o, responses)
		}
	}
}

// deref returns v as an object, following a local reference "#/..." once.
func deref(doc map[string]any, v any) map[string]any {
	o, _ := v.(map[string]any)
	ref, ok := o["$ref"].(string)
	if !ok || !strings.HasPrefix(ref, "#/") {
		return o
	}
	var cur any = doc
	for _, tok := range strings.Split(ref[2:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		m, _ := cur.(map[string]any)
		cur = m[tok]
	}
	o, _ = cur.(map[string]any)
	return o
}

// walkContent calls f for every media type object under a "content" field
// anywhere in v, with where it is.
func walkContent(v any, where string, f func(where, mediaType string, media map[string]any)) {
	switch v := v.(type) {
	case map[string]any:
		if content, ok := v["content"].(map[string]any); ok {
			for _, mt := range sortedStrings(content) {
				if media, ok := content[mt].(map[string]any); ok {
					f(where, mt, media)
				}
			}
		}
		for _, k := range sortedStrings(v) {
			walkContent(v[k], where+"/"+strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"), f)
		}
	case []any:
		for i, e := range v {
			walkContent(e, fmt.Sprintf("%s/%d", where, i), f)
		}
	}
}

// bodyRef returns the file a body's schema refers to when the schema is
// only a reference to a file of the same directory.
func bodyRef(s any) (string, bool) {
	o, _ := s.(map[string]any)
	ref, ok := o["$ref"].(string)
	if !ok || len(o) != 1 || strings.ContainsAny(ref, "/#") {
		return ref, false
	}
	return ref, true
}

func isJSON(mediaType string) bool {
	mt, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		mt = mediaType
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

func sortedStrings[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
