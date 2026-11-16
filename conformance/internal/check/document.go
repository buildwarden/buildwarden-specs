package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

// Sections are the second-level headings every document has, in this order.
// A document may add sections of its own between them.
var Sections = []string{
	"Scope and roles",
	"Transport",
	"Messages and fields",
	"Ordering",
	"Errors",
	"Limits",
	"Versioning",
	"Conformance",
	"Known divergences",
}

// Draft202012 is the JSON Schema dialect every schema file declares.
const Draft202012 = "https://json-schema.org/draft/2020-12/schema"

// The files a specification directory has beside its documents.
const goModFile = "go.mod"

var (
	docName = regexp.MustCompile(`^v([1-9][0-9]*)\.md$`)
	// jsonName is a schema or an OpenAPI file: v<N>.<kind>.json or
	// v<N>.<part>.<kind>.json, a part being lower-case letters, digits and
	// hyphens.
	jsonName  = regexp.MustCompile(`^v([1-9][0-9]*)(?:\.([a-z0-9]+(?:-[a-z0-9]+)*))?\.(schema|openapi)\.json$`)
	versioned = regexp.MustCompile(`^v[0-9]`)
	prefixRow = regexp.MustCompile("^\\|\\s*Requirement identifiers\\s*\\|\\s*`([A-Z]+)-<n>`\\s*\\|\\s*$")
	openFence = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})(.*)$")
)

// SchemaID is the $id a schema file must declare: a name that mirrors its
// path in this repository.
func SchemaID(dir, file string) string {
	return "https://" + Module + "/" + dir + "/" + file
}

// Docs runs every check that reads documents only, over the specification
// directories dirs of the repository fsys: each directory's layout, header,
// sections, requirements, list, CHANGELOG.md, schemas, examples and OpenAPI
// files, the prefixes' uniqueness, and the collector documents' common
// part. Coverage, which needs the suites, is not among them.
func Docs(fsys fs.FS, dirs []string) error {
	var p problems
	prefixes := map[string]string{}
	docs := map[string]map[int][]byte{}
	for _, dir := range dirs {
		d := checkDir(fsys, dir, &p)
		docs[dir] = d.docs
		if d.prefix == "" {
			continue
		}
		if other, ok := prefixes[d.prefix]; ok {
			p.addf(dir, "requirement prefix %s is %s's too", d.prefix, other)
		}
		prefixes[d.prefix] = dir
	}
	if slices.Contains(dirs, CollectorOutputs) && slices.Contains(dirs, CollectorInputs) {
		p = append(p, Common(docs[CollectorOutputs], docs[CollectorInputs]))
	}
	return p.err()
}

// dirState is what checkDir learned of a directory that later checks need.
type dirState struct {
	prefix string
	docs   map[int][]byte
}

func checkDir(fsys fs.FS, dir string, p *problems) dirState {
	st := dirState{docs: map[int][]byte{}}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		p.add(dir, err)
		return st
	}
	var schemas, openapis []string
	files := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		files[name] = true
		switch {
		case docName.MatchString(name):
			n, _ := strconv.Atoi(docName.FindStringSubmatch(name)[1])
			b, err := fs.ReadFile(fsys, path.Join(dir, name))
			if err != nil {
				p.add(path.Join(dir, name), err)
				continue
			}
			st.docs[n] = b
		case jsonName.MatchString(name):
			if jsonName.FindStringSubmatch(name)[3] == "schema" {
				schemas = append(schemas, name)
			} else {
				openapis = append(openapis, name)
			}
		case strings.HasSuffix(name, ".json"), versioned.MatchString(name):
			p.addf(path.Join(dir, name), "is not a name of the layout: a document is v<N>.md, a schema v<N>.schema.json or v<N>.<part>.schema.json, an OpenAPI description v<N>.openapi.json or v<N>.<part>.openapi.json")
		}
	}
	for _, name := range []string{spec.ChangelogFile, spec.ListFile, goModFile} {
		if !files[name] {
			p.addf(dir, "has no %s", name)
		}
	}
	if len(st.docs) == 0 {
		p.addf(dir, "has no document v<N>.md")
	}
	for _, name := range append(slices.Clone(schemas), openapis...) {
		if _, ok := st.docs[fileVersion(name)]; !ok {
			p.addf(path.Join(dir, name), "has no document v%d.md beside it", fileVersion(name))
		}
	}

	// Every document of the directory must name one prefix; the first one
	// read is the directory's.
	reqs := map[int][]string{}
	stated := map[string]bool{}
	for _, n := range sortedKeys(st.docs) {
		file := path.Join(dir, fmt.Sprintf("v%d.md", n))
		prefix := checkHeader(st.docs[n], dir, n, file, p)
		checkSections(st.docs[n], file, p)
		switch {
		case prefix == "":
			continue
		case st.prefix == "":
			st.prefix = prefix
		case prefix != st.prefix:
			p.addf(file, "names the prefix %s where v%d.md names %s", prefix, sortedKeys(st.docs)[0], st.prefix)
			continue
		}
		ids, err := spec.Requirements(st.docs[n], prefix)
		p.add(file, err)
		reqs[n] = ids
		for _, id := range ids {
			stated[id] = true
		}
	}

	if files[spec.ChangelogFile] {
		if b, err := fs.ReadFile(fsys, path.Join(dir, spec.ChangelogFile)); err != nil {
			p.add(path.Join(dir, spec.ChangelogFile), err)
		} else if _, err := spec.ChangelogVersion(b); err != nil {
			p.add(path.Join(dir, spec.ChangelogFile), err)
		}
	}
	if files[spec.ListFile] && st.prefix != "" {
		file := path.Join(dir, spec.ListFile)
		if b, err := fs.ReadFile(fsys, file); err != nil {
			p.add(file, err)
		} else if list, err := spec.ParseList(b, st.prefix); err != nil {
			p.add(file, err)
		} else {
			for _, u := range list {
				if !stated[u.ID] {
					p.addf(file, "lists %s, which no document of %s states", u.ID, dir)
				}
			}
		}
	}

	compiled := checkSchemas(fsys, dir, schemas, p)
	for _, n := range sortedKeys(st.docs) {
		checkExamples(st.docs[n], dir, n, compiled, p)
	}
	for _, name := range openapis {
		checkOpenAPI(fsys, dir, name, reqs[fileVersion(name)], schemas, p)
	}
	if len(openapis) > 0 {
		checkSchemasReferred(fsys, dir, openapis, schemas, p)
	}
	return st
}

// fileVersion is the N of a file named v<N>...; the name has matched
// docName or jsonName.
func fileVersion(name string) int {
	n, _ := strconv.Atoi(name[1:strings.IndexByte(name, '.')])
	return n
}

func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// lines returns the document's lines that are outside fenced code blocks,
// each with its line number.
func lines(doc []byte) []numbered {
	var out []numbered
	fence := ""
	for i, line := range strings.Split(string(doc), "\n") {
		line = strings.TrimRight(line, "\r")
		if fence != "" {
			if closesFence(line, fence) {
				fence = ""
			}
			continue
		}
		if m := openFence.FindStringSubmatch(line); m != nil {
			fence = m[1]
			continue
		}
		out = append(out, numbered{i + 1, line})
	}
	return out
}

type numbered struct {
	n    int
	text string
}

// closesFence reports whether line closes a block opened by fence: the same
// character, at least as many times, and nothing after it.
func closesFence(line, fence string) bool {
	m := openFence.FindStringSubmatch(line)
	return m != nil && m[1][0] == fence[0] && len(m[1]) >= len(fence) && strings.TrimSpace(m[2]) == ""
}

// checkHeader checks the title and the header's rows, and returns the
// prefix the header names, or "" when it names none.
func checkHeader(doc []byte, dir string, n int, file string, p *problems) string {
	ls := lines(doc)
	title := fmt.Sprintf("# %s, version %d", dir, n)
	if len(ls) == 0 || ls[0].n != 1 || ls[0].text != title {
		p.addf(file, "does not start with the title %q", title)
	}
	rows := map[string]string{}
	prefix := ""
	for _, l := range ls {
		if strings.HasPrefix(l.text, "## ") {
			break
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(l.text), "|"), "|")
		if !strings.HasPrefix(strings.TrimSpace(l.text), "|") || len(cells) < 2 {
			continue
		}
		rows[strings.TrimSpace(cells[0])] = strings.TrimSpace(strings.Join(cells[1:], "|"))
		if m := prefixRow.FindStringSubmatch(strings.TrimSpace(l.text)); m != nil {
			prefix = m[1]
		}
	}
	if prefix == "" {
		p.addf(file, "has no header row \"| Requirement identifiers | `PREFIX-<n>` |\" before its first section")
	}
	if !strings.Contains(rows["Concept"], "](https://buildwarden.github.io/buildwarden/") {
		p.addf(file, "has no header row \"Concept\" linking the book, https://buildwarden.github.io/buildwarden/")
	}
	if rows["Reference implementation"] == "" {
		p.addf(file, "has no header row \"Reference implementation\" naming it")
	}
	return prefix
}

// checkSections checks that every section of Sections is a second-level
// heading of the document, once, and in the order Sections gives.
func checkSections(doc []byte, file string, p *problems) {
	at := map[string][]int{}
	for _, l := range lines(doc) {
		if h, ok := strings.CutPrefix(l.text, "## "); ok {
			h = strings.TrimSpace(h)
			at[h] = append(at[h], l.n)
		}
	}
	last, lastName := 0, ""
	for _, s := range Sections {
		switch len(at[s]) {
		case 0:
			p.addf(file, "has no section \"## %s\"", s)
			continue
		case 1:
		default:
			p.addf(file, "has the section \"## %s\" %d times", s, len(at[s]))
		}
		if at[s][0] < last {
			p.addf(file, "has the section \"## %s\" (line %d) before \"## %s\" (line %d)", s, at[s][0], lastName, last)
		}
		last, lastName = at[s][0], s
	}
}

// noLoader refuses every reference that is not a file of the directory, so
// that the checks never reach the network.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("%s is not a schema file of this directory", url)
}

// checkSchemas checks each schema file's $schema and $id and that it is a
// valid 2020-12 schema, and returns the compiled schemas by file name.
func checkSchemas(fsys fs.FS, dir string, schemas []string, p *problems) map[string]*jsonschema.Schema {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noLoader{})
	var added []string
	for _, name := range schemas {
		file := path.Join(dir, name)
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			p.add(file, err)
			continue
		}
		var head struct {
			Schema string `json:"$schema"`
			ID     string `json:"$id"`
		}
		if err := json.Unmarshal(b, &head); err != nil {
			p.addf(file, "is not a JSON object: %v", err)
			continue
		}
		if head.Schema != Draft202012 {
			p.addf(file, "$schema is %q, want %q", head.Schema, Draft202012)
		}
		if want := SchemaID(dir, name); head.ID != want {
			p.addf(file, "$id is %q, want %q", head.ID, want)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			p.addf(file, "is not JSON: %v", err)
			continue
		}
		if err := c.AddResource(SchemaID(dir, name), doc); err != nil {
			p.addf(file, "%v", err)
			continue
		}
		added = append(added, name)
	}
	compiled := map[string]*jsonschema.Schema{}
	for _, name := range added {
		s, err := c.Compile(SchemaID(dir, name))
		if err != nil {
			p.addf(path.Join(dir, name), "is not a valid JSON Schema 2020-12: %v", err)
			continue
		}
		compiled[name] = s
	}
	return compiled
}

// checkExamples checks each JSON example of the document v<n>.md: that it is
// JSON, and that it validates against the schema file it names.
func checkExamples(doc []byte, dir string, n int, compiled map[string]*jsonschema.Schema, p *problems) {
	file := path.Join(dir, fmt.Sprintf("v%d.md", n))
	var (
		fence, schema string
		isJSON        bool
		start         int
		body          []string
	)
	for i, line := range strings.Split(string(doc), "\n") {
		line = strings.TrimRight(line, "\r")
		if fence == "" {
			m := openFence.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			fence, start, body = m[1], i+1, nil
			info := strings.Fields(m[2])
			isJSON = len(info) > 0 && info[0] == "json"
			schema = ""
			switch {
			case !isJSON:
			case len(info) > 2:
				p.addf(file, "line %d: the info string %q names more than one schema", start, strings.TrimSpace(m[2]))
				isJSON = false
			case len(info) == 2:
				schema = info[1]
			}
			continue
		}
		if !closesFence(line, fence) {
			body = append(body, line)
			continue
		}
		fence = ""
		if isJSON {
			checkExample(strings.Join(body, "\n"), schema, file, start, dir, n, compiled, p)
		}
	}
}

func checkExample(body, schema, file string, line int, dir string, n int, compiled map[string]*jsonschema.Schema, p *problems) {
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		p.addf(file, "line %d: the JSON example is not JSON: %v", line, err)
		return
	}
	if schema == "" {
		return
	}
	m := jsonName.FindStringSubmatch(schema)
	if m == nil || m[3] != "schema" || fileVersion(schema) != n {
		p.addf(file, "line %d: the example names %q, which is not a schema file of version %d (v%d.schema.json or v%d.<part>.schema.json)", line, schema, n, n, n)
		return
	}
	s, ok := compiled[schema]
	if !ok {
		p.addf(file, "line %d: the example names %s, which is not a valid schema file in %s", line, schema, dir)
		return
	}
	if err := s.Validate(inst); err != nil {
		p.addf(file, "line %d: the example does not validate against %s: %v", line, schema, err)
	}
}
