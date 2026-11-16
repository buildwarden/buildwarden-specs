package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/blake2b"
)

// The specification directories, beside the harness in this checkout.
var specDir = filepath.Join("..", "..")

func read(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func compile(t *testing.T, dir, name string) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(read(t, dir, name)))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validates(t *testing.T, s *jsonschema.Schema, b []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not JSON: %v: %s", err, b)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("%s does not validate: %v", b, err)
	}
}

var fence = regexp.MustCompile("(?s)```json ([^\\n]+)\\n(.*?)\\n```")

// examples are a document's JSON examples for the schema file name.
func examples(t *testing.T, dir, name string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, m := range fence.FindAllSubmatch(read(t, dir, "v1.md"), -1) {
		if string(m[1]) == name {
			out = append(out, m[2])
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s/v1.md has no example of %s", dir, name)
	}
	return out
}

// serve serves c on a loopback listener and returns its base URL.
func serve(t *testing.T, c *Collector) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })
	return "http://" + l.Addr().String()
}

type client struct {
	t    *testing.T
	base string
	auth string
	c    *http.Client
}

func newClient(t *testing.T, c *Collector, auth string, h2 bool) *client {
	t.Helper()
	tr := &http.Transport{}
	if h2 {
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		tr.Protocols = &p
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &client{t: t, base: serve(t, c), auth: auth, c: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type answer struct {
	status int
	header http.Header
	body   []byte
}

func (c *client) do(method, path string, body io.Reader, edit ...func(*http.Request)) answer {
	c.t.Helper()
	r, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.auth != "" {
		r.Header.Set("Authorization", c.auth)
	}
	for _, e := range edit {
		e(r)
	}
	resp, err := c.c.Do(r)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return answer{resp.StatusCode, resp.Header, b}
}

func (c *client) expect(method, path string, body io.Reader, status int, want string, edit ...func(*http.Request)) answer {
	c.t.Helper()
	a := c.do(method, path, body, edit...)
	if a.status != status || (want != "*" && string(a.body) != want) {
		c.t.Errorf("%s %s: %d %q, want %d %q", method, path, a.status, a.body, status, want)
	}
	return a
}

var full = Form{
	Token:     "sess",
	Script:    []byte("#!/bin/sh\n"),
	Context:   map[string][]byte{"Makefile": []byte("all:\n"), "src/a.c": []byte("a"), "src/sub/b.c": []byte("b"), ".warden/cfg": []byte("c"), "bad name": []byte("x")},
	Bootstrap: []byte(`{"version": 1}`),
}

// TestAuthentication holds the collector to the documents' common part:
// the token on every endpoint under /v1/ but the status (COLLOUT-5,
// COLLIN-5, COLLIN-6), in the Bearer form only (COLLOUT-7), and nothing
// refused for its Authorization when the session has no token (COLLOUT-8).
func TestAuthentication(t *testing.T) {
	t.Parallel()
	paths := []struct{ method, path string }{
		{"PUT", "/v1/artifacts/a"}, {"PUT", "/v1/captures/c"}, {"PUT", "/v1/ledger"},
		{"PUT", "/v1/environment"}, {"POST", "/v1/output"}, {"GET", "/v1/build-script"},
		{"GET", "/v1/bootstrap"}, {"GET", "/v1/context/"}, {"GET", "/v1/context/Makefile"},
		{"POST", "/v1/ready"}, {"POST", "/v1/heartbeat"}, {"POST", "/v1/complete"},
		{"DELETE", "/v1/ledger"}, {"GET", "/v1/no-such-endpoint"},
	}
	for _, auth := range []string{"", "Bearer other", "bearer sess", "Bearer  sess", "sess"} {
		c := newClient(t, New(full, nil), auth, false)
		for _, p := range paths {
			c.expect(p.method, p.path, strings.NewReader("{}"), http.StatusUnauthorized, "unauthorized\n")
		}
		c.expect("GET", "/v1/status", nil, http.StatusOK, `{"state":"running"}`)
		c.expect("GET", "/healthz", nil, http.StatusOK, "ok\n")
	}
	c := newClient(t, New(full, nil), "Bearer sess", false)
	c.expect("GET", "/v1/build-script", nil, http.StatusOK, "#!/bin/sh\n")
	for _, auth := range []string{"", "Bearer x", "garbage"} {
		c := newClient(t, New(Form{Script: []byte("s")}, nil), auth, false)
		c.expect("GET", "/v1/build-script", nil, http.StatusOK, "s")
	}
}

// TestOpenAPI holds every reply of every operation the two OpenAPI
// descriptions list to the statuses and the content types they give it.
func TestOpenAPI(t *testing.T) {
	t.Parallel()
	type response struct {
		Content map[string]any `json:"content"`
	}
	type operation struct {
		Responses map[string]response `json:"responses"`
	}
	ops := map[string]operation{}
	for _, dir := range []string{"collector-outputs", "collector-inputs"} {
		var doc struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(read(t, dir, "v1.openapi.json"), &doc); err != nil {
			t.Fatal(err)
		}
		for path, methods := range doc.Paths {
			for m, raw := range methods {
				if m == "parameters" {
					continue
				}
				var op operation
				if err := json.Unmarshal(raw, &op); err != nil {
					t.Fatal(err)
				}
				ops[strings.ToUpper(m)+" "+path] = op
			}
		}
	}
	// Each operation's requests, in the forms the collector can be in, and
	// the template path they answer to.
	type probe struct {
		op, path string
		body     string
		edit     func(*http.Request)
	}
	hash := blake2b.Sum256([]byte("p"))
	withTrailer := func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader("p"))
		r.ContentLength = -1
		r.Trailer = http.Header{"Warden-Hash": {hex.EncodeToString(hash[:])}}
	}
	probes := []probe{
		{"PUT /v1/artifacts/{name}", "/v1/artifacts/a/b.bin", "x", nil},
		{"PUT /v1/artifacts/{name}", "/v1/artifacts/-a", "x", nil},
		{"PUT /v1/captures/{name}", "/v1/captures/c", "", withTrailer},
		{"PUT /v1/captures/{name}", "/v1/captures/c", "p", nil},
		{"PUT /v1/captures/{name}", "/v1/captures/...", "", withTrailer},
		{"PUT /v1/ledger", "/v1/ledger", "BLDL", nil},
		{"PUT /v1/environment", "/v1/environment", "{}", nil},
		{"PUT /v1/environment", "/v1/environment", strings.Repeat("x", EnvironmentLimit+1), nil},
		{"POST /v1/output", "/v1/output", "out", nil},
		{"GET /v1/build-script", "/v1/build-script", "", nil},
		{"GET /v1/bootstrap", "/v1/bootstrap", "", nil},
		{"GET /v1/context/", "/v1/context/", "", nil},
		{"GET /v1/context/{path}", "/v1/context/src/", "", nil},
		{"GET /v1/context/{path}", "/v1/context/src/a.c", "", nil},
		{"GET /v1/context/{path}", "/v1/context/nothing", "", nil},
		{"GET /v1/context/{path}", "/v1/context/a.", "", nil},
		{"POST /v1/ready", "/v1/ready", "", nil},
		{"POST /v1/heartbeat", "/v1/heartbeat", "", nil},
		{"POST /v1/complete", "/v1/complete", "[]", nil},
		{"GET /v1/status", "/v1/status", "", nil},
		{"GET /healthz", "/healthz", "", nil},
		{"POST /v1/complete", "/v1/complete", `{"exit_code":0,"message":"","error":""}`, nil},
		{"GET /v1/status", "/v1/status", "", nil},
	}
	covered := map[string]bool{}
	// Each form serves after its completion, so that the status after it
	// is probed too.
	all := full
	all.ServesAfterCompletion = true
	for _, f := range []Form{all, {Token: "sess", ServesAfterCompletion: true}, {Token: "sess", Context: map[string][]byte{}, ServesAfterCompletion: true}} {
		for _, auth := range []string{"Bearer sess", ""} {
			c := newClient(t, New(f, nil), auth, true)
			for _, p := range probes {
				op, ok := ops[p.op]
				if !ok {
					t.Fatalf("the OpenAPI descriptions have no operation %s", p.op)
				}
				covered[p.op] = true
				method, _, _ := strings.Cut(p.op, " ")
				var edit []func(*http.Request)
				if p.edit != nil {
					edit = append(edit, p.edit)
				}
				a := c.do(method, p.path, strings.NewReader(p.body), edit...)
				code := fmt.Sprint(a.status)
				res, ok := op.Responses[code]
				if !ok && a.status >= 500 {
					res, ok = op.Responses["5XX"]
				}
				if !ok {
					t.Errorf("%s %s (form with token %q, auth %q): %d, which %s does not list", method, p.path, f.Token, auth, a.status, p.op)
					continue
				}
				if len(res.Content) > 0 {
					mt, _, _ := strings.Cut(a.header.Get("Content-Type"), ";")
					if _, ok := res.Content[mt]; !ok {
						t.Errorf("%s %s: %d with Content-Type %q, which %s does not list", method, p.path, a.status, mt, p.op)
					}
				}
			}
		}
	}
	for op := range ops {
		if !covered[op] {
			t.Errorf("no probe of %s", op)
		}
	}
}

// TestSchemasAndExamples holds the collector's JSON to the documents'
// schemas, and its reading of their examples: each completion example is
// a completion, each bootstrap example is served byte for byte, and the
// status before and after a completion validates (COLLIN-14, COLLIN-23,
// COLLIN-26, BOOTCFG-1's collector side).
func TestSchemasAndExamples(t *testing.T) {
	t.Parallel()
	status := compile(t, "collector-inputs", "v1.status.schema.json")
	complete := compile(t, "collector-inputs", "v1.complete.schema.json")
	boot := compile(t, "bootstrap-config", "v1.schema.json")
	for _, ex := range examples(t, "collector-inputs", "v1.status.schema.json") {
		validates(t, status, ex)
	}
	for _, ex := range examples(t, "bootstrap-config", "v1.schema.json") {
		validates(t, boot, ex)
		c := newClient(t, New(Form{Bootstrap: ex}, nil), "", false)
		a := c.expect("GET", "/v1/bootstrap", nil, http.StatusOK, string(ex))
		if a.header.Get("Content-Type") != "application/json" {
			t.Errorf("bootstrap Content-Type %q", a.header.Get("Content-Type"))
		}
	}
	for _, ex := range examples(t, "collector-inputs", "v1.complete.schema.json") {
		validates(t, complete, ex)
		coll := New(Form{ServesAfterCompletion: true}, nil)
		c := newClient(t, coll, "", false)
		running := c.expect("GET", "/v1/status", nil, http.StatusOK, `{"state":"running"}`)
		validates(t, status, running.body)
		c.expect("POST", "/v1/complete", bytes.NewReader(ex), http.StatusOK, "")
		done := c.expect("GET", "/v1/status", nil, http.StatusOK, "*")
		validates(t, status, done.body)
		if done.header.Get("Content-Type") != "application/json" {
			t.Errorf("status Content-Type %q", done.header.Get("Content-Type"))
		}
		var got map[string]any
		if err := json.Unmarshal(done.body, &got); err != nil {
			t.Fatal(err)
		}
		var want map[string]any
		if err := json.Unmarshal(ex, &want); err != nil {
			t.Fatal(err)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("status %s = %v, want the completion's %v", k, got[k], v)
			}
		}
	}
}

// TestCompletion reads the completion as COLLIN-23 states it, keeps the
// first as the result (COLLIN-24), and refuses what the document leaves
// open.
func TestCompletion(t *testing.T) {
	t.Parallel()
	coll := New(Form{ServesAfterCompletion: true}, nil)
	c := newClient(t, coll, "", false)
	for _, body := range []string{
		"", "nope", "[]", `"s"`, "3", "true", "null",
		`{"exit_code":"0","message":"","error":""}`,
		`{"exit_code":0,"message":1,"error":""}`,
		`{"exit_code":0,"message":"","error":[]}`,
		`{"exit_code":null,"message":"","error":""}`,
		`{"message":"","error":""}`,
		`{"exit_code":0,"message":"","error":"","Exit_Code":1}`,
		`{"exit_code":0,"exit_code":1,"message":"","error":""}`,
		`{"exit_code":1.5,"message":"","error":""}`,
		`{"exit_code":1e2,"message":"","error":""}`,
		`{"exit_code":9223372036854775808,"message":"","error":""}`,
		`{"exit_code":0,"message":"","error":""} {}`,
	} {
		if a := c.do("POST", "/v1/complete", strings.NewReader(body)); a.status != http.StatusBadRequest {
			t.Errorf("completion %q: %d, want 400", body, a.status)
		}
	}
	if _, ok := coll.Completion(); ok {
		t.Fatal("a refused completion was recorded")
	}
	c.expect("GET", "/v1/complete", nil, http.StatusMethodNotAllowed, "POST only\n")
	c.expect("POST", "/v1/complete", strings.NewReader(`{"exit_code":-9223372036854775808,"message":"m","error":"e","other":{"x":1}}`), http.StatusOK, "")
	c.expect("POST", "/v1/complete", strings.NewReader(`{"exit_code":0,"message":"","error":""}`), http.StatusOK, "")
	comp, ok := coll.Completion()
	if !ok || comp.ExitCode != -9223372036854775808 || comp.Message != "m" || comp.Error != "e" {
		t.Errorf("the result is %+v, want the first completion", comp)
	}
}

// TestSessionEnds: a collector that does not serve after its completion
// answers the completion, closes Done, and resets every later request.
func TestSessionEnds(t *testing.T) {
	t.Parallel()
	coll := New(Form{}, nil)
	h := httpHandlerClient{coll}
	if s := h.serve("POST", "/v1/complete", `{"exit_code":0,"message":"","error":""}`); s != http.StatusOK {
		t.Fatalf("completion: %d", s)
	}
	select {
	case <-coll.Done():
	default:
		t.Fatal("Done is not closed after the completion")
	}
	func() {
		defer func() {
			if p := recover(); p != http.ErrAbortHandler {
				t.Errorf("a request after the completion: %v, want the handler aborted", p)
			}
		}()
		h.serve("GET", "/v1/status", "")
	}()
	reqs := coll.Requests()
	if len(reqs) != 2 || reqs[1].Status != 0 || reqs[1].End <= reqs[1].Begin {
		t.Errorf("requests %+v", reqs)
	}
	// One that serves after it keeps Done open.
	after := New(Form{ServesAfterCompletion: true}, nil)
	httpHandlerClient{after}.serve("POST", "/v1/complete", `{"exit_code":0,"message":"","error":""}`)
	select {
	case <-after.Done():
		t.Error("Done closed for a collector that serves after its completion")
	default:
	}
}

// httpHandlerClient calls the handler directly, with no server between.
type httpHandlerClient struct{ c *Collector }

func (h httpHandlerClient) serve(method, path, body string) int {
	r, _ := http.NewRequest(method, "http://collector.tunnel"+path, strings.NewReader(body))
	w := &recorder{header: http.Header{}}
	h.c.ServeHTTP(w, r)
	return w.status
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(s int) { r.status = s }

// TestOutputs holds the collector's side of collector-outputs: names
// (COLLOUT-11, COLLOUT-14, COLLOUT-16), the capture's trailer (COLLOUT-15,
// COLLOUT-17), the methods (COLLOUT-20, COLLOUT-23), the limits (COLLOUT-30,
// COLLOUT-31), and the console's order (COLLOUT-21).
func TestOutputs(t *testing.T) {
	t.Parallel()
	for _, h2 := range []bool{false, true} {
		coll := New(Form{}, nil)
		c := newClient(t, coll, "", h2)
		for _, name := range []string{"a", "a/b.c", "A-1_2.z9", "out/x/y"} {
			c.expect("PUT", "/v1/artifacts/"+name, strings.NewReader(name), http.StatusOK, "")
		}
		for _, name := range []string{"", "-a", "a-", "a/", "a//b", ".a", "a/.b", "%2e%2e", "a%2fb%2f", "a%20b", strings.Repeat("a", 256)} {
			c.expect("PUT", "/v1/artifacts/"+name, strings.NewReader("x"), http.StatusBadRequest, "*")
		}
		c.expect("PUT", "/v1/artifacts/a/./b", strings.NewReader("x"), http.StatusBadRequest, "*")
		c.expect("PUT", "/v1/artifacts/a/../b", strings.NewReader("x"), http.StatusBadRequest, "*")
		c.expect("POST", "/v1/artifacts/p", strings.NewReader("x"), http.StatusMethodNotAllowed, "PUT only\n")
		c.expect("GET", "/v1/ledger", nil, http.StatusMethodNotAllowed, "PUT only\n")
		c.expect("POST", "/v1/environment", strings.NewReader("x"), http.StatusMethodNotAllowed, "PUT only\n")
		c.expect("PUT", "/v1/output", strings.NewReader("x"), http.StatusMethodNotAllowed, "POST only\n")
		art := coll.Artifacts()
		if len(art) != 4 || string(art["a/b.c"]) != "a/b.c" {
			t.Errorf("artifacts %v", art)
		}

		body := []byte("captured")
		sum := blake2b.Sum256(body)
		good := hex.EncodeToString(sum[:])
		capture := func(name string, trailer http.Header, header http.Header) func(*http.Request) {
			return func(r *http.Request) {
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = -1
				r.Trailer = trailer
				for k, v := range header {
					r.Header[k] = v
				}
			}
		}
		wrong := strings.Repeat("0", 64)
		c.expect("PUT", "/v1/captures/0001-GET-h%2Fp%20q", nil, http.StatusOK, "", capture("", http.Header{"Warden-Hash": {good}}, nil))
		c.expect("PUT", "/v1/captures/upper", nil, http.StatusOK, "", capture("", http.Header{"Warden-Hash": {strings.ToUpper(wrong)}}, nil))
		c.expect("PUT", "/v1/captures/none", nil, http.StatusBadRequest, "*", capture("", nil, nil))
		c.expect("PUT", "/v1/captures/as-header", nil, http.StatusBadRequest, "*", capture("", nil, http.Header{"Warden-Hash": {good}}))
		c.expect("PUT", "/v1/captures/short", nil, http.StatusBadRequest, "*", capture("", http.Header{"Warden-Hash": {good[:63]}}, nil))
		c.expect("PUT", "/v1/captures/notHex", nil, http.StatusBadRequest, "*", capture("", http.Header{"Warden-Hash": {strings.Repeat("g", 64)}}, nil))
		for _, name := range []string{"", "...", strings.Repeat("a", 256)} {
			c.expect("PUT", "/v1/captures/"+name, nil, http.StatusBadRequest, "*", capture("", http.Header{"Warden-Hash": {good}}, nil))
		}
		caps := coll.Captures()
		if len(caps) != 2 {
			t.Fatalf("%d captures, want 2: %+v", len(caps), caps)
		}
		if caps[0].Sent != "0001-GET-h/p q" || caps[0].Name != "0001-GET-h_p_q" || caps[0].Hash != good || caps[0].BodyHash != good {
			t.Errorf("capture 0: %+v", caps[0])
		}
		if caps[1].Hash == caps[1].BodyHash {
			t.Error("a capture whose trailer is not its body's hash recorded no difference")
		}

		c.expect("PUT", "/v1/environment", strings.NewReader(strings.Repeat("e", EnvironmentLimit)), http.StatusOK, "")
		c.expect("PUT", "/v1/environment", strings.NewReader(strings.Repeat("f", EnvironmentLimit+1)), http.StatusRequestEntityTooLarge, "*")
		env, n := coll.Environment()
		if len(env) != EnvironmentLimit || env[0] != 'e' || n != 2 {
			t.Errorf("environment of %d bytes, %d requests: the 413 replaced what was stored", len(env), n)
		}

		for i := range 5 {
			c.expect("POST", "/v1/output", strings.NewReader(fmt.Sprint(i)), http.StatusOK, "")
		}
		if string(coll.Output()) != "01234" {
			t.Errorf("output %q", coll.Output())
		}
	}
}

// TestLedgerWhileOpen holds the ledger to COLLOUT-19 and COLLOUT-28: its
// bytes are stored as they arrive, the session's other requests are served
// while it is open, and its 200 comes once its body has ended.
func TestLedgerWhileOpen(t *testing.T) {
	t.Parallel()
	coll := New(Form{Context: map[string][]byte{}}, nil)
	base := serve(t, coll)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "PUT /v1/ledger HTTP/1.1\r\nHost: c\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nBLDL\x01\r\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if l, _, _ := coll.Ledger(); string(l) == "BLDL\x01" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ledger's first bytes were not stored while its request was open")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := newClient(t, coll, "", false)
	c.base = base
	c.expect("POST", "/v1/ready", nil, http.StatusOK, "")
	c.expect("GET", "/v1/context/", nil, http.StatusOK, "")
	if _, n, ended := coll.Ledger(); n != 1 || ended {
		t.Fatalf("%d ledger requests, ended %v", n, ended)
	}
	if _, err := io.WriteString(conn, "3\r\nabc\r\n0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ledger: %d", resp.StatusCode)
	}
	if l, n, ended := coll.Ledger(); string(l) != "BLDL\x01abc" || n != 1 || !ended {
		t.Errorf("ledger %q, %d requests, ended %v", l, n, ended)
	}
	reqs := coll.Requests()
	if len(reqs) != 3 || reqs[0].Path != "/v1/ledger" || reqs[0].End < reqs[2].End {
		t.Errorf("the ledger request did not stay open across the others: %+v", reqs)
	}
}

// TestInputs holds the collector's side of collector-inputs: the build
// script and bootstrap config, or a 404 (COLLIN-13, COLLIN-14); the build
// context (COLLIN-15 to COLLIN-18); the methods (COLLIN-20, COLLIN-25).
func TestInputs(t *testing.T) {
	t.Parallel()
	c := newClient(t, New(full, nil), "Bearer sess", false)
	a := c.expect("GET", "/v1/build-script", nil, http.StatusOK, "#!/bin/sh\n")
	if a.header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("script Content-Type %q", a.header.Get("Content-Type"))
	}
	c.expect("GET", "/v1/bootstrap", nil, http.StatusOK, `{"version": 1}`)
	list := c.expect("GET", "/v1/context/", nil, http.StatusOK, ".warden/cfg\nMakefile\nsrc/a.c\nsrc/sub/b.c\n")
	if list.header.Get("Warden-Context") != "list" || list.header.Get("Content-Type") != "text/plain" {
		t.Errorf("listing headers %v", list.header)
	}
	c.expect("GET", "/v1/context/src", nil, http.StatusOK, "src/a.c\nsrc/sub/b.c\n")
	c.expect("GET", "/v1/context/src/", nil, http.StatusOK, "src/a.c\nsrc/sub/b.c\n")
	c.expect("GET", "/v1/context/src/sub/", nil, http.StatusOK, "src/sub/b.c\n")
	file := c.expect("GET", "/v1/context/.warden/cfg", nil, http.StatusOK, "c")
	if file.header.Get("Warden-Context") != "file" || file.header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("file headers %v", file.header)
	}
	c.expect("GET", "/v1/context/Makefile/", nil, http.StatusNotFound, "*")
	c.expect("GET", "/v1/context/nothing", nil, http.StatusNotFound, "*")
	c.expect("GET", "/v1/context/bad%20name", nil, http.StatusForbidden, "*")
	c.expect("GET", "/v1/context/a.", nil, http.StatusForbidden, "*")
	c.expect("GET", "/v1/context/%2e%2e", nil, http.StatusForbidden, "*")
	c.expect("GET", "/v1/context/src/../Makefile", nil, http.StatusBadRequest, "*")
	for _, p := range []string{"/v1/build-script", "/v1/bootstrap", "/v1/context/"} {
		c.expect("POST", p, nil, http.StatusMethodNotAllowed, "GET only\n")
	}
	for _, p := range []string{"/v1/ready", "/v1/heartbeat"} {
		c.expect("GET", p, nil, http.StatusMethodNotAllowed, "POST only\n")
		c.expect("POST", p, nil, http.StatusOK, "")
	}
	c.expect("POST", "/v1/status", nil, http.StatusMethodNotAllowed, "GET only\n")

	none := newClient(t, New(Form{}, nil), "", false)
	none.expect("GET", "/v1/build-script", nil, http.StatusNotFound, "*")
	none.expect("GET", "/v1/bootstrap", nil, http.StatusNotFound, "*")
	none.expect("GET", "/v1/context/", nil, http.StatusNotFound, "*")
	none.expect("GET", "/v1/context/bad%20name", nil, http.StatusNotFound, "*")
	empty := newClient(t, New(Form{Context: map[string][]byte{}}, nil), "", false)
	empty.expect("GET", "/v1/context/", nil, http.StatusOK, "")
}

// TestFault answers a request with the status a case sets, after the
// token, and stores nothing for it.
func TestFault(t *testing.T) {
	t.Parallel()
	coll := New(Form{Token: "t", Script: []byte("s")}, func(r *http.Request) int {
		if r.URL.Path == "/v1/build-script" || r.URL.Path == "/v1/environment" {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	c := newClient(t, coll, "Bearer t", false)
	c.expect("GET", "/v1/build-script", nil, http.StatusServiceUnavailable, "*")
	c.expect("PUT", "/v1/environment", strings.NewReader("{}"), http.StatusServiceUnavailable, "*")
	if env, n := coll.Environment(); env != nil || n != 0 {
		t.Errorf("a faulted environment was stored: %q, %d", env, n)
	}
	unauth := newClient(t, coll, "", false)
	unauth.c = c.c
	unauth.base = c.base
	unauth.expect("GET", "/v1/build-script", nil, http.StatusUnauthorized, "unauthorized\n")
	got := slices.Collect(func(yield func(int) bool) {
		for _, r := range coll.Requests() {
			if !yield(r.Status) {
				return
			}
		}
	})
	if !slices.Equal(got, []int{503, 503, 401}) {
		t.Errorf("recorded statuses %v", got)
	}
}

// TestServeEndsAtCompletion: the collector served at a base URL of its own
// stops serving at the completion of a session it does not serve after.
func TestServeEndsAtCompletion(t *testing.T) {
	t.Parallel()
	coll := New(Form{}, nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- coll.Serve(l) }()
	c := &client{t: t, base: "http://" + l.Addr().String(), c: &http.Client{}}
	c.expect("POST", "/v1/complete", strings.NewReader(`{"exit_code":0,"message":"","error":""}`), http.StatusOK, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Serve did not return at the completion")
	}
}
