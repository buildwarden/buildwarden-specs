package cases

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	collectorinputs "github.com/buildwarden/buildwarden-specs/collector-inputs"
	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The cases that test a collector. Each starts a relay of its own, which the
// collector claims, so each ends the instance it runs against.

// The schemas of the completion's body and of the status (COLLIN-23,
// COLLIN-26).
const (
	completeSchema = "v1.complete.schema.json"
	statusSchema   = "v1.status.schema.json"
)

// The forms a case needs the collector to be started as, or to be.
func noScript(d target.Declared) string {
	if !d.Forms.NoScript {
		return "the collector cannot be started without a build script"
	}
	return ""
}

func noContext(d target.Declared) string {
	if !d.Forms.NoContext {
		return "the collector cannot be started without a build context"
	}
	return ""
}

func hasBootstrap(d target.Declared) string {
	if d.Forms.NoBootstrap {
		return "the collector has no bootstrap config"
	}
	return ""
}

func noBootstrap(d target.Declared) string {
	if !d.Forms.NoBootstrap {
		return "the collector always has a bootstrap config"
	}
	return ""
}

func servesAfter(d target.Declared) string {
	if !d.Forms.ServesAfterCompletion {
		return "the collector does not serve its session after the completion"
	}
	return ""
}

// script is the build script a case gives a collector.
var script = []byte("#!/bin/sh\necho conformance\n")

// scriptFile writes script to a file of the case's, for a collector's start.
func scriptFile(t *runner.T) string {
	p := filepath.Join(t.TempDir(), "build.sh")
	if err := os.WriteFile(p, script, 0o644); err != nil {
		t.Fatalf("the build script: %v", err)
	}
	return p
}

// contextFiles are the files of the build context a case gives a
// collector, by their slash path. "bad-" and "x y.txt" are not safe context
// paths (COLLIN-15).
var contextFiles = map[string]string{
	"a.txt":         "a\n",
	"dir/b.txt":     "b\n",
	"dir/sub/c.txt": "c\n",
	".warden/d.txt": "d\n",
	"bad-":          "unsafe\n",
	"x y.txt":       "unsafe\n",
}

// contextDir writes contextFiles into a directory of the case's.
func contextDir(t *runner.T) string {
	dir := t.TempDir()
	for p, b := range contextFiles {
		f := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatalf("the build context: %v", err)
		}
		if err := os.WriteFile(f, []byte(b), 0o644); err != nil {
			t.Fatalf("the build context: %v", err)
		}
	}
	return dir
}

// get sends GET path with the session's token.
func (s *session) get(path string) *relay.Reply {
	return s.do(http.MethodGet, path, s.auth(), nil, nil)
}

// mediaType is rep's Content-Type without its parameters.
func mediaType(rep *relay.Reply) string {
	mt, _, _ := mime.ParseMediaType(rep.Header.Get("Content-Type"))
	return mt
}

// wantInput fails the case unless rep is 200 with the media type mt and the
// body want.
func wantInput(t *runner.T, what string, rep *relay.Reply, mt string, want []byte) {
	if rep.Status != http.StatusOK || mediaType(rep) != mt || !bytes.Equal(rep.Body, want) {
		t.Errorf("%s was answered %d, Content-Type %q, %q; want 200, %s, %q", what, rep.Status, rep.Header.Get("Content-Type"), short(rep.Body), mt, want)
	}
}

func wantStatus(t *runner.T, what string, rep *relay.Reply, status int) {
	if rep.Status != status {
		t.Errorf("%s was answered %d %q, want %d", what, rep.Status, short(rep.Body), status)
	}
}

// short renders the start of b for a failure.
func short(b []byte) string {
	if len(b) > 64 {
		return string(b[:64]) + "..."
	}
	return string(b)
}

// scriptServed serves the build script it was given.
var scriptServed = runner.Case{
	Name:    "a collector serves its build script at GET /v1/build-script",
	Cites:   []string{"COLLIN-3", "COLLIN-7", "COLLIN-13"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Script: scriptFile(t)})
		wantInput(t, "GET /v1/build-script", s.get("/v1/build-script"), "application/octet-stream", script)
	},
}

// noScriptServed answers 404 for a session with no build script.
var noScriptServed = runner.Case{
	Name:    "a collector with no build script answers GET /v1/build-script with 404",
	Cites:   []string{"COLLIN-13"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, noScript),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		wantStatus(t, "GET /v1/build-script with no script", s.get("/v1/build-script"), http.StatusNotFound)
	},
}

// bootstrapServed serves a bootstrap config as application/json, the same
// bytes each time. The case does not know the config the collector was
// given, so it checks only that what is served is one JSON document and is
// served alike twice; its schema is bootstrap-config's.
var bootstrapServed = runner.Case{
	Name:    "a collector serves its bootstrap config at GET /v1/bootstrap as application/json",
	Cites:   []string{"COLLIN-14"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, hasBootstrap),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		one, two := s.get("/v1/bootstrap"), s.get("/v1/bootstrap")
		if one.Status != http.StatusOK || mediaType(one) != "application/json" {
			t.Fatalf("GET /v1/bootstrap was answered %d, Content-Type %q, want 200 and application/json", one.Status, one.Header.Get("Content-Type"))
		}
		if !json.Valid(one.Body) {
			t.Errorf("GET /v1/bootstrap served %q, which is not JSON", short(one.Body))
		}
		if !bytes.Equal(one.Body, two.Body) || two.Status != http.StatusOK {
			t.Errorf("GET /v1/bootstrap served %q, and then %d %q", short(one.Body), two.Status, short(two.Body))
		}
	},
}

// noBootstrapServed answers 404 for a session with no bootstrap config.
var noBootstrapServed = runner.Case{
	Name:    "a collector with no bootstrap config answers GET /v1/bootstrap with 404",
	Cites:   []string{"COLLIN-14"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, noBootstrap),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		wantStatus(t, "GET /v1/bootstrap with no bootstrap config", s.get("/v1/bootstrap"), http.StatusNotFound)
	},
}

// contextServed serves each file of the context, and a listing of the files
// beneath the root and each directory, by safe paths only, sorted.
var contextServed = runner.Case{
	Name:    "a collector serves a context file, and lists the safe files beneath a directory, sorted",
	Cites:   []string{"COLLIN-11", "COLLIN-16", "COLLIN-17"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Context: contextDir(t)})
		for _, p := range []string{"a.txt", "dir/b.txt", "dir/sub/c.txt", ".warden/d.txt"} {
			rep := s.get("/v1/context/" + p)
			wantInput(t, "GET /v1/context/"+p, rep, "application/octet-stream", []byte(contextFiles[p]))
			if k := rep.Header.Get("Warden-Context"); k != "file" {
				t.Errorf("GET /v1/context/%s has Warden-Context %q, want file", p, k)
			}
		}
		all := ".warden/d.txt\na.txt\ndir/b.txt\ndir/sub/c.txt\n"
		dir := "dir/b.txt\ndir/sub/c.txt\n"
		for p, want := range map[string]string{
			"": all, "dir": dir, "dir/": dir, "dir/sub": "dir/sub/c.txt\n", "dir/sub/": "dir/sub/c.txt\n", ".warden/": ".warden/d.txt\n",
		} {
			rep := s.get("/v1/context/" + p)
			wantInput(t, "GET /v1/context/"+p, rep, "text/plain", []byte(want))
			if k := rep.Header.Get("Warden-Context"); k != "list" {
				t.Errorf("GET /v1/context/%s has Warden-Context %q, want list", p, k)
			}
		}
	},
}

// contextEmpty lists an empty context as an empty body.
var contextEmpty = runner.Case{
	Name:    "a collector lists a build context that has no files as an empty listing",
	Cites:   []string{"COLLIN-17"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Context: t.TempDir()})
		rep := s.get("/v1/context/")
		wantInput(t, "GET /v1/context/ of an empty context", rep, "text/plain", nil)
		if k := rep.Header.Get("Warden-Context"); k != "list" {
			t.Errorf("GET /v1/context/ has Warden-Context %q, want list", k)
		}
	},
}

// unsafeContextPaths are context paths that are not safe (COLLIN-15), as a
// path carries them; none has an empty, "." or ".." segment.
var unsafeContextPaths = []string{
	"bad-", "x%20y.txt", "a.txt.", "a.txt_", "dir/b.txt-", "dir-/b.txt", "a%7Eb", "a%25b",
	strings.Repeat("a", 256), strings.Repeat("ab/", 85) + "a",
}

// contextUnsafe answers 403 to a context path that is not safe, and serves
// nothing for it.
var contextUnsafe = runner.Case{
	Name:    "a collector answers 403 to a context path that is not safe",
	Cites:   []string{"COLLIN-11", "COLLIN-15"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Context: contextDir(t)})
		for _, p := range unsafeContextPaths {
			rep := s.get("/v1/context/" + p)
			wantStatus(t, "GET /v1/context/"+p, rep, http.StatusForbidden)
			if bytes.Contains(rep.Body, []byte("unsafe")) {
				t.Errorf("GET /v1/context/%s served the file's bytes", p)
			}
		}
	},
}

// contextMissing answers 404 to a path that names nothing, and to a file
// named with a trailing "/".
var contextMissing = runner.Case{
	Name:    "a collector answers 404 to a context path that names nothing, or a file with a trailing /",
	Cites:   []string{"COLLIN-18"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Context: contextDir(t)})
		for _, p := range []string{"nope.txt", "dir/nope", "nope/", "a.txt/", "dir/sub/c.txt/"} {
			wantStatus(t, "GET /v1/context/"+p, s.get("/v1/context/"+p), http.StatusNotFound)
		}
	},
}

// noContextServed answers 404 to every context path of a session with no
// build context.
var noContextServed = runner.Case{
	Name:    "a collector with no build context answers every context path with 404",
	Cites:   []string{"COLLIN-18"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, noContext),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, p := range []string{"", "a.txt", "dir/", "dir"} {
			wantStatus(t, "GET /v1/context/"+p+" with no context", s.get("/v1/context/"+p), http.StatusNotFound)
		}
	},
}

// contextLinks serves nothing through a link that leads out of the context,
// and lists neither it nor a link to a directory inside.
var contextLinks = runner.Case{
	Name:    "a collector serves no symbolic link that leads out of the context, and lists no link to a directory",
	Cites:   []string{"COLLIN-19"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		dir := contextDir(t)
		outside := filepath.Join(t.TempDir(), "secret.txt")
		if err := os.WriteFile(outside, []byte("secret\n"), 0o644); err != nil {
			t.Fatalf("a file outside the context: %v", err)
		}
		for link, to := range map[string]string{"out.txt": outside, "outdir": filepath.Dir(outside), "linkdir": filepath.Join(dir, "dir")} {
			if err := os.Symlink(to, filepath.Join(dir, link)); err != nil {
				t.Fatalf("a symbolic link %s in the context: %v", link, err)
			}
		}
		s := claimedBy(t, attach.Params{Context: dir})
		for _, p := range []string{"out.txt", "outdir/secret.txt"} {
			rep := s.get("/v1/context/" + p)
			wantStatus(t, "GET /v1/context/"+p+" through a link out of the context", rep, http.StatusNotFound)
			if bytes.Contains(rep.Body, []byte("secret")) {
				t.Errorf("GET /v1/context/%s served the bytes of a file outside the context", p)
			}
		}
		rep := s.get("/v1/context/")
		wantInput(t, "GET /v1/context/ with links", rep, "text/plain", []byte(".warden/d.txt\na.txt\ndir/b.txt\ndir/sub/c.txt\n"))
	},
}

// inputMethods answers 405 to a method other than GET on the inputs.
var inputMethods = runner.Case{
	Name:    "a collector answers 405 to a method other than GET on the inputs",
	Cites:   []string{"COLLIN-20"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Script: scriptFile(t), Context: contextDir(t)})
		for _, p := range []string{"/v1/build-script", "/v1/bootstrap", "/v1/context/", "/v1/context/a.txt", "/v1/context/dir/"} {
			for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
				wantStatus(t, m+" "+p, s.do(m, p, s.auth(), []byte("x"), nil), http.StatusMethodNotAllowed)
			}
		}
	},
}

// signalsAnswered answers ready and heartbeat 200, and the session's
// requests in an order of the relay's choosing, inputs and signals among
// them, while its ledger request is open.
var signalsAnswered = runner.Case{
	Name:    "a collector answers ready and heartbeat with 200, and the session's requests in any order while the ledger is open",
	Cites:   []string{"COLLIN-3", "COLLIN-7", "COLLIN-21", "COLLIN-22", "COLLIN-36"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Script: scriptFile(t), Context: contextDir(t)})
		post := func(p string) {
			wantStatus(t, "POST "+p, s.do(http.MethodPost, p, s.auth(), nil, nil), http.StatusOK)
		}
		post("/v1/heartbeat")
		wantInput(t, "GET /v1/context/a.txt", s.get("/v1/context/a.txt"), "application/octet-stream", []byte(contextFiles["a.txt"]))
		post("/v1/ready")
		post("/v1/heartbeat")
		wantInput(t, "GET /v1/build-script", s.get("/v1/build-script"), "application/octet-stream", script)
		post("/v1/heartbeat")
		wantStatus(t, "GET /v1/context/", s.get("/v1/context/"), http.StatusOK)
		if _, done, err := s.s.LedgerReply(); done {
			t.Errorf("the ledger request ended before the completion (%v)", err)
		}
	},
}

// signalMethods answers 405 to a method other than POST on the signals.
var signalMethods = runner.Case{
	Name:    "a collector answers 405 to a method other than POST on the signals",
	Cites:   []string{"COLLIN-25"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, p := range []string{"/v1/ready", "/v1/heartbeat", "/v1/complete"} {
			for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
				var body []byte
				if m != http.MethodGet {
					body = []byte(`{"exit_code":0,"message":"","error":""}`)
				}
				wantStatus(t, m+" "+p, s.do(m, p, s.auth(), body, nil), http.StatusMethodNotAllowed)
			}
		}
	},
}

// notCompletions are bodies of POST /v1/complete that COLLIN-23 has a
// collector answer 400.
var notCompletions = []string{
	`not json`,
	`{"exit_code":0,`,
	`[]`,
	`[{"exit_code":0,"message":"","error":""}]`,
	`"done"`,
	`0`,
	`true`,
	`{"exit_code":"0","message":"","error":""}`,
	`{"exit_code":true,"message":"","error":""}`,
	`{"exit_code":0,"message":1,"error":""}`,
	`{"exit_code":0,"message":"","error":false}`,
	`{"exit_code":0,"message":"","error":{}}`,
}

// completionRead answers 400 to each body that is not a completion, which
// does not complete the session, and 200 to one that is.
var completionRead = runner.Case{
	Name:    "a collector answers 400 to a completion's body that is not one, and 200 to one that is",
	Cites:   []string{"COLLIN-23"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		h := s.auth()
		h.Set("Content-Type", "application/json")
		for _, b := range notCompletions {
			wantStatus(t, "POST /v1/complete with "+b, s.do(http.MethodPost, "/v1/complete", h, []byte(b), nil), http.StatusBadRequest)
		}
		// None of them completed the session: it still serves.
		wantStatus(t, "POST /v1/heartbeat after the refused completions", s.do(http.MethodPost, "/v1/heartbeat", s.auth(), nil, nil), http.StatusOK)
		// The completion, with a member the collector ignores. Its reply
		// may not come (COLLIN-2, D16).
		body := []byte(`{"exit_code":3,"message":"done","error":"","extra":[1]}`)
		rep, err := s.s.Do(t.Context(), http.MethodPost, "/v1/complete", h, bytes.NewReader(body), nil)
		if err == nil && rep.Status != http.StatusOK {
			t.Errorf("POST /v1/complete with %s was answered %d %q, want 200", body, rep.Status, rep.Body)
		}
	},
}

// statusOf reads GET /v1/status as COLLIN-26 has it: 200, application/json,
// a body valid against the status schema.
func statusOf(t *runner.T, s *session) map[string]any {
	rep := s.do(http.MethodGet, "/v1/status", http.Header{}, nil, nil)
	if rep.Status != http.StatusOK || mediaType(rep) != "application/json" {
		t.Fatalf("GET /v1/status was answered %d, Content-Type %q, %q; want 200 and application/json", rep.Status, rep.Header.Get("Content-Type"), rep.Body)
	}
	if err := collectorinputs.Spec.Validate(statusSchema, rep.Body); err != nil {
		t.Errorf("GET /v1/status: %v; the body: %q", err, rep.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rep.Body, &m); err != nil {
		t.Fatalf("GET /v1/status: %v; the body: %q", err, rep.Body)
	}
	return m
}

// statusRunning answers GET /v1/status before the completion with
// {"state":"running"}, and 405 to another method.
var statusRunning = runner.Case{
	Name:    "a collector answers GET /v1/status before its completion with the state running",
	Cites:   []string{"COLLIN-26"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		if m := statusOf(t, s); len(m) != 1 || m["state"] != "running" {
			t.Errorf("GET /v1/status before the completion gave %v, want {\"state\":\"running\"}", m)
		}
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			wantStatus(t, m+" /v1/status", s.do(m, "/v1/status", s.auth(), []byte("{}"), nil), http.StatusMethodNotAllowed)
		}
	},
}

// statusCompleted answers GET /v1/status after the completion with the
// first completion's members and when it was received; a later completion
// is answered 200 and changes nothing.
var statusCompleted = runner.Case{
	Name:    "a collector's status after its completion is the first completion, which a later one does not change",
	Cites:   []string{"COLLIN-24", "COLLIN-26"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, servesAfter),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		before := time.Now()
		if rep, err := s.s.Complete(t.Context(), relay.Completion{ExitCode: 3, Message: "the message", Error: "the error"}); err != nil || rep.Status != http.StatusOK {
			t.Fatalf("POST /v1/complete: %v %v, want 200", rep, err)
		}
		after := time.Now()
		rep, err := s.s.Complete(t.Context(), relay.Completion{ExitCode: 5, Message: "later"})
		if err != nil || rep.Status != http.StatusOK {
			t.Errorf("a second POST /v1/complete: %v %v, want 200", rep, err)
		}
		m := statusOf(t, s)
		if m["exit_code"] != float64(3) || m["message"] != "the message" || m["error"] != "the error" {
			t.Errorf("GET /v1/status after the completions gave %v, want the first's exit_code 3, message and error", m)
		}
		at, _ := m["received_at"].(string)
		got, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			t.Errorf("received_at %q is not an RFC 3339 date and time: %v", at, err)
		} else if got.Before(before.Add(-time.Minute)) || got.After(after.Add(time.Minute)) {
			t.Errorf("received_at %s is not the time the first completion was received, between %s and %s", got, before, after)
		}
	},
}

// healthz answers GET /healthz with 200 and "ok" and a line feed, without a
// token, as GET /v1/status is.
var healthz = runner.Case{
	Name:    "a collector answers GET /healthz and GET /v1/status with 200, with no token",
	Cites:   []string{"COLLIN-6", "COLLIN-27"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, h := range []http.Header{{}, s.auth()} {
			rep := s.do(http.MethodGet, "/healthz", h, nil, nil)
			if rep.Status != http.StatusOK || string(rep.Body) != "ok\n" {
				t.Errorf("GET /healthz with Authorization %q was answered %d %q, want 200 \"ok\\n\"", h.Get("Authorization"), rep.Status, rep.Body)
			}
		}
		wantStatus(t, "GET /v1/status with no token", s.do(http.MethodGet, "/v1/status", http.Header{}, nil, nil), http.StatusOK)
	},
}

// unauthorizedInputs answers 401 with the body "unauthorized" and a line
// feed to an input or a signal with no token or another, whatever its
// method; none of them completes the session.
var unauthorizedInputs = runner.Case{
	Name:    "a collector with a token answers 401 to an input or a signal with no token or another",
	Cites:   []string{"COLLIN-5"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, hasToken),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Script: scriptFile(t), Context: contextDir(t)})
		tok := s.requireToken()
		for _, auth := range []string{"", "Bearer " + tok + "x", "Bearer wrong"} {
			h := http.Header{}
			if auth != "" {
				h.Set("Authorization", auth)
			}
			for _, c := range []struct {
				method, path string
				body         []byte
			}{
				{http.MethodGet, "/v1/build-script", nil},
				{http.MethodGet, "/v1/bootstrap", nil},
				{http.MethodGet, "/v1/context/", nil},
				{http.MethodGet, "/v1/context/a.txt", nil},
				{http.MethodGet, "/v1/context/bad-", nil},
				{http.MethodPost, "/v1/ready", nil},
				{http.MethodPost, "/v1/heartbeat", nil},
				{http.MethodPost, "/v1/complete", []byte(`{"exit_code":0,"message":"","error":""}`)},
				{http.MethodDelete, "/v1/build-script", nil},
			} {
				rep := s.do(c.method, c.path, h, c.body, nil)
				if rep.Status != http.StatusUnauthorized || string(rep.Body) != "unauthorized\n" {
					t.Errorf("%s %s with Authorization %q was answered %d %q, want 401 \"unauthorized\\n\"", c.method, c.path, auth, rep.Status, short(rep.Body))
				}
			}
		}
		// The refused completions completed nothing.
		wantStatus(t, "POST /v1/heartbeat with the token", s.do(http.MethodPost, "/v1/heartbeat", s.auth(), nil, nil), http.StatusOK)
	},
}

// tokenless: a collector with no token refuses nothing for its
// Authorization header.
var tokenless = runner.Case{
	Name:    "a collector with no token refuses no input or signal for its Authorization header",
	Cites:   []string{"COLLIN-8"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, noToken),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Script: scriptFile(t)})
		if tok := s.s.Token(); tok != "" {
			t.Fatalf("the collector declares no token, and its claim carried a collector_token")
		}
		for _, auth := range []string{"", "Bearer anything", "Basic x", "anything"} {
			h := http.Header{}
			if auth != "" {
				h.Set("Authorization", auth)
			}
			wantStatus(t, "POST /v1/heartbeat with Authorization "+auth, s.do(http.MethodPost, "/v1/heartbeat", h, nil, nil), http.StatusOK)
			wantStatus(t, "GET /v1/build-script with Authorization "+auth, s.do(http.MethodGet, "/v1/build-script", h, nil, nil), http.StatusOK)
		}
	},
}
