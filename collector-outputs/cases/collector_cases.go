package cases

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The cases that test a collector. Each starts a relay of its own, which the
// collector claims, so each ends the instance it runs against.

// hashOf is the Warden-Hash a relay sends for body (COLLOUT-18).
func hashOf(body []byte) string {
	sum := blake2b.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// captureTrailer is a declared Warden-Hash trailer of body.
func captureTrailer(body []byte) http.Header {
	return http.Header{"Warden-Hash": {hashOf(body)}}
}

// eachOutput accepts each output over the tunnel, as a relay sends it, at
// its path, with the token as the relay sends it.
var eachOutput = runner.Case{
	Name:    "a collector accepts each output at its path, with the token as the relay sends it",
	Cites:   []string{"COLLOUT-3", "COLLOUT-7", "COLLOUT-13", "COLLOUT-15", "COLLOUT-20", "COLLOUT-21", "COLLOUT-28"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		h := s.auth()
		s.wantEmpty("PUT /v1/artifacts/report.txt", s.do(http.MethodPut, "/v1/artifacts/report.txt", h, []byte("a report\n"), nil), http.StatusOK)
		s.wantEmpty("PUT /v1/artifacts/dir/sub/out.bin", s.do(http.MethodPut, "/v1/artifacts/dir/sub/out.bin", h, []byte{0, 1, 2, 3}, nil), http.StatusOK)
		body := []byte("HTTP/1.1 200 OK\r\n\r\n")
		s.wantEmpty("PUT /v1/captures/000001-GET-response-headers", s.do(http.MethodPut, "/v1/captures/000001-GET-response-headers", h, body, captureTrailer(body)), http.StatusOK)
		s.wantEmpty("PUT /v1/environment", s.do(http.MethodPut, "/v1/environment", h, []byte(`{"type":"conformance/v1"}`), nil), http.StatusOK)
		s.wantEmpty("POST /v1/output", s.do(http.MethodPost, "/v1/output", h, []byte("console\n"), nil), http.StatusOK)
		// Every reply above came while the ledger request was open.
		if _, done, err := s.s.LedgerReply(); done {
			t.Errorf("the ledger request ended before the completion (%v): the collector did not keep it open while it served the others", err)
		}
	},
}

// ledgerAnswered has the ledger request, open from the claim, answered 200
// with an empty body once the relay ends its body at the completion; the
// ledger is the session's, and read back it verifies under the session's key
// with every record whole. COLLOUT-34's other half, that the bytes of a
// ledger request that ends early are kept, has no check: the harness's
// relay session holds the ledger request and has no way to cut it.
var ledgerAnswered = runner.Case{
	Name:    "a collector answers the ledger request once its body has ended, and keeps the ledger",
	Cites:   []string{"COLLOUT-19", "COLLOUT-34"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, readBack),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		ctx := t.Context()
		rep, _, err := s.s.Artifact(ctx, relay.Request{Method: "POST", URL: "http://artifacts/a.txt", Protocol: "HTTP/1.1", Header: []byte("POST /a.txt HTTP/1.1\r\nHost: artifacts\r\n\r\n")}, "a.txt", strings.NewReader("a\n"))
		if err != nil || rep.Status != http.StatusOK {
			t.Fatalf("PUT /v1/artifacts/a.txt: %v %v", rep, err)
		}
		s.complete()
		lrep, _, _ := s.s.LedgerReply()
		s.wantEmpty("PUT /v1/ledger", lrep, http.StatusOK)
		dir, err := s.in.ReadBack(ctx)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		data, ok := file(dir, "ledger")
		if !ok {
			t.Fatalf("the read-back has no ledger; it has %s", listed(files(dir, "")))
		}
		l, err := ledger.Verify(data, s.s.PublicKey())
		if err != nil {
			t.Fatalf("the stored ledger does not verify under the session's key: %v", err)
		}
		if l.Truncated != 0 || len(l.Unclosed) != 0 {
			t.Errorf("the stored ledger has %d bytes after its last whole record and %d channels open, want a whole ledger", l.Truncated, len(l.Unclosed))
		}
		if !slices.ContainsFunc(l.Records, func(r ledger.Record) bool { return r.Type == ledger.Artifact }) {
			t.Errorf("the stored ledger has no artifact record, which the relay wrote before the completion")
		}
	},
}

// badArtifactNames are artifact names that are not safe by COLLOUT-14, as a
// path carries them. None has an empty, "." or ".." segment, which a relay
// may not send (COLLOUT-12).
var badArtifactNames = []string{
	"",                              // the empty name
	"-a",                            // a segment that starts with "-"
	"a-",                            // one that ends with "-"
	"_a",                            // starts with "_"
	"a_",                            // ends with "_"
	".a",                            // starts with "."
	"a.",                            // ends with "."
	"dir/-a",                        // a later segment that starts with "-"
	"a%20b",                         // a space
	"a%25b",                         // a "%"
	"a%7Eb",                         // a "~"
	strings.Repeat("a", 256),        // longer than 255 bytes
	strings.Repeat("ab/", 85) + "a", // 256 bytes in segments
}

// artifactNamesRefused refuses each name that is not a safe artifact name
// with 400.
var artifactNamesRefused = runner.Case{
	Name:    "a collector refuses an artifact whose name is not safe with 400",
	Cites:   []string{"COLLOUT-14"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, n := range badArtifactNames {
			rep := s.do(http.MethodPut, "/v1/artifacts/"+n, s.auth(), []byte("x"), nil)
			if rep.Status != http.StatusBadRequest {
				t.Errorf("PUT /v1/artifacts/%s was answered %d %q, want 400", n, rep.Status, rep.Body)
			}
		}
	},
}

// artifactsStored stores artifacts where the disk layout has them, and
// nothing for a name that is not safe or for a request that did not end.
var artifactsStored = runner.Case{
	Name:    "a disk collector stores an artifact at artifacts/<name>, and nothing for one it refused or one cut short",
	Cites:   []string{"COLLOUT-11", "COLLOUT-13", "COLLOUT-14", "COLLOUT-32"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, readBack),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		h := s.auth()
		want := map[string][]byte{
			"report.txt":      []byte("a report\n"),
			"dir/sub/out.bin": bytes.Repeat([]byte{0, 0xff, 7}, 4096),
			"A.b-c_d/e.f0":    []byte("mixed\n"),
		}
		for _, n := range []string{"report.txt", "dir/sub/out.bin", "A.b-c_d/e.f0"} {
			s.wantEmpty("PUT /v1/artifacts/"+n, s.do(http.MethodPut, "/v1/artifacts/"+n, h, want[n], nil), http.StatusOK)
		}
		for _, n := range badArtifactNames {
			_ = s.do(http.MethodPut, "/v1/artifacts/"+n, h, []byte("refused"), nil)
		}
		// A request whose body never ends: the relay's request is cancelled
		// after its first bytes, so it ends in no reply at all.
		cut(t, s, "/v1/artifacts/cut.txt", h)
		dir := s.readBack()
		for n, b := range want {
			got, ok := file(dir, "artifacts/"+n)
			if !ok || !bytes.Equal(got, b) {
				t.Errorf("artifacts/%s holds %q (present %v), want the %d bytes sent", n, short(got), ok, len(b))
			}
		}
		var extra []string
		for _, f := range files(dir, "artifacts") {
			if _, ok := want[strings.TrimPrefix(f, "artifacts/")]; !ok {
				extra = append(extra, f)
			}
		}
		if len(extra) > 0 {
			t.Errorf("the read-back holds %s, which no request that ended in 200 stored", listed(extra))
		}
	},
}

// cut sends a PUT to path whose body has begun and never ends, and cancels
// it once its first bytes have gone; the request ends with no reply.
func cut(t *runner.T, s *session, path string, h http.Header) {
	ctx, cancel := contextWithCancel(t)
	pr, pw := newPipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.s.Do(ctx, http.MethodPut, path, h, pr, nil)
	}()
	_, _ = pw.Write(bytes.Repeat([]byte("partial "), 1024))
	sleep(t, cutSettle)
	cancel()
	_ = pw.CloseWithError(errCut)
	<-done
	// Let the collector see the stream's reset before the completion.
	sleep(t, cutSettle)
}

// short renders the start of b for a failure.
func short(b []byte) string {
	if len(b) > 64 {
		return string(b[:64]) + "..."
	}
	return string(b)
}

// badCaptureNames are capture names a collector refuses with 400
// (COLLOUT-16): the empty name, one longer than 255 bytes, and names of
// dots only that are not a "." or ".." segment.
var badCaptureNames = []string{"", strings.Repeat("c", 256), "...", "...."}

// capturesStored stores each capture under the name COLLOUT-16 makes, and
// refuses the names it gives 400.
var capturesNamed = runner.Case{
	Name:    "a collector refuses a capture name that is empty, too long or only dots, and accepts any other",
	Cites:   []string{"COLLOUT-15", "COLLOUT-16"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		h := s.auth()
		body := []byte("body")
		for _, n := range []string{"a%20b", "x~y", "a%2Fb", "with/slash", "%C3%A9t%C3%A9", ".hidden", "-"} {
			s.wantEmpty("PUT /v1/captures/"+n, s.do(http.MethodPut, "/v1/captures/"+n, h, body, captureTrailer(body)), http.StatusOK)
		}
		for _, n := range badCaptureNames {
			lastOn(t, func(s *session) {
				rep := s.do(http.MethodPut, "/v1/captures/"+n, s.auth(), body, captureTrailer(body))
				if rep.Status != http.StatusBadRequest {
					t.Errorf("PUT /v1/captures/%s was answered %d %q, want 400", n, rep.Status, rep.Body)
				}
			})
		}
	},
}

// lastOn runs f in a session of its own, with a fresh relay and collector,
// and sends nothing after it there. f sends a capture that the collector
// refuses before its body has ended. Its trailer then arrives on a stream the
// collector has answered, which Go's HTTP/2 server, the harness's and the
// disk collector's, takes for a connection error that ends the tunnel; so no
// request of the case may follow it on the same session.
func lastOn(t *runner.T, f func(*session)) {
	f(claimedBy(t, attach.Params{}))
}

// capturesStored stores captures as payloads/<hash> with captures/<name>
// referring to them, under the names COLLOUT-16 makes, and one payload for
// content sent twice under the same hash. The same content sent once more
// with its hash in upper case is a payload of its own, payloads/<HASH>, as
// sent; on a file system whose names ignore case the two are one file, and
// the case then counts them as one.
var capturesStored = runner.Case{
	Name:    "a disk collector stores a capture at payloads/<hash>, captures/<name> referring to it, once for the same content",
	Cites:   []string{"COLLOUT-15", "COLLOUT-16", "COLLOUT-33"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, readBack),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		h := s.auth()
		one, two := []byte("the same body\n"), []byte("another body\n")
		sent := []struct {
			path, name string
			body       []byte
		}{
			{"000001-GET-request-headers", "000001-GET-request-headers", one},
			{"a%20b/c~d", "a_b_c_d", one},
			{"%C3%A9", "__", two},
		}
		for _, c := range sent {
			s.wantEmpty("PUT /v1/captures/"+c.path, s.do(http.MethodPut, "/v1/captures/"+c.path, h, c.body, captureTrailer(c.body)), http.StatusOK)
		}
		upper := strings.ToUpper(hashOf(one))
		s.wantEmpty("PUT /v1/captures/upper with its hash in upper case", s.do(http.MethodPut, "/v1/captures/upper", h, one, http.Header{"Warden-Hash": {upper}}), http.StatusOK)
		dir := s.readBack()
		for _, hb := range []struct {
			hash string
			body []byte
		}{{hashOf(one), one}, {hashOf(two), two}, {upper, one}} {
			got, ok := file(dir, "payloads/"+hb.hash)
			if !ok || !bytes.Equal(got, hb.body) {
				t.Errorf("payloads/%s holds %q (present %v), want %q", hb.hash, got, ok, hb.body)
			}
		}
		var payloads []string
		for _, f := range files(dir, "payloads") {
			if !strings.HasPrefix(filepath.Base(f), "incoming-") {
				payloads = append(payloads, f)
			}
		}
		want := 3
		if sameFile(filepath.Join(dir, "payloads", hashOf(one)), filepath.Join(dir, "payloads", upper)) {
			want = 2
		}
		if len(payloads) != want {
			t.Errorf("payloads/ holds %s, want %d: one for each content and each hash sent, the hash in upper case counting as another", listed(payloads), want)
		}
		for _, c := range sent {
			referTo(t, dir, c.name, hashOf(c.body), c.body)
		}
		referTo(t, dir, "upper", upper, one)
	},
}

// sameFile says that a and b are one file, as they are on a file system
// whose names ignore case when they differ only in case.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// referTo checks that captures/<name> of dir refers to payloads/<hash>: a
// symbolic link to ../payloads/<hash>, or a copy of body.
func referTo(t *runner.T, dir, name, hash string, body []byte) {
	p := filepath.Join(dir, "captures", name)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Errorf("captures/%s: %v; captures/ holds %s", name, err, listed(files(dir, "captures")))
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		to, err := os.Readlink(p)
		if err != nil || filepath.ToSlash(to) != "../payloads/"+hash {
			t.Errorf("captures/%s is a link to %q (%v), want ../payloads/%s", name, to, err, hash)
		}
		return
	}
	if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, body) {
		t.Errorf("captures/%s is a file holding %q (%v), want a link to ../payloads/%s or a copy of it", name, got, err, hash)
	}
}

// capturesWithoutHash refuses a capture with no Warden-Hash trailer, or one
// that is not 64 hexadecimal digits, and stores none of them.
var capturesWithoutHash = runner.Case{
	Name:    "a collector does not store, or answer 200 to, a capture with no valid Warden-Hash trailer",
	Cites:   []string{"COLLOUT-17"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, c := range noHash(s) {
			if rep := s.do(http.MethodPut, "/v1/captures/"+c.name, c.h, c.body, c.tr); rep.Status == http.StatusOK {
				t.Errorf("a capture with %s was answered 200", c.what)
			}
		}
		if t.Declared().ReadBack {
			dir := s.readBack()
			if fs := files(dir, "captures"); len(fs) > 0 {
				t.Errorf("the read-back holds %s, from captures with no valid trailer", listed(fs))
			}
		}
	},
}

type hashless struct {
	what, name string
	h, tr      http.Header
	body       []byte
}

// noHash are captures with no valid Warden-Hash trailer.
func noHash(s *session) []hashless {
	body := []byte("body")
	good := hashOf(body)
	header := s.auth()
	header.Set("Warden-Hash", good)
	return []hashless{
		{"no trailer", "no-trailer", s.auth(), nil, body},
		{"the hash as a header and not as a trailer", "as-header", header, nil, body},
		{"a trailer of 63 digits", "short", s.auth(), http.Header{"Warden-Hash": {good[:63]}}, body},
		{"a trailer of 64 characters that are not hexadecimal", "not-hex", s.auth(), http.Header{"Warden-Hash": {strings.Repeat("g", 64)}}, body},
		{"an empty trailer", "empty", s.auth(), http.Header{"Warden-Hash": {""}}, body},
	}
}

// environmentStored stores the environment payload at environment.json,
// byte for byte, for a payload of exactly 1 MiB.
var environmentStored = runner.Case{
	Name:    "a collector accepts an environment payload of 1 MiB and stores it byte for byte",
	Cites:   []string{"COLLOUT-20", "COLLOUT-31", "COLLOUT-35"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, readBack),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		payload := environmentOf(1 << 20)
		s.wantEmpty("PUT /v1/environment of 1 MiB", s.do(http.MethodPut, "/v1/environment", s.auth(), payload, nil), http.StatusOK)
		dir := s.readBack()
		if got, ok := file(dir, "environment.json"); !ok || !bytes.Equal(got, payload) {
			t.Errorf("environment.json holds %d bytes (present %v), want the %d bytes sent", len(got), ok, len(payload))
		}
	},
}

// environmentOf is an environment payload, a JSON object, of n bytes.
func environmentOf(n int) []byte {
	head := `{"type":"conformance/v1","pad":"`
	return []byte(head + strings.Repeat("p", n-len(head)-2) + `"}`)
}

// environmentOverLimit sends an environment payload of 1 MiB and one byte,
// which a collector may refuse with 413; if it does, it stores nothing.
var environmentOverLimit = runner.Case{
	Name:    "a collector that refuses an environment payload over 1 MiB answers 413 and stores none of it",
	Cites:   []string{"COLLOUT-30", "COLLOUT-31", "COLLOUT-35"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		payload := environmentOf(1<<20 + 1)
		rep := s.do(http.MethodPut, "/v1/environment", s.auth(), payload, nil)
		if rep.Status != http.StatusOK && rep.Status != http.StatusRequestEntityTooLarge {
			t.Errorf("PUT /v1/environment of 1 MiB and one byte was answered %d %q, want 200 or 413", rep.Status, rep.Body)
		}
		if !t.Declared().ReadBack {
			return
		}
		dir := s.readBack()
		got, ok := file(dir, "environment.json")
		switch {
		case rep.Status == http.StatusOK && (!ok || !bytes.Equal(got, payload)):
			t.Errorf("the payload was answered 200, and environment.json holds %d bytes (present %v), want the %d sent", len(got), ok, len(payload))
		case rep.Status != http.StatusOK && ok:
			t.Errorf("the payload was refused %d, and environment.json holds %d bytes of it", rep.Status, len(got))
		}
	},
}

// methodsRefused answers 405 to each method an output endpoint does not
// take.
var methodsRefused = runner.Case{
	Name:    "a collector answers 405 to a method an output endpoint does not take",
	Cites:   []string{"COLLOUT-20", "COLLOUT-23"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/v1/artifacts/a.txt"},
			{http.MethodDelete, "/v1/artifacts/a.txt"},
			{http.MethodPatch, "/v1/artifacts/a.txt"},
			{http.MethodGet, "/v1/captures/c"},
			{http.MethodDelete, "/v1/captures/c"},
			{http.MethodGet, "/v1/ledger"},
			{http.MethodDelete, "/v1/ledger"},
			{http.MethodGet, "/v1/output"},
			{http.MethodDelete, "/v1/output"},
			{http.MethodPost, "/v1/environment"},
			{http.MethodGet, "/v1/environment"},
			{http.MethodPatch, "/v1/environment"},
		} {
			var body []byte
			if c.method != http.MethodGet {
				body = []byte("x")
			}
			if rep := s.do(c.method, c.path, s.auth(), body, nil); rep.Status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s was answered %d %q, want 405", c.method, c.path, rep.Status, rep.Body)
			}
		}
	},
}

// unauthorizedOutputs answers 401 with the body "unauthorized" and a line
// feed to a request with no token or another one, whatever its method.
var unauthorizedOutputs = runner.Case{
	Name:    "a collector with a token answers 401 to an output request with no token or another",
	Cites:   []string{"COLLOUT-5"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, hasToken),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		tok := s.requireToken()
		body := []byte("body")
		auths := []string{"", "Bearer " + tok + "x", "Bearer wrong"}
		header := func(auth string) http.Header {
			h := http.Header{}
			if auth != "" {
				h.Set("Authorization", auth)
			}
			return h
		}
		check := func(rep *relay.Reply, method, path, auth string) {
			if rep.Status != http.StatusUnauthorized || string(rep.Body) != "unauthorized\n" {
				t.Errorf("%s %s with Authorization %q was answered %d %q, want 401 \"unauthorized\\n\"", method, path, auth, rep.Status, rep.Body)
			}
		}
		for _, auth := range auths {
			for _, c := range []struct{ method, path string }{
				{http.MethodPut, "/v1/artifacts/a.txt"},
				{http.MethodPut, "/v1/ledger"},
				{http.MethodPut, "/v1/environment"},
				{http.MethodPost, "/v1/output"},
				{http.MethodDelete, "/v1/artifacts/a.txt"},
				{http.MethodGet, "/v1/output"},
			} {
				check(s.do(c.method, c.path, header(auth), body, nil), c.method, c.path, auth)
			}
		}
		// A capture refused before its body has ended ends the tunnel
		// (lastOn), so each is sent in a session of its own.
		for _, auth := range auths {
			lastOn(t, func(s *session) {
				check(s.do(http.MethodPut, "/v1/captures/c", header(auth), body, captureTrailer(body)), http.MethodPut, "/v1/captures/c", auth)
			})
		}
	},
}

// noTokenNeeded: GET /healthz and GET /v1/status need no token.
var noTokenNeeded = runner.Case{
	Name:    "a collector requires no token for GET /healthz and GET /v1/status",
	Cites:   []string{"COLLOUT-6"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		for _, p := range []string{"/healthz", "/v1/status"} {
			if rep := s.do(http.MethodGet, p, http.Header{}, nil, nil); rep.Status == http.StatusUnauthorized {
				t.Errorf("GET %s with no token was answered 401 %q", p, rep.Body)
			}
		}
	},
}

// tokenless: a collector with no token refuses nothing for its
// Authorization header.
var tokenless = runner.Case{
	Name:    "a collector with no token refuses no request for its Authorization header",
	Cites:   []string{"COLLOUT-8"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, noToken),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		if tok := s.s.Token(); tok != "" {
			t.Fatalf("the collector declares no token, and its claim carried a collector_token")
		}
		for i, auth := range []string{"", "Bearer anything", "Basic x", "anything"} {
			h := http.Header{}
			if auth != "" {
				h.Set("Authorization", auth)
			}
			s.wantEmpty(fmt.Sprintf("POST /v1/output with Authorization %q", auth), s.do(http.MethodPost, "/v1/output", h, []byte("piece\n"), nil), http.StatusOK)
			n := fmt.Sprintf("a%d.txt", i)
			s.wantEmpty(fmt.Sprintf("PUT /v1/artifacts/%s with Authorization %q", n, auth), s.do(http.MethodPut, "/v1/artifacts/"+n, h, []byte("a"), nil), http.StatusOK)
		}
	},
}

// consoleStored appends the console's pieces to build-output.log, in the
// order their requests were made, each after the reply to the one before.
var consoleStored = runner.Case{
	Name:    "a disk collector appends each piece of the console to build-output.log in order",
	Cites:   []string{"COLLOUT-21", "COLLOUT-36"},
	Role:    "collector",
	Ends:    true,
	Applies: all(claims, readBack),
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{})
		var want []byte
		for i := range 20 {
			piece := []byte(fmt.Sprintf("line %02d of the console\n", i))
			if i == 7 {
				piece = bytes.Repeat([]byte("long "), 20000)
			}
			want = append(want, piece...)
			s.wantEmpty("POST /v1/output", s.do(http.MethodPost, "/v1/output", s.auth(), piece, nil), http.StatusOK)
		}
		dir := s.readBack()
		if got, ok := file(dir, "build-output.log"); !ok || !bytes.Equal(got, want) {
			t.Errorf("build-output.log holds %d bytes (present %v), want the %d bytes sent, in order", len(got), ok, len(want))
		}
	},
}
