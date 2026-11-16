package cases

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The cases of the reserved host cwd (GUEST-33, GUEST-34) and of the
// control plane (GUEST-35 to GUEST-40). Each claims a relay of its own.

// buildContext is the context the cwd cases' collector serves: files at the
// root and below it, one in a directory whose name starts with a dot.
func buildContext() map[string][]byte {
	return map[string][]byte{
		"a.txt":            []byte("a file at the root\n"),
		"dir/b.bin":        pattern(40000, 21),
		"dir/sub/c":        []byte{},
		".warden/stage-1":  []byte("staged\n"),
		"-dash/_under.dat": []byte("edges\n"),
	}
}

// cwdServed: a GET for cwd of a file is answered with the file's bytes and
// recorded; of the root, a directory or a path with a trailing "/", with
// the collector's listing, unchanged and not recorded; of a path the
// context does not have, 404. Each goes to the collector as the path asks,
// a trailing "/" kept.
var cwdServed = runner.Case{
	Name:  "cwd serves a context file byte for byte, recorded, and a listing unchanged, not recorded; a missing path is 404",
	Cites: []string{"GUEST-34", "GUEST-49"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		ctx := buildContext()
		w := startWeb(t, webOpts{form: collector.Form{Context: ctx}})
		files := []string{"a.txt", "dir/b.bin", "dir/sub/c", ".warden/stage-1", "-dash/_under.dat"}
		for _, f := range files {
			expect(t, "GET http://cwd/"+f, w.get("cwd", "/"+f), http.StatusOK, "application/octet-stream", ctx[f])
			if n := len(w.received(http.MethodGet, "/v1/context/"+f)); n != 1 {
				t.Errorf("the collector received %d GET /v1/context/%s for the build's one, want 1", n, f)
			}
		}
		var listings [][]byte
		for _, l := range []struct{ target, path string }{
			{"/", "/v1/context/"}, {"/dir", "/v1/context/dir"}, {"/dir/", "/v1/context/dir/"}, {"/dir/sub/", "/v1/context/dir/sub/"},
		} {
			rep := w.get("cwd", l.target)
			gave, ok := w.tee.replied(l.path)
			if !ok {
				t.Errorf("GET http://cwd%s: the collector received no GET %s:\n%s", l.target, l.path, w.requests())
				continue
			}
			expect(t, "GET http://cwd"+l.target, rep, http.StatusOK, "text/plain", gave)
			listings = append(listings, gave)
		}
		rep := w.get("cwd", "/missing.txt")
		refused(t, "GET http://cwd/missing.txt", rep, http.StatusNotFound, "")
		if len(w.received(http.MethodGet, "/v1/context/missing.txt")) == 0 {
			t.Errorf("the relay answered GET http://cwd/missing.txt without asking the collector:\n%s", w.requests())
		}
		l := w.exit()
		for _, f := range files {
			served(t, l, "/"+f, ctx[f])
		}
		notRecorded(t, l, "a listing of cwd", []string{"/", "/dir", "/dir/", "/dir/sub/", "/missing.txt"}, listings...)
	},
}

// badContextPaths are cwd paths, as sent, that break GUEST-33's rule.
var badContextPaths = []string{
	"/%2e%2e/x", "/a/../b", "/./a", "/dir/..", "/a//b", "//a", "/a%20b", "/caf%C3%A9",
	"/a%00b", "/" + strings.Repeat("d", 256),
}

// cwdRefused: a cwd path that breaks the rule is answered 403 with
// "forbidden", and the relay asks the collector nothing for it; a path
// whose segments start with ".", "-" or "_" keeps it.
var cwdRefused = runner.Case{
	Name:  "a cwd path that breaks the rule is answered 403, and the collector is not asked",
	Cites: []string{"GUEST-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{form: collector.Form{Context: buildContext()}})
		for _, p := range badContextPaths {
			refused(t, "GET http://cwd"+short([]byte(p)), w.get("cwd", p), http.StatusForbidden, "forbidden\n")
		}
		if rs := w.received(http.MethodGet, "/v1/context/"); len(rs) > 0 {
			t.Errorf("the relay sent the collector GET %s for a path it refuses", rs[0].Path)
		}
		expect(t, "GET http://cwd/-dash/_under.dat", w.get("cwd", "/-dash/_under.dat"), http.StatusOK, "", []byte("edges\n"))
		long := strings.Repeat("e", 255)
		refused(t, "GET of a missing cwd path of 255 bytes", w.get("cwd", "/"+long), http.StatusNotFound, "")
	},
}

// cwdRefusedEnds: a cwd path with a segment that ends in ".", "-" or "_"
// breaks the rule too: GUEST-33 relaxes GUEST-28 for a context path at a
// segment's start only. It is answered 403 with "forbidden", and the relay
// asks the collector nothing for it.
var cwdRefusedEnds = runner.Case{
	Name:  "a cwd path with a segment that ends in a dot, a dash or an underscore is answered 403, and the collector is not asked",
	Cites: []string{"GUEST-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{form: collector.Form{Context: buildContext()}})
		for _, p := range []string{"/a.", "/a-", "/a_", "/dir/x_/", "/.warden./x", "/-dash-/_under.dat"} {
			refused(t, "GET http://cwd"+p, w.get("cwd", p), http.StatusForbidden, "forbidden\n")
		}
		if rs := w.received(http.MethodGet, "/v1/context/"); len(rs) > 0 {
			t.Errorf("the relay sent the collector GET %s for a path it refuses", rs[0].Path)
		}
	},
}

// health: GET /health on the control plane is answered 200 with "ok",
// whatever the request's Host.
var health = runner.Case{
	Name:  "the control plane answers GET /health with 200 and ok, whatever the Host",
	Cites: []string{"GUEST-35", "GUEST-36"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		for _, host := range []string{"control", "artifacts", "cwd", originName, w.relayAddr().String() + ":8300"} {
			rep := w.send(controlPort, "", request(http.MethodGet, "/health", host, nil))
			expect(t, "GET /health with Host "+host+" on port 8300", rep, http.StatusOK, "", []byte("ok"))
		}
	},
}

// outputForwarded: POST /v1/output forwards each body as one POST
// /v1/output to the collector, whatever its Content-Type, and is answered
// 200 with an empty body once the collector has; the console is not
// recorded.
var outputForwarded = runner.Case{
	Name:  "POST /v1/output forwards the body to the collector as one /v1/output and is answered 200, not recorded",
	Cites: []string{"GUEST-38"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		pieces := [][]byte{[]byte("first line\n"), pattern(300000, 31), []byte("\x1b[31mlast\x1b[0m\n")}
		for i, p := range pieces {
			fields := []string{"Content-Type: application/octet-stream"}
			if i == 0 {
				fields = []string{"Content-Type: text/plain; charset=utf-8"}
			}
			rep := w.send(controlPort, "", request(http.MethodPost, "/v1/output", "control", p, fields...))
			expect(t, fmt.Sprintf("POST /v1/output, piece %d", i+1), rep, http.StatusOK, "", []byte{})
			if n := len(w.received(http.MethodPost, "/v1/output")); n != i+1 {
				t.Errorf("after piece %d the collector had received %d POST /v1/output, want %d", i+1, n, i+1)
			}
		}
		if got, want := w.coll.Output(), bytes.Join(pieces, nil); !bytes.Equal(got, want) {
			t.Errorf("the collector's console holds %d bytes, want the %d of the build's three pieces in order", len(got), len(want))
		}
		l := w.exit()
		notRecorded(t, l, "the console", []string{"/v1/output"}, pieces...)
	},
}

// outputRefused: output the collector does not take is answered 500 with a
// body that says why.
var outputRefused = runner.Case{
	Name:  "POST /v1/output that the collector does not take is answered 500 with why",
	Cites: []string{"GUEST-38"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		fault := func(r *http.Request) int {
			if r.URL.Path == "/v1/output" {
				return http.StatusServiceUnavailable
			}
			return 0
		}
		w := startWeb(t, webOpts{fault: fault})
		rep := w.control(http.MethodPost, "/v1/output", []byte("lost\n"))
		refused(t, "POST /v1/output, which the collector answers 503", rep, http.StatusInternalServerError, "")
		if len(bytes.TrimSpace(rep.body)) == 0 {
			t.Errorf("the 500 for output the collector did not take has an empty body, want one that says why")
		}
	},
}

// outputLimit: the relay forwards at most 256 MiB of output for a build,
// cuts short the request that crosses it, and answers the next 413 with
// "output limit exceeded", forwarding nothing of it. The collector's side
// of /v1/output is the case's: it counts what it receives and answers 200,
// so that no collector stores 256 MiB.
var outputLimit = runner.Case{
	Name:  "the relay forwards at most 256 MiB of output, cuts short the request that crosses it, and answers the next 413",
	Cites: []string{"GUEST-38"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		const limit = 256 << 20
		var got atomic.Int64
		count := func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			got.Add(n)
			w.WriteHeader(http.StatusOK)
		}
		w := startWeb(t, webOpts{override: map[string]http.HandlerFunc{"/v1/output": count}})
		// Four pieces of 60 MiB, then one that crosses the limit by 64 KiB:
		// little enough that a server which stops reading at the limit
		// still reads the rest before it closes, so that its reply is not
		// lost to a reset.
		sizes := []int{60 << 20, 60 << 20, 60 << 20, 60 << 20, 16<<20 + 64<<10}
		chunk := pattern(1<<20, 41)
		for i, size := range sizes {
			what := fmt.Sprintf("POST /v1/output, piece %d of %d bytes", i+1, size)
			c := w.conn(controlPort, "")
			_ = c.SetDeadline(time.Now().Add(time.Minute))
			if _, err := fmt.Fprintf(c, "POST /v1/output HTTP/1.1\r\nHost: control\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", size); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			for left := size; left > 0; left -= len(chunk) {
				if _, err := c.Write(chunk[:min(left, len(chunk))]); err != nil {
					break
				}
			}
			rep, err := w.exchange(c, bufio.NewReader(c), "")
			_ = c.Close()
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			switch {
			case i < len(sizes)-1:
				expect(t, what, rep, http.StatusOK, "", nil)
			case rep.status != http.StatusOK && rep.status != http.StatusRequestEntityTooLarge:
				// GUEST-38 recommends 413 and allows 200 (Known
				// divergences, D11).
				t.Errorf("%s, which crosses 256 MiB, was answered %s, want 413 or 200", what, rep)
			}
		}
		rep := w.control(http.MethodPost, "/v1/output", []byte("after the limit\n"))
		refused(t, "POST /v1/output after 256 MiB", rep, http.StatusRequestEntityTooLarge, "output limit exceeded\n")
		if n := got.Load(); n != limit {
			t.Errorf("the collector received %d bytes of output, want exactly 256 MiB (%d)", n, limit)
		}
		if n := w.tee.count("/v1/output"); n > 5 {
			t.Errorf("the collector received %d POST /v1/output, want at most the 5 under the limit", n)
		}
	},
}

// controlRefused: /v1/output and /v1/complete with a method but POST are
// 405 "POST only" and do nothing; any other clean path is 404.
var controlRefused = runner.Case{
	Name:  "the control plane answers 405 to /v1/output and /v1/complete but by POST, doing nothing, and 404 to any other path",
	Cites: []string{"GUEST-40"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		for _, c := range []struct {
			method, target string
			body           []byte
		}{
			{http.MethodGet, "/v1/output", nil}, {http.MethodPut, "/v1/output", []byte("not sent\n")},
			{http.MethodGet, "/v1/complete?code=3", nil}, {http.MethodPut, "/v1/complete?code=3", nil},
		} {
			refused(t, c.method+" "+c.target+" on the control plane", w.control(c.method, c.target, c.body), http.StatusMethodNotAllowed, "POST only\n")
		}
		for _, c := range []struct{ method, target string }{
			{http.MethodGet, "/"}, {http.MethodGet, "/nothing"}, {http.MethodGet, "/v1/nothing"},
			{http.MethodPost, "/v1/heartbeat"}, {http.MethodPost, "/exit"}, {http.MethodGet, "/heartbeat"},
		} {
			rep := w.control(c.method, c.target, nil)
			if rep.status != http.StatusNotFound {
				t.Errorf("%s %s on the control plane was answered %s, want 404", c.method, c.target, rep)
			}
		}
		sleep(t, quiet)
		if _, ok := w.coll.Completion(); ok {
			t.Errorf("the collector received a completion, though the build sent none by POST")
		}
		for _, p := range []string{"/v1/output", "/v1/complete"} {
			if rs := w.received(http.MethodPost, p); len(rs) > 0 {
				t.Errorf("the relay sent the collector POST %s for a request it answered 405 or 404", p)
			}
		}
	},
}
