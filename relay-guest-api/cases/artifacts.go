package cases

import (
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The cases of the reserved host artifacts (GUEST-17, GUEST-19 to
// GUEST-32). Each claims a relay of its own, so each ends its instance.

// okBody is the body of /heartbeat and /exit (GUEST-19, GUEST-21).
var okBody = []byte("ok\n")

// heartbeatServed: GET /heartbeat on artifacts is answered 200, text/plain,
// "ok" and a line feed, on port 80 and inside TLS on port 443.
var heartbeatServed = runner.Case{
	Name:  "artifacts answers /heartbeat with 200, text/plain and ok",
	Cites: []string{"GUEST-19"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		expect(t, "GET http://artifacts/heartbeat", w.get("artifacts", "/heartbeat"), http.StatusOK, "text/plain", okBody)
		rep := w.send(443, "artifacts", request(http.MethodGet, "/heartbeat", "artifacts", nil))
		expect(t, "GET https://artifacts/heartbeat", rep, http.StatusOK, "text/plain", okBody)
	},
}

// routedByTarget: a request is routed by its target host, a port in it
// ignored: the absolute form's host over Host, Host otherwise, and inside
// TLS the request's host over the name sent at the handshake. The reserved
// hosts' paths are percent-decoded, without the query.
var routedByTarget = runner.Case{
	Name:  "a request is routed by its target host, without a port, and the reserved hosts' paths are percent-decoded",
	Cites: []string{"GUEST-17"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{form: collector.Form{Context: map[string][]byte{"a.txt": []byte("in the context\n")}}})
		for _, c := range []struct{ what, req string }{
			{"GET /%68eartbeat for artifacts", request(http.MethodGet, "/%68eartbeat", "artifacts", nil)},
			{"GET /heartbeat for artifacts:80", request(http.MethodGet, "/heartbeat", "artifacts:80", nil)},
			{"GET /heartbeat?code=3 for artifacts", request(http.MethodGet, "/heartbeat?code=3", "artifacts", nil)},
			{"GET http://artifacts/heartbeat with Host " + originName, request(http.MethodGet, "http://artifacts/heartbeat", originName, nil)},
		} {
			expect(t, c.what, w.send(80, "", c.req), http.StatusOK, "text/plain", okBody)
		}
		rep := w.send(443, originName, request(http.MethodGet, "/heartbeat", "artifacts", nil))
		expect(t, "GET /heartbeat for artifacts inside TLS for "+originName, rep, http.StatusOK, "text/plain", okBody)
		if xs := w.up.Origins.Exchanges(); len(xs) > 0 {
			t.Errorf("a request for artifacts reached the origin: %s %s with Host %s on port %d", xs[0].Method, xs[0].Target, xs[0].Host, xs[0].Port)
		}
		rep = w.send(80, "", request(http.MethodGet, "http://"+originName+"/heartbeat", "artifacts", nil))
		expect(t, "GET http://"+originName+"/heartbeat with Host artifacts", rep, http.StatusOK, "", upstream.Body(originName, "/heartbeat"))
		if xs := w.up.Origins.Exchanges(); len(xs) != 1 || xs[0].Target != "/heartbeat" {
			t.Errorf("the origin received %d exchanges for the absolute target http://%s/heartbeat, want 1 for /heartbeat", len(xs), originName)
		}
		rep = w.post("artifacts", "/a%2Fb?x=1", []byte("routed"))
		expect(t, "POST /a%2Fb?x=1 for artifacts", rep, http.StatusOK, "text/plain", []byte("artifact stored: a/b (6 bytes)\n"))
		if got, ok := w.coll.Artifacts()["a/b"]; !ok || string(got) != "routed" {
			t.Errorf("the collector holds the artifact a/b as %q (%v), want %q", got, ok, "routed")
		}
		refused(t, "GET /%2e%2e/x for cwd", w.get("cwd", "/%2e%2e/x"), http.StatusForbidden, "forbidden\n")
		expect(t, "GET /a%2etxt for cwd", w.get("cwd", "/a%2etxt"), http.StatusOK, "application/octet-stream", []byte("in the context\n"))
	},
}

// heartbeatForwarded: the build's activity, a proxied request first and
// then /heartbeat, has the relay send its collector heartbeats: none
// before any activity, the first within 2 s of it, then at least every 2 s
// while it is less than 4 s old, and none once it is 5 s old. The build's
// last activity is put 0.5 s after a heartbeat arrived, so that a beat
// every 2 s finds it 3.5 s old. Last, once the heartbeats have stopped, a
// proxied request is the only activity, and the same bounds hold for it.
var heartbeatForwarded = runner.Case{
	Name:  "the build's activity, a proxied request or /heartbeat, has the relay send heartbeats while it is less than 4 s old, and none before it or at 5 s",
	Cites: []string{"GUEST-20"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		// slack covers the way from the relay to the collector, and the
		// relay's own scheduling.
		const slack = 500 * time.Millisecond
		beats := func() []collector.Request { return w.received(http.MethodPost, "/v1/heartbeat") }
		sleep(t, 4500*time.Millisecond)
		if hs := beats(); len(hs) > 0 {
			t.Errorf("the relay sent %d heartbeats before the build's first activity", len(hs))
		}
		first := time.Now()
		expect(t, "GET / for "+originName, w.get(originName, "/"), http.StatusOK, "", nil)
		for time.Since(first) < 6*time.Second {
			sleep(t, time.Second)
			expect(t, "GET http://artifacts/heartbeat", w.get("artifacts", "/heartbeat"), http.StatusOK, "", nil)
		}
		hs := beats()
		if len(hs) == 0 {
			t.Fatalf("the relay sent no heartbeat for 6 s of the build's activity")
		}
		next := hs[len(hs)-1].BeganAt.Add(500 * time.Millisecond)
		for !next.After(time.Now()) {
			next = next.Add(2 * time.Second)
		}
		sleep(t, time.Until(next))
		expect(t, "GET http://artifacts/heartbeat", w.get("artifacts", "/heartbeat"), http.StatusOK, "", nil)
		last := time.Now()
		sleep(t, 9*time.Second)
		hs = beats()
		if d := hs[0].BeganAt.Sub(first); d > 2*time.Second+slack || d < 0 {
			t.Errorf("the first heartbeat came %s after the build's first activity, a proxied request, want within 2s", d)
		}
		for i := 1; i < len(hs); i++ {
			if hs[i].BeganAt.After(last.Add(4 * time.Second)) {
				break
			}
			if d := hs[i].BeganAt.Sub(hs[i-1].BeganAt); d > 2*time.Second+slack {
				t.Errorf("heartbeats %d and %d came %s apart while the build was active, want at most 2s", i, i+1, d)
			}
		}
		if !slices.ContainsFunc(hs, func(h collector.Request) bool {
			d := h.BeganAt.Sub(last)
			return d >= 2*time.Second && d <= 4*time.Second+slack
		}) {
			var at []string
			for _, h := range hs {
				at = append(at, h.BeganAt.Sub(last).Round(time.Millisecond).String())
			}
			t.Errorf("no heartbeat came between 2 and 4 s after the build's last activity; they came at %s from it", strings.Join(at, ", "))
		}
		for _, h := range hs {
			if d := h.BeganAt.Sub(last); d > 5*time.Second+slack {
				t.Errorf("a heartbeat came %s after the build's last activity, want none once it is 5s old", d)
			}
		}
		// Then a proxied request alone, once the heartbeats have stopped:
		// in the first phase a /heartbeat follows the proxied request, and
		// its beat would hide a relay that does not count the proxied one.
		if n := len(hs); n > 0 && time.Since(hs[n-1].BeganAt) < 3*time.Second {
			t.Fatalf("the relay still sent heartbeats 9 s after the build's last activity")
		}
		before := len(hs)
		proxied := time.Now()
		expect(t, "GET /alone for "+originName, w.get(originName, "/alone"), http.StatusOK, "", nil)
		sleep(t, 9*time.Second)
		after := beats()[before:]
		if len(after) == 0 || after[0].BeganAt.Sub(proxied) > 2*time.Second+slack {
			t.Errorf("no heartbeat came within 2s of a proxied request that was the build's only activity")
		}
		for _, h := range after {
			if d := h.BeganAt.Sub(proxied); d > 5*time.Second+slack {
				t.Errorf("a heartbeat came %s after a proxied request that was the build's last activity, want none once it is 5s old", d)
			}
		}
	},
}

// sleep waits d, or ends the case when its time runs out.
func sleep(t *runner.T, d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d):
	case <-t.Context().Done():
		t.Fatalf("the case's time ran out")
	}
}

// exitWith is a case that completes the build with POST to target, a path
// of artifacts or of the control plane by port, and checks the reply, the
// order of the ledger and the completion, and the exit code want.
func exitWith(name string, cites []string, port uint16, target string, want int64) runner.Case {
	return runner.Case{
		Name:  name,
		Cites: cites,
		Role:  "relay",
		Ends:  true,
		Run: func(t *runner.T) {
			w := startWeb(t, webOpts{})
			what := "POST " + target
			if port == 80 {
				what = "POST http://artifacts" + target
				expect(t, what, w.post("artifacts", target, nil), http.StatusOK, "text/plain", okBody)
			} else {
				what += " on the control plane"
				expect(t, what, w.control(http.MethodPost, target, nil), http.StatusOK, "", []byte{})
			}
			w.completedInOrder(what, want)
			w.ledger()
		},
	}
}

var (
	exitCode = exitWith("/exit completes the build with its code: the ledger ends and is sent, then the completion, then 200 and ok",
		[]string{"GUEST-21", "GUEST-22"}, 80, "/exit?code=42", 42)
	exitLeast = exitWith("/exit takes the least signed 64-bit exit code",
		[]string{"GUEST-22"}, 80, "/exit?code="+strconv.FormatInt(math.MinInt64, 10), math.MinInt64)
	exitMost = exitWith("/exit takes the greatest signed 64-bit exit code",
		[]string{"GUEST-22"}, 80, "/exit?code="+strconv.FormatInt(math.MaxInt64, 10), math.MaxInt64)
	exitAbsent = exitWith("/exit without code completes the build with exit code 0",
		[]string{"GUEST-22"}, 80, "/exit", 0)
	exitEmpty = exitWith("/exit with an empty code completes the build with exit code 0",
		[]string{"GUEST-22"}, 80, "/exit?code=", 0)
	completeCode = exitWith("POST /v1/complete on the control plane completes the build as /exit does, and is answered 200 with an empty body",
		[]string{"GUEST-39"}, controlPort, "/v1/complete?code=-7", -7)
	completeAbsent = exitWith("POST /v1/complete without code completes the build with exit code 0",
		[]string{"GUEST-39"}, controlPort, "/v1/complete", 0)
)

// caServed: /ca.pem on artifacts and on the control plane is answered 200,
// application/x-pem-file, with the claim reply's ca_cert byte for byte, and
// neither is recorded.
var caServed = runner.Case{
	Name:  "/ca.pem on artifacts and on the control plane serves the claim's ca_cert byte for byte, not recorded",
	Cites: []string{"GUEST-23", "GUEST-37", "GUEST-50"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		expect(t, "GET http://artifacts/ca.pem", w.get("artifacts", "/ca.pem"), http.StatusOK, "application/x-pem-file", w.caPEM)
		rep := w.send(443, "artifacts", request(http.MethodGet, "/ca.pem", "artifacts", nil))
		expect(t, "GET https://artifacts/ca.pem", rep, http.StatusOK, "application/x-pem-file", w.caPEM)
		expect(t, "GET /ca.pem on the control plane", w.control(http.MethodGet, "/ca.pem", nil), http.StatusOK, "application/x-pem-file", w.caPEM)
		l := w.exit()
		notRecorded(t, l, "/ca.pem", []string{"/ca.pem"}, w.caPEM)
	},
}

// crlServed: /ca.crl is answered 200, application/pkix-crl, with a CRL the
// claim's CA signed, that revokes nothing and is not due for an update
// before the CA expires; the same bytes each time, not recorded.
var crlServed = runner.Case{
	Name:  "/ca.crl serves the same empty CRL, signed by the claim's CA and lasting as long as it, not recorded",
	Cites: []string{"GUEST-24", "GUEST-50"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		rep := w.get("artifacts", "/ca.crl")
		expect(t, "GET http://artifacts/ca.crl", rep, http.StatusOK, "application/pkix-crl", nil)
		again := w.send(443, "artifacts", request(http.MethodGet, "/ca.crl", "artifacts", nil))
		expect(t, "GET https://artifacts/ca.crl", again, http.StatusOK, "application/pkix-crl", rep.body)
		checkCRL(t, rep.body, w.ca)
		l := w.exit()
		notRecorded(t, l, "/ca.crl", []string{"/ca.crl"}, rep.body)
	},
}

// inputServed is a case for an input the relay fetches from its collector
// at path and serves at target of artifacts: with the collector holding
// body it is served, 200 with ctype and the bytes, and recorded; with none,
// 404 and nothing recorded.
func inputServed(name string, cites []string, target, path, ctype string, holds func(*collector.Form, []byte)) runner.Case {
	return runner.Case{
		Name:  name,
		Cites: cites,
		Role:  "relay",
		Ends:  true,
		Run: func(t *runner.T) {
			body := append([]byte("#!/bin/sh\r\n\x00 kept as it is \xff\n"), pattern(70000, 7)...)
			var f collector.Form
			holds(&f, body)
			w := startWeb(t, webOpts{form: f})
			for i := range 2 {
				expect(t, fmt.Sprintf("GET http://artifacts%s, %d of 2", target, i+1), w.get("artifacts", target), http.StatusOK, ctype, body)
			}
			if n := len(w.received(http.MethodGet, path)); n < 2 {
				t.Errorf("the collector received %d requests GET %s for the build's 2, want one for each", n, path)
			}
			l := w.exit()
			served(t, l, target, body)
		},
	}
}

// inputMissing is a case for an input the collector does not have: the
// relay answers 404, after it asked, and records nothing for it.
func inputMissing(name string, cites []string, target, path string) runner.Case {
	return runner.Case{
		Name:  name,
		Cites: cites,
		Role:  "relay",
		Ends:  true,
		Run: func(t *runner.T) {
			w := startWeb(t, webOpts{})
			refused(t, "GET http://artifacts"+target, w.get("artifacts", target), http.StatusNotFound, "")
			if n := len(w.received(http.MethodGet, path)); n < 1 {
				t.Errorf("the relay answered GET http://artifacts%s without GET %s of the collector:\n%s", target, path, w.requests())
			}
			l := w.exit()
			notRecorded(t, l, target, []string{target})
		},
	}
}

var (
	scriptServed = inputServed("/build-script serves the collector's build script byte for byte, and records it",
		[]string{"GUEST-25", "GUEST-49"}, "/build-script", "/v1/build-script", "application/octet-stream",
		func(f *collector.Form, b []byte) { f.Script = b })
	scriptMissing = inputMissing("/build-script is 404 when the collector has none, and nothing is recorded",
		[]string{"GUEST-25"}, "/build-script", "/v1/build-script")
	bootstrapServed = inputServed("/bootstrap serves the collector's bootstrap config byte for byte, and records it",
		[]string{"GUEST-26", "GUEST-49"}, "/bootstrap", "/v1/bootstrap", "application/json",
		func(f *collector.Form, b []byte) { f.Bootstrap = b })
	bootstrapMissing = inputMissing("/bootstrap is 404 when the collector has none, and nothing is recorded",
		[]string{"GUEST-26"}, "/bootstrap", "/v1/bootstrap")
)

// artifactStored: a POST to a path that is not fixed stores its body, of
// any Content-Type, as the artifact the path names, streamed to the
// collector, recorded, and answered with its name and length; an empty
// name is unnamed.
var artifactStored = runner.Case{
	Name:  "a POST to any other path of artifacts stores its body as the artifact it names, recorded, and an empty name is unnamed",
	Cites: []string{"GUEST-27", "GUEST-49"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		uploads := []struct {
			target, name string
			body         []byte
			fields       []string
		}{
			{"/dir/out-1.bin", "dir/out-1.bin", pattern(100000, 11), []string{"Content-Type: application/x-anything"}},
			{"/", "unnamed", []byte("no name\n"), nil},
			{"/Report_2.txt", "Report_2.txt", []byte{}, []string{"Content-Type: text/html"}},
		}
		for _, u := range uploads {
			rep := w.post("artifacts", u.target, u.body, u.fields...)
			want := fmt.Sprintf("artifact stored: %s (%d bytes)\n", u.name, len(u.body))
			expect(t, "POST http://artifacts"+u.target, rep, http.StatusOK, "text/plain", []byte(want))
			if got, ok := w.coll.Artifacts()[u.name]; !ok || string(got) != string(u.body) {
				t.Errorf("the collector holds the artifact %s as %d bytes (%v), want the %d the build sent", u.name, len(got), ok, len(u.body))
			}
			if n := len(w.received(http.MethodPut, "/v1/artifacts/"+u.name)); n != 1 {
				t.Errorf("the collector received %d PUT /v1/artifacts/%s, want 1:\n%s", n, u.name, w.requests())
			}
		}
		l := w.exit()
		for _, u := range uploads {
			if !artifactRecorded(l, u.name, u.body) {
				t.Errorf("the ledger has no artifact record named %s with the %d bytes the build sent", u.name, len(u.body))
			}
		}
	},
}

// artifactRecorded says whether l has an artifact record named name whose
// payload is body, out of the build.
func artifactRecorded(l *ledger.Ledger, name string, body []byte) bool {
	for _, r := range l.Records {
		if n, _ := r.Text("name"); r.Type == ledger.Artifact && n == name && r.PayloadSize <= 0 && holds(l, r, body) {
			return true
		}
	}
	return false
}

// artifacts are the artifact records of l, by name.
func artifactNames(l *ledger.Ledger) []string {
	var out []string
	for _, r := range l.Records {
		if r.Type == ledger.Artifact {
			n, _ := r.Text("name")
			out = append(out, n)
		}
	}
	return out
}

// badNames are artifact paths, as sent, whose names break GUEST-28.
var badNames = []string{
	"/.hidden", "/-a", "/_a", "/a.", "/a-", "/a_", "/dir/.x", "/dir/x_",
	"/a//b", "/a/", "//a", "/a/../b", "/%2e%2e/x", "/a%20b", "/caf%C3%A9",
	"/a:b", "/a%00b", "/" + strings.Repeat("a", 256),
}

// artifactNameRefused: a name that breaks GUEST-28 is answered 400 with
// "invalid artifact name", and nothing is streamed to the collector or
// recorded; a name of 255 bytes that keeps it is stored.
var artifactNameRefused = runner.Case{
	Name:  "an artifact whose name breaks the rule is answered 400, and nothing is stored or recorded",
	Cites: []string{"GUEST-28"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		body := []byte("refused\n")
		for _, p := range badNames {
			refused(t, "POST http://artifacts"+short([]byte(p)), w.post("artifacts", p, body), http.StatusBadRequest, "invalid artifact name\n")
		}
		if rs := w.received(http.MethodPut, "/v1/artifacts/"); len(rs) > 0 {
			t.Errorf("the relay sent the collector %s for a refused name", rs[0].Path)
		}
		long := strings.Repeat("b", 127) + "/" + strings.Repeat("c", 127)
		rep := w.post("artifacts", "/"+long, body)
		expect(t, "POST of an artifact named with 255 bytes", rep, http.StatusOK, "text/plain", []byte(fmt.Sprintf("artifact stored: %s (%d bytes)\n", long, len(body))))
		l := w.exit()
		if names := artifactNames(l); len(names) != 1 || names[0] != long {
			t.Errorf("the ledger has artifact records named %q, want the one of 255 bytes alone", names)
		}
	},
}

// artifactNotStored: an artifact the collector does not store is answered
// 500, and is not recorded as stored. The 413 of an artifact over 2 GiB is
// not sent: that is 2 GiB through the build link for every relay a suite
// runs, and the harness's collector stores no body that large.
var artifactNotStored = runner.Case{
	Name:  "an artifact the collector does not store is answered 500, and not recorded as stored",
	Cites: []string{"GUEST-29"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		fault := func(r *http.Request) int {
			if strings.HasPrefix(r.URL.Path, "/v1/artifacts/") {
				return http.StatusInsufficientStorage
			}
			return 0
		}
		w := startWeb(t, webOpts{fault: fault})
		refused(t, "POST http://artifacts/lost.bin, which the collector does not store", w.post("artifacts", "/lost.bin", pattern(5000, 3)), http.StatusInternalServerError, "")
		if len(w.received(http.MethodPut, "/v1/artifacts/lost.bin")) == 0 {
			t.Errorf("the relay answered the upload without PUT /v1/artifacts/lost.bin to the collector:\n%s", w.requests())
		}
		l := w.exit()
		if names := artifactNames(l); len(names) > 0 {
			t.Errorf("the ledger records the artifacts %q, which the collector did not store", names)
		}
	},
}

// fixedNotUploads: a POST to each fixed path but /exit, with a body, is
// that path's request and not an upload: nothing is streamed to the
// collector as an artifact, nothing is recorded as one, and the reply is
// not an upload's. Whether the relay serves the path for POST, GUEST-31
// leaves to it (the Go relay does, D9).
var fixedNotUploads = runner.Case{
	Name:  "a POST to a fixed path of artifacts is that path's request, never an upload",
	Cites: []string{"GUEST-30", "GUEST-31"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{form: collector.Form{Script: []byte("script\n"), Bootstrap: []byte(`{"version":1}`)}})
		for _, p := range []string{"/heartbeat", "/ca.pem", "/ca.crl", "/build-script", "/bootstrap"} {
			rep := w.post("artifacts", p, []byte("not an artifact\n"))
			if strings.HasPrefix(string(rep.body), "artifact stored") {
				t.Errorf("POST http://artifacts%s was answered as an upload: %s", p, rep)
			}
		}
		if rs := w.received(http.MethodPut, "/v1/artifacts/"); len(rs) > 0 {
			t.Errorf("the relay sent the collector %s for a POST to a fixed path", rs[0].Path)
		}
		l := w.exit()
		if names := artifactNames(l); len(names) > 0 {
			t.Errorf("the ledger records the artifacts %q for POSTs to fixed paths", names)
		}
	},
}

// notFound: every other request for artifacts, one that is not a POST to a
// path that is not fixed, is answered 404; http://artifacts/health is not a
// path of it (D12).
var notFound = runner.Case{
	Name:  "any other request for artifacts is answered 404, /health among them",
	Cites: []string{"GUEST-32"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		w := startWeb(t, webOpts{})
		for _, c := range []struct{ method, target string }{
			{http.MethodGet, "/nothing"}, {http.MethodGet, "/dir/out.bin"}, {http.MethodGet, "/health"},
			{http.MethodGet, "/"}, {http.MethodPut, "/out.bin"}, {http.MethodDelete, "/out.bin"},
		} {
			rep := w.send(80, "", request(c.method, c.target, "artifacts", nil))
			refused(t, c.method+" http://artifacts"+c.target, rep, http.StatusNotFound, "")
		}
		if rs := w.received(http.MethodPut, "/v1/artifacts/"); len(rs) > 0 {
			t.Errorf("the relay sent the collector %s for a request it answers 404", rs[0].Path)
		}
	},
}
