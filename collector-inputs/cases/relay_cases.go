package cases

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	collectorinputs "github.com/buildwarden/buildwarden-specs/collector-inputs"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The cases that test a relay as the client of the inputs and the signals.
// Each claims a relay of its own, so each ends the instance it runs
// against.

// bootstrapConfig is the bootstrap config of a session that has one.
var bootstrapConfig = []byte(`{"version":1,"trust":{"mode":"append"}}`)

// fullForm is a collector form with a token and every input.
func fullForm() collector.Form {
	ctx := map[string][]byte{}
	for p, b := range contextFiles {
		ctx[p] = []byte(b)
	}
	return collector.Form{Token: collectorToken, Script: script, Context: ctx, Bootstrap: bootstrapConfig}
}

// isInput says that a path is one of the inputs'.
func isInput(p string) bool {
	return p == "/v1/build-script" || p == "/v1/bootstrap" || strings.HasPrefix(p, "/v1/context/")
}

// inputsOnRequest: the relay fetches an input only when the build asks for
// one, once for each time it asks, at the base URL's path, with the token
// on every request of the session.
var inputsOnRequest = runner.Case{
	Name:  "a relay fetches an input only when the build asks, at the claim's base URL, with the token",
	Cites: []string{"COLLIN-4", "COLLIN-9", "COLLIN-12", "COLLIN-28"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{form: fullForm()})
		sleep(t, time.Second)
		for _, r := range b.c.Requests() {
			if isInput(r.Path) {
				t.Errorf("the relay sent %s %s before the build asked for an input", r.Method, r.Path)
			}
		}
		if rep := b.do(http.MethodGet, "http://artifacts/build-script", nil); rep.status != http.StatusOK || !bytes.Equal(rep.body, script) {
			t.Errorf("the build's GET http://artifacts/build-script was answered %d %q, want 200 and the script", rep.status, short(rep.body))
		}
		if rep := b.do(http.MethodGet, "http://artifacts/bootstrap", nil); rep.status != http.StatusOK || !bytes.Equal(rep.body, bootstrapConfig) {
			t.Errorf("the build's GET http://artifacts/bootstrap was answered %d %q, want 200 and the config", rep.status, short(rep.body))
		}
		for _, p := range []string{"a.txt", "dir/b.txt", "dir/sub/c.txt"} {
			if rep := b.do(http.MethodGet, "http://cwd/"+p, nil); rep.status != http.StatusOK || string(rep.body) != contextFiles[p] {
				t.Errorf("the build's GET http://cwd/%s was answered %d %q, want 200 and the file", p, rep.status, short(rep.body))
			}
		}
		b.do(http.MethodGet, "http://artifacts/heartbeat", nil)
		b.exit(0)
		for path, n := range map[string]int{"/v1/build-script": 1, "/v1/bootstrap": 1, "/v1/context/a.txt": 1, "/v1/context/dir/b.txt": 1, "/v1/context/dir/sub/c.txt": 1} {
			if got := b.count(http.MethodGet, path); got != n {
				t.Errorf("the relay sent GET %s %d times, for the build's %d", path, got, n)
			}
		}
		for _, r := range b.c.Requests() {
			if got := r.Header.Get("Authorization"); got != "Bearer "+collectorToken {
				t.Errorf("%s %s carried Authorization %q, want %q", r.Method, r.Path, got, "Bearer "+collectorToken)
			}
			if !strings.HasPrefix(r.Path, "/v1/") {
				t.Errorf("%s %s is not under the base URL's /v1/", r.Method, r.Path)
			}
			if bad := uncleanPath(r.Path); bad != "" {
				t.Errorf("%s %s: %s", r.Method, r.Path, bad)
			}
		}
	},
}

// escaped is a path whose every segment is percent-encoded as
// url.PathEscape leaves it.
var escaped = regexp.MustCompile(`^(/([A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*$`)

// uncleanPath says what is wrong with a path a relay sent (COLLIN-12), or
// "" for nothing.
func uncleanPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	for _, bad := range []string{"//", "/./", "/../"} {
		if strings.Contains(p, bad) {
			return "the path holds " + bad
		}
	}
	if strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		return "the path ends in a dot segment"
	}
	if !escaped.MatchString(p) {
		return "a segment of the path is not percent-encoded"
	}
	return ""
}

// noTokenSent: a session whose claim has no collector_token sends no
// Authorization header on an input or a signal.
var noTokenSent = runner.Case{
	Name:  "a relay whose claim has no collector token sends no Authorization header on the inputs and signals",
	Cites: []string{"COLLIN-9"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		f := fullForm()
		f.Token = ""
		b := claimRelay(t, buildOpts{form: f})
		b.do(http.MethodGet, "http://artifacts/build-script", nil)
		b.do(http.MethodGet, "http://cwd/", nil)
		b.do(http.MethodGet, "http://artifacts/heartbeat", nil)
		sleep(t, 2500*time.Millisecond)
		b.exit(0)
		for _, r := range b.c.Requests() {
			if v, ok := r.Header["Authorization"]; ok {
				t.Errorf("%s %s carried Authorization %q, with no collector_token in the claim", r.Method, r.Path, v)
			}
		}
	},
}

// notAnInput: a relay reads only a 200 as the input. The collector answers
// each input with another status, and the build is not served it.
var notAnInput = runner.Case{
	Name:  "a relay reads only a 200 as an input",
	Cites: []string{"COLLIN-28"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		statuses := map[string]int{
			"/v1/build-script":      http.StatusCreated,
			"/v1/bootstrap":         http.StatusInternalServerError,
			"/v1/context/a.txt":     http.StatusNonAuthoritativeInfo,
			"/v1/context/dir/":      http.StatusPartialContent,
			"/v1/context/dir/b.txt": http.StatusServiceUnavailable,
		}
		o := buildOpts{form: fullForm(), fault: func(r *http.Request) int { return statuses[r.URL.Path] }}
		b := claimRelay(t, o)
		for _, u := range []string{"http://artifacts/build-script", "http://artifacts/bootstrap", "http://cwd/a.txt", "http://cwd/dir/", "http://cwd/dir/b.txt"} {
			if rep := b.do(http.MethodGet, u, nil); rep.status == http.StatusOK {
				t.Errorf("the collector did not give the input, and the build's GET %s was answered 200 %q", u, short(rep.body))
			}
		}
		if rep := b.do(http.MethodGet, "http://cwd/dir/sub/c.txt", nil); rep.status != http.StatusOK || string(rep.body) != contextFiles["dir/sub/c.txt"] {
			t.Errorf("the build's GET http://cwd/dir/sub/c.txt, which the collector gave, was answered %d %q", rep.status, short(rep.body))
		}
		b.exit(0)
	},
}

// contextPaths: a relay sends a context path as the build gave it, with its
// trailing "/", and reads a 200 with Warden-Context: list as a listing and
// any other 200 as a file.
var contextPaths = runner.Case{
	Name:  "a relay sends a context path as the build gave it, and reads a listing only by Warden-Context: list",
	Cites: []string{"COLLIN-29"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := buildOpts{form: fullForm(), override: map[string]http.HandlerFunc{
			// A 200 that is not marked a listing, whatever it looks like.
			"/v1/context/odd/": func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Warden-Context", "listing")
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("odd/one\n"))
			},
			"/v1/context/plain.txt": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("no kind\n"))
			},
		}}
		b := claimRelay(t, o)
		cases := []struct {
			build, sent string
			list        bool
			body        string
		}{
			{"http://cwd/", "/v1/context/", true, ".warden/d.txt\na.txt\ndir/b.txt\ndir/sub/c.txt\n"},
			{"http://cwd/dir", "/v1/context/dir", true, "dir/b.txt\ndir/sub/c.txt\n"},
			{"http://cwd/dir/", "/v1/context/dir/", true, "dir/b.txt\ndir/sub/c.txt\n"},
			{"http://cwd/dir/sub/", "/v1/context/dir/sub/", true, "dir/sub/c.txt\n"},
			{"http://cwd/dir/b.txt", "/v1/context/dir/b.txt", false, contextFiles["dir/b.txt"]},
			{"http://cwd/.warden/d.txt", "/v1/context/.warden/d.txt", false, contextFiles[".warden/d.txt"]},
			{"http://cwd/odd/", "/v1/context/odd/", false, "odd/one\n"},
			{"http://cwd/plain.txt", "/v1/context/plain.txt", false, "no kind\n"},
		}
		for _, c := range cases {
			rep := b.do(http.MethodGet, c.build, nil)
			if !overridden(o, c.sent) && b.count(http.MethodGet, c.sent) == 0 {
				t.Errorf("the build's GET %s did not reach the collector as GET %s; it received:\n%s", c.build, c.sent, b.requests())
			}
			mt, _, _ := mime.ParseMediaType(rep.header.Get("Content-Type"))
			want := "application/octet-stream"
			if c.list {
				want = "text/plain"
			}
			if rep.status != http.StatusOK || mt != want || string(rep.body) != c.body {
				t.Errorf("the build's GET %s was answered %d, %q, %q; want 200, %s, %q", c.build, rep.status, mt, short(rep.body), want, c.body)
			}
		}
		b.exit(0)
		for _, c := range cases {
			if !overridden(o, c.sent) && b.count(http.MethodGet, c.sent) != 1 {
				t.Errorf("the relay sent GET %s %d times, want once", c.sent, b.count(http.MethodGet, c.sent))
			}
		}
	},
}

// overridden says that the case answers path in the collector's place, so
// that the collector records no request to it.
func overridden(o buildOpts, path string) bool {
	_, ok := o.override[path]
	return ok
}

// heartbeatForwarded: the relay sends no heartbeat before the build's first
// activity, then one within 2 s of it and at least every 2 s while it is
// less than 4 s old, and none once it is 5 s old.
var heartbeatForwarded = runner.Case{
	Name:  "a relay sends heartbeats on a beat of 2 s while the build's last activity is recent, and none otherwise",
	Cites: []string{"COLLIN-30"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{form: fullForm()})
		// slack covers the way from the relay to the collector, and the
		// relay's own scheduling.
		const slack = 500 * time.Millisecond
		beats := func() []collector.Request {
			var out []collector.Request
			for _, r := range b.c.Requests() {
				if r.Path == "/v1/heartbeat" {
					out = append(out, r)
				}
			}
			return out
		}
		sleep(t, 3*time.Second)
		if n := len(beats()); n > 0 {
			t.Errorf("the relay sent %d heartbeats before the build's first activity", n)
		}
		first := time.Now()
		var last time.Time
		for time.Since(first) < 6*time.Second {
			if rep := b.do(http.MethodGet, "http://artifacts/heartbeat", nil); rep.status != http.StatusOK {
				t.Errorf("the build's GET http://artifacts/heartbeat was answered %d", rep.status)
			}
			last = time.Now()
			sleep(t, time.Second)
		}
		sleep(t, 7*time.Second)
		hs := beats()
		if len(hs) == 0 {
			t.Fatalf("the relay sent no heartbeat for 6 s of the build's activity")
		}
		if d := hs[0].BeganAt.Sub(first); d > 2*time.Second+slack {
			t.Errorf("the first heartbeat came %s after the build's first activity, want within 2s", d)
		}
		for i := 1; i < len(hs); i++ {
			if hs[i].BeganAt.After(last.Add(4 * time.Second)) {
				break
			}
			if d := hs[i].BeganAt.Sub(hs[i-1].BeganAt); d > 2*time.Second+slack {
				t.Errorf("heartbeats %d and %d came %s apart while the build was active, want at most 2s", i, i+1, d)
			}
		}
		for _, h := range hs {
			if d := h.BeganAt.Sub(last); d > 5*time.Second+slack {
				t.Errorf("a heartbeat came %s after the build's last activity, want none once it is 5s old", d)
			}
		}
		b.exit(0)
	},
}

// readyOnce: the relay sends POST /v1/ready once, with no body, before it
// answers the claim.
var readyOnce = runner.Case{
	Name:  "a relay sends ready once, with no body, before it answers the claim",
	Cites: []string{"COLLIN-31"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{form: fullForm()})
		ready, ok := b.first(http.MethodPost, "/v1/ready")
		if !ok {
			t.Fatalf("the relay had sent no POST /v1/ready when it answered the claim; the collector received:\n%s", b.requests())
		}
		if !ready.BeganAt.Before(b.claimedAt) {
			t.Errorf("POST /v1/ready arrived at %s, after the claim's reply at %s", ready.BeganAt, b.claimedAt)
		}
		if len(ready.Body) != 0 {
			t.Errorf("POST /v1/ready had the body %q, want none", ready.Body)
		}
		b.do(http.MethodGet, "http://artifacts/build-script", nil)
		b.exit(0)
		if n := b.count(http.MethodPost, "/v1/ready"); n != 1 {
			t.Errorf("the relay sent POST /v1/ready %d times, want once", n)
		}
	},
}

// completionSent: the build's end is sent as POST /v1/complete with a JSON
// body of the three members and the build's exit code, after the ledger
// request has been answered.
var completionSent = runner.Case{
	Name:  "a relay sends the completion as JSON with the build's exit code, after the ledger request is answered",
	Cites: []string{"COLLIN-32", "COLLIN-35"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{form: fullForm()})
		b.do(http.MethodPost, "http://artifacts/out.txt", []byte("out\n"))
		b.exit(7)
		comp, ok := b.first(http.MethodPost, "/v1/complete")
		if !ok {
			t.Fatalf("the collector received no completion:\n%s", b.requests())
		}
		if mt, _, _ := mime.ParseMediaType(comp.Header.Get("Content-Type")); mt != "application/json" {
			t.Errorf("POST /v1/complete had Content-Type %q, want application/json", comp.Header.Get("Content-Type"))
		}
		if err := collectorinputs.Spec.Validate(completeSchema, comp.Body); err != nil {
			t.Errorf("POST /v1/complete: %v; the body: %q", err, comp.Body)
		}
		var body struct {
			ExitCode *json.Number `json:"exit_code"`
			Message  *string      `json:"message"`
			Error    *string      `json:"error"`
		}
		if err := json.Unmarshal(comp.Body, &body); err != nil || body.ExitCode == nil || body.Message == nil || body.Error == nil {
			t.Errorf("POST /v1/complete's body %q does not have the three members (%v)", comp.Body, err)
		} else if body.ExitCode.String() != "7" {
			t.Errorf("POST /v1/complete's exit_code is %s, and the build exited with 7", body.ExitCode)
		}
		ledger, ok := b.first(http.MethodPut, "/v1/ledger")
		if !ok || ledger.End > comp.Begin {
			t.Errorf("the completion (event %d) began before the ledger request had been answered (event %d):\n%s", comp.Begin, ledger.End, b.requests())
		}
	},
}

// signalsNotDelivered: a ready or a heartbeat the collector does not take
// fails neither the claim nor the build.
var signalsNotDelivered = runner.Case{
	Name:  "a relay whose ready and heartbeats are refused goes on with the claim and the build",
	Cites: []string{"COLLIN-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := buildOpts{form: fullForm(), fault: func(r *http.Request) int {
			switch r.URL.Path {
			case "/v1/ready":
				return http.StatusServiceUnavailable
			case "/v1/heartbeat":
				return http.StatusInternalServerError
			}
			return 0
		}}
		// claimRelay fails the case unless the claim is answered 200 and
		// the build side serves.
		b := claimRelay(t, o)
		for range 3 {
			if rep := b.do(http.MethodGet, "http://artifacts/heartbeat", nil); rep.status != http.StatusOK {
				t.Errorf("the build's GET http://artifacts/heartbeat was answered %d with the collector refusing heartbeats", rep.status)
			}
			sleep(t, time.Second)
		}
		sleep(t, 2*time.Second)
		if n := b.count(http.MethodPost, "/v1/heartbeat"); n < 2 {
			t.Errorf("the relay sent %d heartbeats in 5 s of the build's activity after the collector refused one", n)
		}
		if rep := b.do(http.MethodGet, "http://artifacts/build-script", nil); rep.status != http.StatusOK || !bytes.Equal(rep.body, script) {
			t.Errorf("the build's GET http://artifacts/build-script was answered %d %q, want 200 and the script", rep.status, short(rep.body))
		}
		b.exit(0)
	},
}

// completionUnanswered: the relay does not depend on the completion's
// reply. The collector records the completion and resets its stream
// unanswered; the build's exit is still answered.
var completionUnanswered = runner.Case{
	Name:  "a relay does not depend on the completion's reply",
	Cites: []string{"COLLIN-34"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{form: fullForm(), abortComplete: true})
		b.do(http.MethodGet, "http://artifacts/build-script", nil)
		// exit fails the case unless the build's exit is answered 200 and
		// the collector has the completion.
		b.exit(0)
	},
}
