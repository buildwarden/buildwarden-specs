package cases

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
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
// one, once for each time it asks, with the token on every request of the
// session, at a path that is clean and percent-encoded. The build also asks
// for context paths with "." and ".." segments, which the relay may refuse
// or resolve but must not send as they are. Of COLLIN-12 the case can see
// the dot segments only: a context path is a safe name, whose bytes need no
// encoding, and the Go relay refuses an unsafe one itself, so no name that
// a conforming relay sends carries a byte to encode.
var inputsOnRequest = runner.Case{
	Name:  "a relay fetches an input only when the build asks, at a clean path, with the token",
	Cites: []string{"COLLIN-9", "COLLIN-12", "COLLIN-28"},
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
		// The relay's answer to these is its own (relay-guest-api); what
		// it sends the collector for them is checked below.
		for _, p := range []string{"dir/../.warden/d.txt", "./.warden/d.txt", ".warden/./d.txt", ".warden/.."} {
			b.do(http.MethodGet, "http://cwd/"+p, nil)
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

// baseURL: with a collector_url that has a path and a trailing "/", every
// request goes to that path with the trailing "/" removed and the
// protocol's path appended. The collector is served off the tunnel, at an
// origin of the upstream, as the relay requests it itself.
var baseURL = runner.Case{
	Name:  "a relay sends every input and signal under the path of a base URL, with its trailing / removed",
	Cites: []string{"COLLIN-4"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := buildOpts{form: fullForm(), base: "http://collector.example/base/"}
		b := claimRelay(t, o)
		if rep := b.do(http.MethodGet, "http://artifacts/build-script", nil); rep.status != http.StatusOK || !bytes.Equal(rep.body, script) {
			t.Errorf("the build's GET http://artifacts/build-script was answered %d %q, want 200 and the script", rep.status, short(rep.body))
		}
		if rep := b.do(http.MethodGet, "http://cwd/dir/b.txt", nil); rep.status != http.StatusOK || string(rep.body) != contextFiles["dir/b.txt"] {
			t.Errorf("the build's GET http://cwd/dir/b.txt was answered %d %q, want 200 and the file", rep.status, short(rep.body))
		}
		b.do(http.MethodGet, "http://artifacts/heartbeat", nil)
		sleep(t, 2500*time.Millisecond)
		b.exit(0)
		targets := b.base.Targets()
		for _, tg := range targets {
			_, target, _ := strings.Cut(tg, " ")
			if !strings.HasPrefix(target, "/base/v1/") {
				t.Errorf("%s is not the base URL's path /base with the protocol's path appended", tg)
			}
		}
		for _, p := range []string{"/v1/ready", "/v1/build-script", "/v1/context/dir/b.txt", "/v1/heartbeat", "/v1/complete"} {
			if !slices.ContainsFunc(b.c.Requests(), func(r collector.Request) bool { return r.Path == p }) {
				t.Errorf("the collector at the base URL received no request to /base%s; the relay sent:\n  %s", p, strings.Join(targets, "\n  "))
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
// each input with another status, or resets the request unanswered, and
// the build is not served it.
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
		o := buildOpts{form: fullForm(), fault: func(r *http.Request) int { return statuses[r.URL.Path] },
			override: map[string]http.HandlerFunc{
				// A request that fails: its stream is reset unanswered.
				"/v1/context/.warden/d.txt": func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
			}}
		b := claimRelay(t, o)
		for _, u := range []string{"http://artifacts/build-script", "http://artifacts/bootstrap", "http://cwd/a.txt", "http://cwd/dir/", "http://cwd/dir/b.txt", "http://cwd/.warden/d.txt"} {
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

// heartbeatForwarded: the relay sends a heartbeat within 2 s of the build's
// first activity and at least every 2 s while it is less than 4 s old, one
// at a beat that finds it between 2 and 4 s old, and none once it is 5 s
// old. What a relay sends before the build's first activity COLLIN-30 does
// not say, and the case does not look. The build's last activity is put
// 0.5 s after a heartbeat arrived, so that a beat finds it 3.5 s old: a
// relay that stops at 3 s, or at 2 s, sends nothing then.
var heartbeatForwarded = runner.Case{
	Name:  "a relay sends heartbeats on a beat of 2 s while the build's last activity is less than 4 s old, and none at 5 s",
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
		activity := func() time.Time {
			if rep := b.do(http.MethodGet, "http://artifacts/heartbeat", nil); rep.status != http.StatusOK {
				t.Errorf("the build's GET http://artifacts/heartbeat was answered %d", rep.status)
			}
			return time.Now()
		}
		first := time.Now()
		for time.Since(first) < 6*time.Second {
			activity()
			sleep(t, time.Second)
		}
		hs := beats()
		if len(hs) == 0 {
			t.Fatalf("the relay sent no heartbeat for 6 s of the build's activity")
		}
		// Beats fall every 2 s from the last heartbeat that arrived; the
		// last activity goes 0.5 s after one of them.
		next := hs[len(hs)-1].BeganAt.Add(500 * time.Millisecond)
		for !next.After(time.Now()) {
			next = next.Add(2 * time.Second)
		}
		sleep(t, time.Until(next))
		last := activity()
		// Long enough for the beats that find it 5.5 s and 7.5 s old to
		// arrive, so that a relay that goes on beating is seen to.
		sleep(t, 9*time.Second)
		hs = beats()
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
		// A beat arrives no earlier than it falls, so one that found the
		// last activity 2 s old or more arrives 2 s after it or later.
		if !slices.ContainsFunc(hs, func(h collector.Request) bool {
			d := h.BeganAt.Sub(last)
			return d >= 2*time.Second && d <= 4*time.Second+slack
		}) {
			var at []string
			for _, h := range hs {
				at = append(at, h.BeganAt.Sub(last).Round(time.Millisecond).String())
			}
			t.Errorf("no heartbeat came between 2 and 4 s after the build's last activity, when a beat finds it less than 4 s old; they came at %s from it", strings.Join(at, ", "))
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
		if ready.Begin > b.claimed {
			t.Errorf("POST /v1/ready arrived at event %d, after the claim's reply at event %d", ready.Begin, b.claimed)
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
// fails neither the claim nor the build, nor does a heartbeat it never
// answers. COLLIN-33 gives no time for the bound on the wait for a reply,
// so the case cannot see one: it checks that the build goes on while a
// heartbeat is unanswered.
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

// heartbeatUnanswered: a heartbeat the collector never answers holds up
// neither the build's requests nor its completion.
var heartbeatUnanswered = runner.Case{
	Name:  "a relay whose heartbeat is never answered goes on with the build",
	Cites: []string{"COLLIN-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		held := make(chan struct{})
		var once sync.Once
		o := buildOpts{form: fullForm(), override: map[string]http.HandlerFunc{
			"/v1/heartbeat": func(_ http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(held) })
				<-r.Context().Done()
			},
		}}
		b := claimRelay(t, o)
		b.do(http.MethodGet, "http://artifacts/heartbeat", nil)
		select {
		case <-held:
		case <-time.After(4 * time.Second):
			t.Fatalf("the relay sent no heartbeat within 4 s of the build's activity")
		}
		for _, u := range []string{"http://artifacts/heartbeat", "http://artifacts/build-script", "http://cwd/a.txt"} {
			if rep := b.do(http.MethodGet, u, nil); rep.status != http.StatusOK {
				t.Errorf("the build's GET %s was answered %d %q while a heartbeat was unanswered, want 200", u, rep.status, short(rep.body))
			}
		}
		// exit fails the case unless the build's exit is answered 200 and
		// the collector has the completion.
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
