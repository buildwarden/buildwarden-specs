package cases

import (
	"bytes"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/upstream"
)

// The cases that test a relay as the client of the outputs. Each claims a
// relay of its own, so each ends the instance it runs against.

// oddPath is the path of a request the build has the relay proxy, as the
// build sends it, and oddDecoded the same path percent-decoded. Its bytes
// " " and "%" are outside every set a path may carry unencoded, so that a
// relay that names a capture after the request's path, as the Go relay
// does, has a name to percent-encode (COLLOUT-12).
const (
	oddPath    = "/a%20b~c%25d"
	oddDecoded = "/a b~c%d"
)

// aBuild is a build that sends each kind of output: an artifact, two
// requests the relay proxies (which the capture mode "all" captures), one of
// them at oddPath, and a piece of the console; then it exits. It returns the
// bytes the build sent of each.
func aBuild(b *build) (artifact, console []byte) {
	artifact = []byte("an artifact the build made\n")
	if rep := b.do(http.MethodPost, "http://artifacts/out/report.txt", artifact); rep.status != http.StatusOK {
		b.t.Errorf("the build's POST http://artifacts/out/report.txt was answered %d %q, want 200", rep.status, rep.body)
	}
	for _, p := range []string{"/page", oddPath} {
		if rep := b.do(http.MethodGet, "http://"+originName+p, nil); rep.status != http.StatusOK {
			b.t.Errorf("the build's GET http://%s%s was answered %d %q, want 200", originName, p, rep.status, rep.body)
		}
	}
	console = []byte("the build's console\n")
	if rep := b.do(http.MethodPost, b.control("/v1/output"), console); rep.status != http.StatusOK {
		b.t.Errorf("the build's POST /v1/output was answered %d %q, want 200", rep.status, rep.body)
	}
	b.exit(0)
	return artifact, console
}

// withToken is a session whose collector has a token, capturing all.
func withToken() buildOpts {
	return buildOpts{form: collector.Form{Token: collectorToken}, capture: relay.CaptureAll}
}

// outputMethods: each output is sent with the method its endpoint names,
// with the session's token on every request, at a path that is clean and
// percent-encoded. A capture's name is the relay's to choose, so the case
// can see the encoding only of a relay whose names carry bytes that need
// it: the response at oddPath must arrive as a capture, which it does not
// from a relay that puts the "%" of its path in a name unencoded (the
// request cannot be made, or names another capture), and every path must
// be encoded.
var outputMethods = runner.Case{
	Name:  "a relay sends each output with its method, at a clean and percent-encoded path, with the token",
	Cites: []string{"COLLOUT-9", "COLLOUT-12", "COLLOUT-22"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, withToken())
		artifact, console := aBuild(b)
		methods := map[string]string{
			"/v1/artifacts/": http.MethodPut, "/v1/captures/": http.MethodPut,
			"/v1/ledger": http.MethodPut, "/v1/environment": http.MethodPut, "/v1/output": http.MethodPost,
		}
		seen := map[string]bool{}
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
			for prefix, m := range methods {
				if r.Path == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(r.Path, prefix) {
					seen[prefix] = true
					if r.Method != m {
						t.Errorf("%s %s: want %s", r.Method, r.Path, m)
					}
				}
			}
		}
		for _, p := range []string{"/v1/artifacts/", "/v1/captures/", "/v1/ledger", "/v1/output"} {
			if !seen[p] {
				t.Errorf("the collector received no request to %s; it received:\n%s", p, b.requests())
			}
		}
		if got := b.c.Artifacts()["out/report.txt"]; !bytes.Equal(got, artifact) {
			t.Errorf("the collector stored the artifact out/report.txt as %q, want %q", got, artifact)
		}
		if got := b.c.Output(); !bytes.Equal(got, console) {
			t.Errorf("the collector stored the console as %q, want %q", got, console)
		}
		odd := upstream.Body(originName, oddDecoded)
		if !slices.ContainsFunc(b.c.Captures(), func(c collector.Capture) bool { return bytes.Equal(c.Body, odd) }) {
			t.Errorf("the collector stored no capture of the response to the build's GET http://%s%s, in capture mode all; a capture named after that path must be sent with the name percent-encoded. It received:\n%s", originName, oddPath, b.requests())
		}
	},
}

// baseURL: with a collector_url that has a path and a trailing "/", every
// request goes to that path with the trailing "/" removed and the
// protocol's path appended. The collector is served off the tunnel, at an
// origin of the upstream, as the relay requests it itself.
var baseURL = runner.Case{
	Name:  "a relay sends every request under the path of a base URL, with its trailing / removed",
	Cites: []string{"COLLOUT-4"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := withToken()
		o.base = "http://collector.example/base/"
		b := claimRelay(t, o)
		aBuild(b)
		targets := b.base.Targets()
		if len(targets) == 0 {
			t.Fatalf("the relay sent no request to the base URL %s", o.base)
		}
		for _, tg := range targets {
			_, target, _ := strings.Cut(tg, " ")
			if !strings.HasPrefix(target, "/base/v1/") {
				t.Errorf("%s is not the base URL's path /base with the protocol's path appended", tg)
			}
		}
		for _, p := range []string{"/v1/ledger", "/v1/output", "/v1/complete"} {
			if !slices.ContainsFunc(b.c.Requests(), func(r collector.Request) bool { return r.Path == p }) {
				t.Errorf("the collector at the base URL received no request to /base%s; the relay sent:\n  %s", p, strings.Join(targets, "\n  "))
			}
		}
	},
}

// escaped is a path whose every segment is percent-encoded as
// url.PathEscape leaves it: only the unreserved bytes, sub-delimiters, ":",
// "@" and "%XX" escapes.
var escaped = regexp.MustCompile(`^(/([A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*$`)

// uncleanPath says what is wrong with a path a relay sent (COLLOUT-12), or
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
// Authorization header.
var noTokenSent = runner.Case{
	Name:  "a relay whose claim has no collector token sends no Authorization header",
	Cites: []string{"COLLOUT-9"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, buildOpts{capture: relay.CaptureAll})
		aBuild(b)
		for _, r := range b.c.Requests() {
			if v, ok := r.Header["Authorization"]; ok {
				t.Errorf("%s %s carried Authorization %q, with no collector_token in the claim", r.Method, r.Path, v)
			}
		}
	},
}

// isOutput says that a path is one of the outputs': the ledger, an artifact,
// a capture, the environment or the console. A signal is not one.
func isOutput(p string) bool {
	return p == "/v1/ledger" || p == "/v1/output" || p == "/v1/environment" ||
		strings.HasPrefix(p, "/v1/artifacts/") || strings.HasPrefix(p, "/v1/captures/")
}

// ledgerFirst: the ledger request is opened before any other output of the
// session (a signal may come before it), and is its only one; it ends, and
// is answered, before the completion is sent, as is every output of the
// build's requests.
var ledgerFirst = runner.Case{
	Name:  "a relay opens the ledger request before any other output, sends one, and has it and every output answered before the completion",
	Cites: []string{"COLLOUT-26", "COLLOUT-29"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := withToken()
		o.edit = environmentClaim(200)
		b := claimRelay(t, o)
		aBuild(b)
		reqs := b.c.Requests()
		led, ok := b.first(http.MethodPut, "/v1/ledger")
		if !ok {
			t.Fatalf("the collector received no PUT /v1/ledger:\n%s", b.requests())
		}
		for _, r := range reqs {
			if isOutput(r.Path) && r.Path != "/v1/ledger" && r.Begin < led.Begin {
				t.Errorf("%s %s (event %d) began before PUT /v1/ledger (event %d):\n%s", r.Method, r.Path, r.Begin, led.Begin, b.requests())
			}
		}
		if n := b.count(http.MethodPut, "/v1/ledger"); n != 1 {
			t.Errorf("the session sent %d ledger requests, want 1", n)
		}
		comp, ok := b.first(http.MethodPost, "/v1/complete")
		if !ok {
			t.Fatalf("the collector received no completion:\n%s", b.requests())
		}
		for _, r := range reqs {
			if isOutput(r.Path) && r.End > comp.Begin {
				t.Errorf("%s %s (events %d to %d) was not answered before the completion began (event %d):\n%s", r.Method, r.Path, r.Begin, r.End, comp.Begin, b.requests())
			}
		}
	},
}

// capturesHashed: each capture declares its trailer, has no length in
// advance, and carries the BLAKE2b-256 of exactly its body, in lower-case
// hexadecimal.
var capturesHashed = runner.Case{
	Name:  "a relay sends each capture with no length, declaring Warden-Hash, the BLAKE2b-256 of its body",
	Cites: []string{"COLLOUT-18"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		b := claimRelay(t, withToken())
		aBuild(b)
		var n int
		for _, r := range b.c.Requests() {
			if !strings.HasPrefix(r.Path, "/v1/captures/") {
				continue
			}
			n++
			if r.Status != http.StatusOK {
				t.Errorf("PUT %s was answered %d: the collector stores only a capture whose Warden-Hash trailer was declared and is 64 hexadecimal digits", r.Path, r.Status)
			}
			if cl := r.Header.Get("Content-Length"); cl != "" {
				t.Errorf("PUT %s gave its length in advance, Content-Length %s", r.Path, cl)
			}
		}
		if n == 0 {
			t.Fatalf("the relay sent no capture of the exchange it proxied, in capture mode all:\n%s", b.requests())
		}
		lower := regexp.MustCompile(`^[0-9a-f]{64}$`)
		for _, c := range b.c.Captures() {
			if !lower.MatchString(c.Hash) {
				t.Errorf("the capture %s has Warden-Hash %q, not 64 lower-case hexadecimal digits", c.Sent, c.Hash)
			}
			if c.Hash != c.BodyHash {
				t.Errorf("the capture %s has Warden-Hash %s, and its %d bytes hash to %s", c.Sent, c.Hash, len(c.Body), c.BodyHash)
			}
		}
	},
}

// environmentPayload is an environment payload a relay takes, of n bytes.
func environmentClaim(n int) func(*claimant.Config) {
	return func(c *claimant.Config) {
		c.Environment = &claimant.Environment{Type: "conformance/v1", Payload: environmentOf(n), Metadata: []byte{0xa0}}
	}
}

// environmentFirst: with an environment, the relay sends it once, and
// before the ledger's environment record arrives.
var environmentFirst = runner.Case{
	Name:  "a relay sends the environment payload once, before the ledger states its hash",
	Cites: []string{"COLLOUT-27"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := withToken()
		o.edit = environmentClaim(200)
		b := claimRelay(t, o)
		b.exit(0)
		if n := b.count(http.MethodPut, "/v1/environment"); n != 1 {
			t.Fatalf("the relay sent %d environment requests, want 1:\n%s", n, b.requests())
		}
		env, _ := b.first(http.MethodPut, "/v1/environment")
		if want := environmentOf(200); !bytes.Equal(env.Body, want) {
			t.Errorf("PUT /v1/environment carried %q, want the claim's payload %q", env.Body, want)
		}
		data, _, _ := b.c.Ledger()
		l, err := ledger.Verify(data, nil)
		if err != nil {
			t.Fatalf("the ledger the collector received: %v", err)
		}
		var rec *ledger.Record
		for i, r := range l.Records {
			if r.Type == ledger.Close && (r.Schema == ledger.SchemaEnvironment || r.Schema == ledger.SchemaEnvironmentContainer) {
				rec = &l.Records[i]
				break
			}
		}
		if rec == nil {
			t.Fatalf("the ledger has no environment record that states the payload's hash")
		}
		// The record's first byte arrived after the payload was held.
		at, ok := b.w.arrived(rec.Offset + 1)
		if !ok {
			t.Fatalf("the arrival of the ledger's byte %d was not seen", rec.Offset)
		}
		if at.Before(env.EndedAt) {
			t.Errorf("the ledger's environment record (at byte %d) arrived at %s, before the collector had answered PUT /v1/environment at %s", rec.Offset, at.Format("15:04:05.000000"), env.EndedAt.Format("15:04:05.000000"))
		}
	},
}

// environmentTooLarge: a relay does not send an environment payload over
// 1 MiB, whatever it answers the claim that carries one.
var environmentTooLarge = runner.Case{
	Name:  "a relay sends no environment payload over 1 MiB",
	Cites: []string{"COLLOUT-31"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := withToken()
		o.edit = environmentClaim(1<<20 + 1)
		o.anyReply = true
		b := claimRelay(t, o)
		if b.rep.Status == http.StatusOK {
			// A relay that took the claim may send the payload at any
			// point of the session; it has sent every output once the
			// collector has the completion.
			b.exit(0)
		}
		for _, r := range b.c.Requests() {
			// The collector answers 413 to a payload over
			// collector.EnvironmentLimit, 1 MiB, and only to one.
			if r.Path == "/v1/environment" && r.Status == http.StatusRequestEntityTooLarge {
				t.Errorf("the relay sent PUT /v1/environment with a body over 1 MiB (answered %d), for a claim answered %d", r.Status, b.rep.Status)
			}
		}
	},
}

// notStored: a relay reads only 200 as an output stored. The collector
// answers the artifact with another status, so the build is not told it was
// stored.
var notStored = runner.Case{
	Name:  "a relay reads only 200 as an output stored",
	Cites: []string{"COLLOUT-25"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		o := withToken()
		o.fault = func(r *http.Request) int {
			switch r.URL.Path {
			case "/v1/artifacts/created.txt":
				return http.StatusCreated
			case "/v1/artifacts/accepted.txt":
				return http.StatusAccepted
			case "/v1/artifacts/failed.txt":
				return http.StatusInternalServerError
			case "/v1/output":
				return http.StatusServiceUnavailable
			}
			return 0
		}
		b := claimRelay(t, o)
		for _, n := range []string{"created.txt", "accepted.txt", "failed.txt"} {
			if rep := b.do(http.MethodPost, "http://artifacts/"+n, []byte("refused\n")); rep.status == http.StatusOK {
				t.Errorf("the collector did not store the artifact %s, and the build's POST was answered 200 %q", n, rep.body)
			}
		}
		if rep := b.do(http.MethodPost, b.control("/v1/output"), []byte("refused\n")); rep.status == http.StatusOK {
			t.Errorf("the collector did not store the console's piece, and the build's POST /v1/output was answered 200")
		}
		if rep := b.do(http.MethodPost, "http://artifacts/stored.txt", []byte("stored\n")); rep.status != http.StatusOK {
			t.Errorf("the build's POST http://artifacts/stored.txt, which the collector stored, was answered %d %q", rep.status, rep.body)
		}
		b.exit(0)
	},
}
