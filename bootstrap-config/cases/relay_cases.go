package cases

import (
	"bytes"
	"mime"
	"net/http"
	"strings"

	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// The cases that test a relay as the config's carrier (BOOTCFG-1 to
// BOOTCFG-3). Each claims a relay of its own and completes its build, so
// each ends the instance it runs against.

// collectorToken is the collector token of each case's session.
const collectorToken = "conformance-collector-token"

// acceptedConfig is a config this version accepts, written with spacing and
// a final line feed that a relay which re-encoded it would lose.
var acceptedConfig = []byte("{ \"version\": 1,\n  \"trust\": {\"mode\": \"append\"} }\n")

// rejectedConfig is a body this version rejects on every count BOOTCFG-12
// names that bytes can carry: a byte order mark, an unknown member, a
// version other than 1, a mode that is not one, a byte that is not UTF-8
// and a second value after the object. A relay carries it as it carries
// acceptedConfig.
var rejectedConfig = []byte("\xef\xbb\xbf{\"version\":2,\"Trust\":{\"mode\":\"Exclusive\"},\"x\":\"\xff\"} {\"version\":1}")

// servesAndRecords has the build fetch the collector's config twice, and
// checks that each fetch reached the collector, was answered 200 with
// application/json and the collector's bytes, and was recorded.
//
// BOOTCFG-1 asks for a request to the collector for each fetch and not for
// exactly one, so each fetch is held to at least one request of its own: a
// relay that serves the second fetch from what it read for the first fails.
// The Content-Type is compared by its media type, as the suites of
// relay-claim and collector-inputs compare it, so a parameter such as a
// charset is not a failure.
func servesAndRecords(t *runner.T, config []byte) {
	b := claimRelay(t, collector.Form{Token: collectorToken, Bootstrap: config}, nil, nil)
	before := b.count(http.MethodGet, collectorPath)
	for i := range 2 {
		rep := b.do(http.MethodGet, bootstrapURL)
		if rep.status != http.StatusOK {
			t.Fatalf("fetch %d of %s was answered %d %s, want 200 and the collector's config %s", i+1, bootstrapURL, rep.status, short(rep.body), short(config))
		}
		if mt, _, err := mime.ParseMediaType(rep.header.Get("Content-Type")); err != nil || mt != "application/json" {
			t.Errorf("fetch %d of %s was answered with Content-Type %q, want application/json", i+1, bootstrapURL, rep.header.Get("Content-Type"))
		}
		if !bytes.Equal(rep.body, config) {
			t.Errorf("fetch %d of %s served %s, want the collector's bytes %s", i+1, bootstrapURL, short(rep.body), short(config))
		}
		now := b.count(http.MethodGet, collectorPath)
		if now == before {
			t.Errorf("the relay answered fetch %d of %s without sending GET %s to the collector for it; the collector received:\n%s", i+1, bootstrapURL, collectorPath, b.requests())
		}
		before = now
	}
	l := b.exit()
	if n := servedRecords(l, config); n != 2 {
		t.Errorf("the ledger records the config as a GET's 200 body %d times, want once for each of the 2 fetches; its records for /bootstrap: %s", n, strings.Join(bootstrapChannels(l), "; "))
	}
}

// carriesAccepted is BOOTCFG-1 and BOOTCFG-2 with a config this version
// accepts.
var carriesAccepted = runner.Case{
	Name:  "a relay serves the collector's bootstrap config byte for byte and records it",
	Cites: []string{"BOOTCFG-1", "BOOTCFG-2"},
	Role:  "relay",
	Ends:  true,
	Run:   func(t *runner.T) { servesAndRecords(t, acceptedConfig) },
}

// carriesEmpty is BOOTCFG-1 and BOOTCFG-2 with an empty body: a 200 is
// carried whatever its body, though to an executor an empty one is the same
// config as a 404 (BOOTCFG-10).
var carriesEmpty = runner.Case{
	Name:  "a relay serves and records an empty bootstrap body as it does any other",
	Cites: []string{"BOOTCFG-1", "BOOTCFG-2"},
	Role:  "relay",
	Ends:  true,
	Run:   func(t *runner.T) { servesAndRecords(t, []byte{}) },
}

// carriesBlank is BOOTCFG-1 and BOOTCFG-2 with a body of JSON white space
// only, the other form of the empty config (BOOTCFG-10).
var carriesBlank = runner.Case{
	Name:  "a relay serves and records a bootstrap body of JSON white space only as it does any other",
	Cites: []string{"BOOTCFG-1", "BOOTCFG-2"},
	Role:  "relay",
	Ends:  true,
	Run:   func(t *runner.T) { servesAndRecords(t, []byte(" \t\r\n")) },
}

// carriesRejected is BOOTCFG-1 and BOOTCFG-2 with a body this version
// rejects: the relay neither parses nor checks it.
var carriesRejected = runner.Case{
	Name:  "a relay serves and records a bootstrap body this version rejects as it does one it accepts",
	Cites: []string{"BOOTCFG-1", "BOOTCFG-2"},
	Role:  "relay",
	Ends:  true,
	Run:   func(t *runner.T) { servesAndRecords(t, rejectedConfig) },
}

// notServed has the collector answer GET /v1/bootstrap other than 200, or
// fail it, through form, fault and override, and checks that the build is
// answered 404 after the relay asked the collector, and that the ledger
// records nothing for the fetch: no exchange under any URL but the ones the
// case's build makes besides it (strayChannels), and not the bytes the
// collector holds. A relay may ask the collector more than once before it
// answers: BOOTCFG-3 does not say how often it asks.
func notServed(t *runner.T, form collector.Form, fault collector.Fault, override http.HandlerFunc) {
	form.Token = collectorToken
	b := claimRelay(t, form, fault, override)
	rep := b.do(http.MethodGet, bootstrapURL)
	if rep.status != http.StatusNotFound {
		t.Errorf("%s was answered %d %s, want 404", bootstrapURL, rep.status, short(rep.body))
	}
	if n := b.count(http.MethodGet, collectorPath) + int(b.w.overridden.Load()); n < 1 {
		t.Errorf("the relay answered the build's fetch without sending GET %s to the collector; the collector received:\n%s", collectorPath, b.requests())
	}
	l := b.exit()
	if rs := strayChannels(l); len(rs) > 0 {
		t.Errorf("the ledger records an exchange for the fetch the relay answered 404: %s", strings.Join(rs, "; "))
	}
	if form.Bootstrap != nil {
		if n := servedRecords(l, form.Bootstrap); n > 0 {
			t.Errorf("the ledger records the collector's config as a GET's 200 body %d times, though the relay answered the build 404", n)
		}
	}
}

// collectorHasNone is BOOTCFG-3 for a collector that answers 404.
var collectorHasNone = runner.Case{
	Name:  "a relay answers 404 and records nothing when the collector has no bootstrap config",
	Cites: []string{"BOOTCFG-3"},
	Role:  "relay",
	Ends:  true,
	Run:   func(t *runner.T) { notServed(t, collector.Form{}, nil, nil) },
}

// collectorFails is BOOTCFG-3 for a collector that answers 500, though it
// holds a config.
var collectorFails = runner.Case{
	Name:  "a relay answers 404 and records nothing when the collector answers GET /v1/bootstrap with 500",
	Cites: []string{"BOOTCFG-3"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		fault := func(r *http.Request) int {
			if r.URL.Path == collectorPath {
				return http.StatusInternalServerError
			}
			return 0
		}
		notServed(t, collector.Form{Bootstrap: acceptedConfig}, fault, nil)
	},
}

// collectorUnreachable is BOOTCFG-3 for a request to the collector that
// fails: the collector resets the request's stream unanswered.
var collectorUnreachable = runner.Case{
	Name:  "a relay answers 404 and records nothing when its request for the bootstrap config fails",
	Cites: []string{"BOOTCFG-3"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		reset := func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }
		notServed(t, collector.Form{Bootstrap: acceptedConfig}, nil, reset)
	},
}
