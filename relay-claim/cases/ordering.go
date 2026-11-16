package cases

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/claimant"
	"github.com/buildwarden/buildwarden-specs/conformance/collector"
	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// beforeTheReply claims a fresh relay with an environment, and checks what
// the collector had received by the time the claim's 200 arrived: the
// ledger stream begun, the environment answered 200, and ready answered.
// Only the collector's side is observed: what the relay's build side serves
// at that moment is not asserted (Known divergences, D19).
var beforeTheReply = runner.Case{
	Name:  "the relay answers 200 only after the ledger stream, the environment and ready",
	Cites: []string{"CLAIM-44"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		env := map[string]any{"payload": payload(`{"type":"conformance-test/v1"}`), "metadata": emptyMap}
		rep := r.send(r.base().with(claim{"environment": env}))
		// The collector's event number for the 200's arrival orders it
		// against the collector's requests, as a clock may not.
		replied := coll.Mark()
		accepted(t, "the claim", rep)
		find := func(method, path string) (collector.Request, bool) {
			for _, q := range coll.Requests() {
				if q.Method == method && q.Path == path {
					return q, true
				}
			}
			return collector.Request{}, false
		}
		if q, ok := find(http.MethodPut, "/v1/ledger"); !ok || q.Begin > replied {
			t.Errorf("the ledger stream, PUT /v1/ledger, had not reached the collector when the claim's 200 arrived (%v)", ok)
		}
		if q, ok := find(http.MethodPut, "/v1/environment"); !ok || q.Status != http.StatusOK || q.End == 0 || q.End > replied {
			t.Errorf("PUT /v1/environment had not been answered 200 when the claim's 200 arrived (%v, %d)", ok, q.Status)
		}
		if q, ok := find(http.MethodPost, "/v1/ready"); !ok || q.End == 0 || q.End > replied {
			t.Errorf("POST /v1/ready had not been answered when the claim's 200 arrived (%v)", ok)
		}
	},
}

// readyRefused has the collector answer ready 500: the claim is still
// answered 200.
var readyRefused = runner.Case{
	Name:  "a failed ready does not fail the claim",
	Cites: []string{"CLAIM-44"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.tunnel(collector.New(collector.Form{}, func(q *http.Request) int {
			if q.URL.Path == "/v1/ready" {
				return http.StatusInternalServerError
			}
			return 0
		}))
		accepted(t, "the claim, its ready answered 500", r.send(r.base()))
	},
}

// afterTheClaim claims a fresh relay and then polls its claim endpoint: it
// stops accepting connections, and a claim it still reads is answered 409.
var afterTheClaim = runner.Case{
	Name:  "after its 200 the relay accepts no claim and stops accepting connections",
	Cites: []string{"CLAIM-46", "CLAIM-47"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		accepted(t, "the claim", r.send(r.base()))
		r.notAnswering("after the 200", false)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if _, err := r.cl.OpenTunnel(ctx, coll); err == nil {
			t.Errorf("a tunnel was opened after the claim's 200")
		}
	},
}

// openConnection is a connection to the claim endpoint on which the first
// line of a POST to path has been sent, and nothing more: the relay is
// reading the request's headers. It is dialled before the claim's, so that a
// relay that accepts its connections in order has accepted it by the time
// it reads the claim. (A connection that has been answered once and is kept
// alive would not do: an HTTP server takes it as idle while it waits for the
// next request's headers, and closes it when it stops serving.)
type openConnection struct {
	conn net.Conn
	rd   *bufio.Reader
}

func (r *relayRun) openConnection(path string) *openConnection {
	t := r.t
	conn, err := r.cl.Net.Dial(t.Context(), "tcp", r.cl.Endpoint.Address)
	if err != nil {
		t.Fatalf("a connection to the claim endpoint: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: relay\r\n", path)
	return &openConnection{conn: conn, rd: bufio.NewReader(conn)}
}

// finish sends the rest of the request, its headers h and body, and returns
// its reply, or nil when the relay closed the connection without one.
func (o *openConnection) finish(t *runner.T, h http.Header, body []byte) *claimant.Reply {
	_ = o.conn.SetDeadline(time.Now().Add(within))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if err := h.Write(o.conn); err != nil {
		t.Logf("the rest of the request: %v", err)
		return nil
	}
	_, _ = o.conn.Write(append([]byte("\r\n"), body...))
	resp, err := http.ReadResponse(o.rd, nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the relay neither answered nor closed the connection within %s", within)
	}
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return &claimant.Reply{Status: resp.StatusCode, Header: resp.Header}
	}
	b, _ := io.ReadAll(resp.Body)
	return &claimant.Reply{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// afterTheClaimOnOpen claims a fresh relay, with no tunnel and a collector
// on the upstream, while it is reading the headers of a tunnel request on
// one connection and of a claim on another, each opened before the claim's
// (CLAIM-46: a connection kept alive or idle). After the 200 each request is
// finished: the relay must answer it 409, the
// tunnel request "tunnel already open" (CLAIM-15) and the claim "already
// claimed" (CLAIM-46), or close the connection with no reply, as the Go
// relay may for the connections it was serving.
var afterTheClaimOnOpen = runner.Case{
	Name:  "after its 200 the relay accepts no tunnel and no claim on a connection it was reading",
	Cites: []string{"CLAIM-15", "CLAIM-46"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		r.upstreamCollector(collectorName)
		c := r.base().with(claim{"collector_url": "http://" + collectorName})
		tun, cl := r.openConnection("/v1/tunnel"), r.openConnection("/v1/claim")
		accepted(t, "the claim", r.send(c))
		auth := func(h http.Header) http.Header {
			if r.cl.Endpoint.Token != "" {
				h.Set("Authorization", "Bearer "+r.cl.Endpoint.Token)
			}
			return h
		}
		for _, v := range []struct {
			what, body string
			o          *openConnection
			h          http.Header
			payload    []byte
		}{
			{"a tunnel request", "tunnel already open", tun, auth(http.Header{"Connection": {"Upgrade"}, "Upgrade": {"warden-tunnel"}}), nil},
			{"a claim", "already claimed", cl, auth(http.Header{"Content-Type": {"application/json"}}), c.body()},
		} {
			rep := v.o.finish(t, v.h, v.payload)
			switch {
			case rep == nil:
			case rep.Status == http.StatusSwitchingProtocols:
				t.Errorf("%s on a connection open before the claim's 200 was answered 101 after it", v.what)
			default:
				refusal(t, v.what+" on a connection open before the claim's 200", rep, http.StatusConflict, v.body, true)
			}
		}
	},
}

// ledgerSigned claims a fresh relay, has the build fetch the origin and
// exit, and verifies the ledger the collector received under the reply's
// ledger_public_key, and not under another key.
var ledgerSigned = runner.Case{
	Name:  "the ledger's records verify under the reply's ledger_public_key",
	Cites: []string{"CLAIM-33"},
	Role:  "relay",
	Ends:  true,
	Run: func(t *runner.T) {
		r := startRelay(t, attach.Params{})
		coll := collector.New(collector.Form{}, nil)
		r.tunnel(coll)
		rep := r.send(r.base())
		ca := accepted(t, "the claim", rep)
		_, _, key, err := rep.Identity()
		if err != nil {
			t.Fatalf("the claim's identity: %v", err)
		}
		env := r.build(declaredLink(r.d))
		fetchOrigin(t, env, ca, "http", "/bytes/100")
		exit(t, env, coll)
		data, _, _ := coll.Ledger()
		l, err := ledger.Verify(data, key)
		if err != nil {
			t.Fatalf("the ledger does not verify under the reply's key: %v", err)
		}
		if len(l.Records) == 0 {
			t.Errorf("the ledger has no record of the build's exchange")
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := ledger.Verify(data, other); !errors.Is(err, ledger.ErrKey) {
			t.Errorf("the ledger verified under a key that is not the reply's: %v", err)
		}
	},
}
