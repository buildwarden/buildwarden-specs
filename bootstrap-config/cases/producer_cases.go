package cases

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"unicode/utf8"

	bootstrapconfig "github.com/buildwarden/buildwarden-specs/bootstrap-config"
	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/target"
)

// The cases that test a producer, through the collector it supplies the
// config to (BOOTCFG-4 to BOOTCFG-6). Each starts the harness's relay, with
// no build side, has the collector under test claim it, and fetches
// GET /v1/bootstrap through the relay's session as a relay does. A case
// cannot choose the config, which is the producer's: it checks the one the
// collector serves. Each claim ends the instance.

// schemaFile is the config's schema (BOOTCFG-4).
const schemaFile = "v1.schema.json"

// resolverConf is the one nameserver of the harness's relay's resolver
// configuration, an address of a documentation range. A collector that
// claims may leave upstream_dns out; a relay on the tunnel resolves no name.
var resolverConf = netip.MustParseAddr("192.0.2.53")

// claimToken is the claim token the harness's relay is started with.
const claimToken = "conformance-claim-token"

// claims applies to a collector the harness reaches by having it claim the
// harness's relay.
func claims(d target.Declared) string {
	if d.Attachment != "claims" {
		return "the case has the collector claim the harness's relay, and this collector does not claim"
	}
	return ""
}

// hasConfig applies to a collector that serves a config.
func hasConfig(d target.Declared) string {
	if r := claims(d); r != "" {
		return r
	}
	if d.Forms.NoBootstrap {
		return "the collector has no bootstrap config"
	}
	return ""
}

// noConfig applies to a collector that can serve a build with none.
func noConfig(d target.Declared) string {
	if r := claims(d); r != "" {
		return r
	}
	if !d.Forms.NoBootstrap {
		return "the collector always has a bootstrap config"
	}
	return ""
}

// claimedBy starts the harness's relay and an instance of the collector
// under test against it, with an output location of its own and the capture
// mode "none", and returns the relay's session once the collector has
// claimed it.
func claimedBy(t *runner.T) *relay.Session {
	ctx := t.Context()
	r, err := relay.Start(ctx, relay.Config{
		Net: t.Network(attach.Claim), Token: claimToken,
		ResolvConf: []netip.Addr{resolverConf},
	})
	if err != nil {
		t.Fatalf("the harness's relay: %v", err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	in := t.Instance(attach.Params{
		Claim: r.Claim().Address, Token: r.Claim().Token,
		Out: t.TempDir(), Capture: relay.CaptureNone,
	})
	s, err := r.Session(ctx)
	if err != nil {
		t.Fatalf("the collector's claim: %v; its log:\n%s", err, in.Log())
	}
	return s
}

// fetch is GET /v1/bootstrap through s; it fails the case when the request
// fails.
func fetch(t *runner.T, s *relay.Session) *relay.Reply {
	in := s.Bootstrap(t.Context())
	if in.Err != nil {
		t.Fatalf("GET %s: %v", collectorPath, in.Err)
	}
	return in.Reply
}

// beyondSchema checks what BOOTCFG-4 (b) adds to the schema: UTF-8 with no
// byte order mark, version written as the token 1, and no member twice in
// any object.
func beyondSchema(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("it is not UTF-8")
	}
	if bytes.HasPrefix(body, []byte("\xef\xbb\xbf")) {
		return errors.New("it starts with a byte order mark")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return fmt.Errorf("it is not one JSON object: %w", err)
	}
	for name, v := range top {
		if name == "version" && string(v) != "1" {
			return fmt.Errorf("its version is written %s, not as the token 1", v)
		}
	}
	return noMemberTwice(body)
}

// noMemberTwice walks body's tokens and fails on an object that names a
// member twice, compared byte for byte after unescaping.
func noMemberTwice(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	// Each open object's member names, and whether the next token of each
	// is a name; an array's entry is nil.
	var objects []map[string]bool
	var atName []bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("it is not JSON: %w", err)
		}
		top := len(objects) - 1
		if top >= 0 && objects[top] != nil && atName[top] {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				objects, atName = objects[:top], atName[:top]
				continue
			}
			name, _ := tok.(string)
			if objects[top][name] {
				return fmt.Errorf("an object names the member %q twice", name)
			}
			objects[top][name] = true
			atName[top] = false
			continue
		}
		if top >= 0 && objects[top] != nil {
			atName[top] = true
		}
		switch tok {
		case json.Delim('{'):
			objects, atName = append(objects, map[string]bool{}), append(atName, true)
		case json.Delim('['):
			objects, atName = append(objects, nil), append(atName, false)
		case json.Delim(']'):
			objects, atName = objects[:top], atName[:top]
		}
	}
}

// producedValid is BOOTCFG-4: the config the collector serves validates
// against the schema and meets what the schema cannot express.
var producedValid = runner.Case{
	Name:    "the bootstrap config a collector serves validates against the schema",
	Cites:   []string{"BOOTCFG-4"},
	Role:    "collector",
	Ends:    true,
	Applies: hasConfig,
	Run: func(t *runner.T) {
		rep := fetch(t, claimedBy(t))
		if rep.Status != http.StatusOK {
			t.Fatalf("GET %s was answered %d %s, want 200 with the config", collectorPath, rep.Status, short(rep.Body))
		}
		if err := bootstrapconfig.Spec.Validate(schemaFile, rep.Body); err != nil {
			t.Errorf("the config %s: %v", short(rep.Body), err)
		}
		if err := beyondSchema(rep.Body); err != nil {
			t.Errorf("the config %s does not meet BOOTCFG-4 (b): %v", short(rep.Body), err)
		}
	},
}

// producedSame is BOOTCFG-6: every GET /v1/bootstrap of the session is
// answered with the same bytes.
var producedSame = runner.Case{
	Name:    "a collector serves the same bootstrap config for the whole session",
	Cites:   []string{"BOOTCFG-6"},
	Role:    "collector",
	Ends:    true,
	Applies: hasConfig,
	Run: func(t *runner.T) {
		s := claimedBy(t)
		first := fetch(t, s)
		if first.Status != http.StatusOK {
			t.Fatalf("GET %s was answered %d %s, want 200 with the config", collectorPath, first.Status, short(first.Body))
		}
		for i := 2; i <= 3; i++ {
			rep := fetch(t, s)
			if rep.Status != http.StatusOK || !bytes.Equal(rep.Body, first.Body) {
				t.Errorf("GET %s %d was answered %d %s, where the first was 200 %s", collectorPath, i, rep.Status, short(rep.Body), short(first.Body))
			}
		}
	},
}

// producedNone is BOOTCFG-5: a build whose producer supplied no config is
// answered 404 at GET /v1/bootstrap, each time.
var producedNone = runner.Case{
	Name:    "a collector whose producer supplied no bootstrap config answers GET /v1/bootstrap with 404",
	Cites:   []string{"BOOTCFG-5"},
	Role:    "collector",
	Ends:    true,
	Applies: noConfig,
	Run: func(t *runner.T) {
		s := claimedBy(t)
		for i := 1; i <= 2; i++ {
			if rep := fetch(t, s); rep.Status != http.StatusNotFound {
				t.Errorf("GET %s %d was answered %d %s, want 404", collectorPath, i, rep.Status, short(rep.Body))
			}
		}
	},
}
