package ledgerwriter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/ledger"
)

// The tests write ledgers with this package and read them with the harness's
// verifier, which is written separately from the same document.

var (
	envPayload  = []byte(`{"type":"oci-image/v1","schemaVersion":2,"layers":[]}`)
	reqHeaders  = []byte("GET /pkg.tar HTTP/1.1\r\nHost: origin.example\r\n\r\n")
	respHeaders = []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	respBody    = []byte("hello")
	postBody    = []byte("form=1")
	artifact    = []byte("built")
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// written is a ledger of every kind of record: the environment record, a
// GET, a POST, and an artifact, each as the format's HTTP mapping lays it
// out. It also returns where each record starts.
func written(t *testing.T, key ed25519.PrivateKey) ([]byte, []int) {
	t.Helper()
	var buf bytes.Buffer
	var offsets []int
	w, err := New(&buf, key, "oci-image/v1")
	if err != nil {
		t.Fatal(err)
	}
	mark := func() { offsets = append(offsets, buf.Len()) }
	open := func(schema Schema, meta map[string]any) Channel {
		t.Helper()
		mark()
		ch, err := w.Open(schema, meta)
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}
	rec := func(f func() error) {
		t.Helper()
		mark()
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	env := open(Environment, map[string]any{"type": "environment"})
	rec(func() error {
		return w.Close(env, Out(envPayload), Environment, map[string]any{"type": "oci-image/v1"})
	})

	get := open(HTTPOpen, map[string]any{"method": "GET", "url": "https://origin.example/pkg.tar", "protocol": "HTTP/1.1"})
	rec(func() error {
		return w.Checkpoint(get, Out(reqHeaders), HTTPHeaders, map[string]any{"headers": [][]string{}})
	})
	rec(func() error {
		return w.Checkpoint(get, In(respHeaders), HTTPHeaders, map[string]any{"headers": [][]string{}})
	})
	rec(func() error { return w.Close(get, In(respBody), HTTPBody, map[string]any{"status": int64(200)}) })

	post := open(HTTPOpen, map[string]any{"method": "POST", "url": "http://origin.example/form", "protocol": "HTTP/1.1"})
	rec(func() error { return w.Checkpoint(post, Out(reqHeaders), HTTPHeaders, nil) })
	rec(func() error { return w.Checkpoint(post, Out(postBody), HTTPBody, nil) })
	rec(func() error { return w.Checkpoint(post, In(respHeaders), HTTPHeaders, nil) })
	rec(func() error { return w.Close(post, Payload{}, None, nil) })

	art := open(HTTPOpen, map[string]any{"method": "POST", "url": "http://artifacts/out/app", "protocol": "HTTP/1.1"})
	rec(func() error { return w.Checkpoint(art, Out(reqHeaders), HTTPHeaders, nil) })
	h := NewHash()
	_, _ = h.Write(artifact[:2])
	_, _ = h.Write(artifact[2:])
	rec(func() error {
		return w.Artifact(art, h.Payload(true), ArtifactMeta, map[string]any{"name": "out/app", "context": map[string]any{}})
	})
	if err := w.End(); err != nil {
		t.Fatal(err)
	}
	if w.Records() != len(offsets) {
		t.Fatalf("%d records, %d offsets", w.Records(), len(offsets))
	}
	return buf.Bytes(), offsets
}

func TestWrittenLedgerVerifies(t *testing.T) {
	t.Parallel()
	key := newKey(t)
	data, offsets := written(t, key)
	l, err := ledger.Verify(data, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Records) != len(offsets) || l.Truncated != 0 || len(l.Unclosed) != 0 {
		t.Fatalf("%d records (want %d), %d bytes cut, unclosed %v", len(l.Records), len(offsets), l.Truncated, l.Unclosed)
	}
	for i, r := range l.Records {
		if r.Offset != offsets[i] {
			t.Errorf("record %d at byte %d, written at %d", i, r.Offset, offsets[i])
		}
		if r.MetadataErr != nil {
			t.Errorf("record %d: metadata: %v", i, r.MetadataErr)
		}
	}
	if l.Header.Scheme != ledger.SchemeEd25519 || l.Header.HashBlockSize != 100 {
		t.Errorf("header %s, %d-byte hash block", l.Header.Scheme, l.Header.HashBlockSize)
	}
	if got := l.Header.Metadata["environment"]; got == nil {
		t.Error("the header's metadata names no environment")
	}
	env, ok := l.Environment()
	if !ok {
		t.Fatal("the ledger has no environment record")
	}
	payloads := map[int][]byte{
		1: envPayload, 3: reqHeaders, 4: respHeaders, 5: respBody,
		7: reqHeaders, 8: postBody, 9: respHeaders, 12: reqHeaders, 13: artifact,
	}
	for i, p := range payloads {
		if err := l.CheckPayload(l.Records[i], p); err != nil {
			t.Error(err)
		}
	}
	if env.PayloadSize != -int64(len(envPayload)) {
		t.Errorf("the environment record's size is %d", env.PayloadSize)
	}
	if l.Records[5].PayloadSize <= 0 || l.Records[13].PayloadSize >= 0 {
		t.Error("the directions of the payloads are wrong")
	}
	if l.Records[13].Type != ledger.Artifact {
		t.Errorf("the last record is %s", l.Records[13].Type)
	}
	if name, _ := l.Records[13].Text("name"); name != "out/app" {
		t.Errorf("the artifact is named %q", name)
	}
	if s, _ := l.Records[5].Int("status"); s != 200 {
		t.Errorf("the body's status is %d", s)
	}
	if l.Records[10].SchemaIndex != ledger.NoMetadata {
		t.Errorf("a record with no metadata has schema index %d", l.Records[10].SchemaIndex)
	}
	for i, id := range Schemas {
		if l.Header.Schemas[i] != id {
			t.Errorf("schema %d is %q", i, l.Header.Schemas[i])
		}
	}
	if l.Records[1].Schema != ledger.SchemaEnvironment || l.Records[13].Schema != ledger.SchemaArtifact {
		t.Errorf("schemas %q and %q", l.Records[1].Schema, l.Records[13].Schema)
	}
}

// TestBrokenLedgersAreRefused breaks a written ledger in one way each, and
// the verifier still refuses each.
func TestBrokenLedgersAreRefused(t *testing.T) {
	t.Parallel()
	key := newKey(t)
	data, offsets := written(t, key)
	// The signature of record 3 sits after its type, previous and open
	// signatures, size and hash block.
	sigAt := offsets[3] + 1 + 64 + 64 + 8 + 100
	cases := map[string]func([]byte) []byte{
		"a flipped signature": func(b []byte) []byte { b[sigAt] ^= 1; return b },
		"a flipped size":      func(b []byte) []byte { b[offsets[3]+1+128+7] ^= 1; return b },
		"a removed record":    func(b []byte) []byte { return append(b[:offsets[3]:offsets[3]], b[offsets[4]:]...) },
		"two records swapped": func(b []byte) []byte {
			out := append([]byte{}, b[:offsets[3]]...)
			out = append(out, b[offsets[4]:offsets[5]]...)
			out = append(out, b[offsets[3]:offsets[4]]...)
			return append(out, b[offsets[5]:]...)
		},
		"a flipped header key": func(b []byte) []byte { b[len("BLDL")+1+len("ed25519-sha512")+1+6] ^= 1; return b },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			b := breakIt(bytes.Clone(data))
			if _, err := ledger.Verify(b, key.Public().(ed25519.PublicKey)); err == nil {
				t.Error("the broken ledger verified")
			}
		})
	}
	t.Run("another key", func(t *testing.T) {
		other := newKey(t)
		if _, err := ledger.Verify(data, other.Public().(ed25519.PublicKey)); !errors.Is(err, ledger.ErrKey) {
			t.Errorf("got %v, want ErrKey", err)
		}
	})
	t.Run("cut short", func(t *testing.T) {
		l, err := ledger.Verify(data[:offsets[6]+10], nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(l.Records) != 6 || l.Truncated != 10 {
			t.Errorf("%d records and %d bytes cut", len(l.Records), l.Truncated)
		}
	})
}

func TestWriterRefusesMistakes(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := New(&buf, newKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := w.Open(None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(Channel("not a channel"), Payload{}, None, nil); err == nil {
		t.Error("a close of no open channel was written")
	}
	if err := w.Checkpoint(ch, Payload{Size: 3}, None, nil); err == nil {
		t.Error("a payload with no hash block was written")
	}
	if err := w.Checkpoint(ch, Payload{}, Schema(9), nil); err == nil {
		t.Error("a schema index outside the list was written")
	}
	if err := w.Close(ch, Payload{}, None, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(ch, Payload{}, None, nil); err == nil {
		t.Error("a channel was closed twice")
	}
	if err := w.End(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Open(None, nil); !errors.Is(err, ErrEnded) {
		t.Errorf("a record after the end: %v", err)
	}
	l, err := ledger.Verify(buf.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Records) != 2 || l.Header.Metadata["environment"] != nil {
		t.Errorf("%d records; header metadata %v", len(l.Records), l.Header.Metadata)
	}
}

type failing struct{ n int }

func (f *failing) Write(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("broken")
	}
	f.n--
	return len(p), nil
}

func TestWriteErrorSticks(t *testing.T) {
	t.Parallel()
	w, err := New(&failing{n: 1}, newKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Open(None, nil); err == nil {
		t.Fatal("a failed write was not an error")
	}
	if _, err := w.Open(None, nil); err == nil {
		t.Error("a record after a failed write was written")
	}
	if err := w.End(); err == nil {
		t.Error("End does not return the write's error")
	}
}
