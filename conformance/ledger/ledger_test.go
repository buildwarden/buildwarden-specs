package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/cbor"
)

// The ledgers below are built in this file from the format's document,
// specs/build-ledger/v1.md, with a seeded key, so that every test reads the
// same bytes.

var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

var defaultSchemas = []string{SchemaHTTPOpen, SchemaHTTPHeaders, SchemaHTTPBody, SchemaArtifact, SchemaRedacted, SchemaEnvironment}

// block is the hash block of p under the default hashes, written out from
// the document's table rather than through the verifier's own code.
func block(p []byte) []byte {
	b2 := blake2b.Sum256(p)
	s256 := sha256.Sum256(p)
	s1 := sha1.Sum(p)
	m5 := md5.Sum(p)
	var b []byte
	b = append(b, b2[:]...)
	b = append(b, s256[:]...)
	b = append(b, s1[:]...)
	return append(b, m5[:]...)
}

func sign(key ed25519.PrivateKey, input []byte) []byte {
	d := digest(input)
	return ed25519.Sign(key, d)
}

// writer writes a ledger as the format's document lays it out.
type writer struct {
	key  ed25519.PrivateKey
	buf  []byte
	prev []byte
}

func newWriter(t *testing.T, key ed25519.PrivateKey, meta map[string]any) *writer {
	t.Helper()
	w := &writer{key: key}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("the key's public half is not an Ed25519 key")
	}
	w.buf = append(w.buf, Magic...)
	w.buf = append(w.buf, Version)
	w.buf = append(w.buf, SchemeEd25519...)
	w.buf = append(w.buf, 0)
	w.buf = binary.BigEndian.AppendUint16(w.buf, ed25519.SignatureSize)
	w.buf = binary.BigEndian.AppendUint16(w.buf, 100)
	w.buf = binary.BigEndian.AppendUint16(w.buf, ed25519.PublicKeySize)
	w.buf = append(w.buf, pub...)
	w.prev = sign(key, w.buf)
	w.buf = append(w.buf, w.prev...)
	if meta == nil {
		meta = map[string]any{
			"hashes":      []string{"blake2b_256", "sha256", "sha1", "md5"},
			"schemas":     defaultSchemas,
			"environment": map[string]any{"type": "oci-image/v1"},
		}
	}
	m, err := cbor.Encode(meta)
	if err != nil {
		t.Fatal(err)
	}
	w.buf = binary.BigEndian.AppendUint32(w.buf, uint32(len(m)))
	w.buf = append(w.buf, m...)
	return w
}

// record appends a record and returns its signature. payload is nil for a
// payload size of 0; out makes the size negative. schema < 0 is no
// metadata.
func (w *writer) record(t *testing.T, typ Type, openSig, payload []byte, out bool, schema int, meta map[string]any) []byte {
	t.Helper()
	size := int64(len(payload))
	if out {
		size = -size
	}
	var in []byte
	in = append(in, byte(typ))
	in = append(in, w.prev...)
	if typ != Open {
		in = append(in, openSig...)
	}
	in = binary.BigEndian.AppendUint64(in, uint64(size))
	if size != 0 {
		in = append(in, block(payload)...)
	}
	sig := sign(w.key, in)
	w.buf = append(w.buf, in...)
	w.buf = append(w.buf, sig...)
	if schema < 0 {
		w.buf = append(w.buf, NoMetadata)
	} else {
		m, err := cbor.Encode(meta)
		if err != nil {
			t.Fatal(err)
		}
		w.buf = append(w.buf, byte(schema))
		w.buf = binary.BigEndian.AppendUint32(w.buf, uint32(len(m)))
		w.buf = append(w.buf, m...)
	}
	w.prev = sig
	return sig
}

var (
	envPayload  = []byte(`{"type":"oci-image/v1","schemaVersion":2,"layers":[]}`)
	reqHeaders  = []byte("GET /pkg.tar HTTP/1.1\r\nHost: origin.example\r\n\r\n")
	respHeaders = []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	respBody    = []byte("hello")
	artifact    = []byte("built")
)

// offsets are where each record of the valid ledger starts.
type built struct {
	data    []byte
	offsets []int
	sigs    [][]byte
}

// validLedger is a whole build's ledger: the environment record, a GET and
// an artifact, as the document's tables give them.
func validLedger(t *testing.T) built {
	t.Helper()
	w := newWriter(t, testKey, nil)
	var b built
	rec := func(typ Type, openSig, payload []byte, out bool, schema int, meta map[string]any) []byte {
		b.offsets = append(b.offsets, len(w.buf))
		sig := w.record(t, typ, openSig, payload, out, schema, meta)
		b.sigs = append(b.sigs, sig)
		return sig
	}
	env := rec(Open, nil, nil, false, 5, map[string]any{"type": "environment"})
	rec(Close, env, envPayload, true, 5, map[string]any{"type": "oci-image/v1"})
	get := rec(Open, nil, nil, false, 0, map[string]any{"method": "GET", "url": "https://origin.example/pkg.tar", "protocol": "HTTP/1.1"})
	rec(Checkpoint, get, reqHeaders, true, 1, map[string]any{"headers": [][]string{}})
	rec(Checkpoint, get, respHeaders, false, 1, map[string]any{"headers": [][]string{{"X-Request-Id", "1"}}})
	rec(Close, get, respBody, false, 2, map[string]any{"status": int64(200)})
	post := rec(Open, nil, nil, false, 0, map[string]any{"method": "PUT", "url": "http://artifacts/out", "protocol": "HTTP/1.1"})
	rec(Artifact, post, artifact, true, 3, map[string]any{"name": "out", "context": map[string]any{}})
	b.data = w.buf
	return b
}

func pub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	p, ok := testKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("not an Ed25519 key")
	}
	return p
}

// TestVerifyValid reads the valid ledger back field by field.
func TestVerifyValid(t *testing.T) {
	t.Parallel()
	b := validLedger(t)
	l, err := Verify(b.data, pub(t))
	if err != nil {
		t.Fatal(err)
	}
	if l.Truncated != 0 || len(l.Unclosed) != 0 || len(l.Records) != 8 {
		t.Fatalf("Truncated %d, Unclosed %v, %d records; want a whole, complete ledger of 8", l.Truncated, l.Unclosed, len(l.Records))
	}
	if got := l.Header.Hashes; strings.Join(got, ",") != "blake2b_256,sha256,sha1,md5" {
		t.Errorf("hashes %v", got)
	}
	env, ok := l.Environment()
	if !ok || env.Index != 1 {
		t.Fatalf("Environment() = %d, %v", env.Index, ok)
	}
	if err := l.CheckPayload(env, envPayload); err != nil {
		t.Error(err)
	}
	body := l.Records[5]
	if body.Type != Close || body.Channel != 2 || body.Schema != SchemaHTTPBody {
		t.Errorf("record 5: %s on channel %d, schema %s", body.Type, body.Channel, body.Schema)
	}
	if n, ok := body.Int("status"); !ok || n != 200 {
		t.Errorf("record 5's status = %d, %v", n, ok)
	}
	if u, _ := l.Records[2].Text("url"); u != "https://origin.example/pkg.tar" {
		t.Errorf("record 2's url = %q", u)
	}
	if err := l.CheckPayload(body, respBody); err != nil {
		t.Error(err)
	}
	b2 := blake2b.Sum256(respBody)
	if got := l.PrimaryHash(body); got != hex.EncodeToString(b2[:]) {
		t.Errorf("PrimaryHash = %s", got)
	}
	art := l.Records[7]
	if art.Type != Artifact || art.PayloadSize != -int64(len(artifact)) {
		t.Errorf("record 7: %s of %d", art.Type, art.PayloadSize)
	}
	if name, _ := art.Text("name"); name != "out" {
		t.Errorf("artifact name %q", name)
	}
	// The key in the claim's reply form.
	k, err := ParseKey(hex.EncodeToString(pub(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(b.data, k); err != nil {
		t.Error(err)
	}
}

func flip(data []byte, at int) []byte {
	d := bytes.Clone(data)
	d[at] ^= 0x01
	return d
}

// TestVerifyBroken holds each ledger broken in one way to an error that says
// where.
func TestVerifyBroken(t *testing.T) {
	t.Parallel()
	b := validLedger(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	otherPub, _ := other.Public().(ed25519.PublicKey)
	sigSize := ed25519.SignatureSize
	// headerEnd is where the header's metadata ends, which is where record 0
	// starts; prefixEnd where the binary prefix ends.
	prefixEnd := len(Magic) + 1 + len(SchemeEd25519) + 1 + 6 + ed25519.PublicKeySize
	headerEnd := b.offsets[0]

	without := func(i int) []byte {
		d := bytes.Clone(b.data[:b.offsets[i]])
		return append(d, b.data[b.offsets[i+1]:]...)
	}
	swapped := func(i int) []byte {
		d := bytes.Clone(b.data[:b.offsets[i]])
		d = append(d, b.data[b.offsets[i+1]:b.offsets[i+2]]...)
		d = append(d, b.data[b.offsets[i]:b.offsets[i+1]]...)
		return append(d, b.data[b.offsets[i+2]:]...)
	}
	// A record whose open signature names a channel that is closed, signed
	// properly at the end of the valid ledger.
	reuse := func() []byte {
		w := &writer{key: testKey, buf: bytes.Clone(b.data), prev: b.sigs[len(b.sigs)-1]}
		w.record(t, Close, b.sigs[2], nil, false, -1, nil)
		return w.buf
	}
	// A record appended with another key's signature.
	forged := func() []byte {
		w := &writer{key: other, buf: bytes.Clone(b.data), prev: b.sigs[len(b.sigs)-1]}
		w.record(t, Open, nil, nil, false, -1, nil)
		return w.buf
	}
	header := func(edit func(w *writer)) []byte {
		w := newWriter(t, testKey, nil)
		edit(w)
		return w.buf
	}
	tests := []struct {
		name string
		data []byte
		key  ed25519.PublicKey
		want string
	}{
		{"empty", nil, nil, "inside its magic"},
		{"magic", flip(b.data, 0), nil, "the magic is"},
		{"version", flip(b.data, 4), nil, "version 0x00"},
		{"scheme", func() []byte { d := bytes.Clone(b.data); copy(d[5:], "rsa25519"); return d }(), nil, "not one this verifier knows"},
		{"scheme with no null", b.data[:5+3], nil, "no terminating null byte"},
		{"signature size", header(func(w *writer) { w.buf[5+len(SchemeEd25519)+2] = 63 }), nil, "declares a 63-byte signature"},
		{"header signature", flip(b.data, prefixEnd+3), nil, "header: its signature does not verify"},
		{"public key", flip(b.data, prefixEnd-1), nil, "header: its signature does not verify"},
		{"header cut short", b.data[:prefixEnd+sigSize+2], nil, "inside its metadata length"},
		{"metadata length", func() []byte {
			d := bytes.Clone(b.data[:headerEnd])
			binary.BigEndian.PutUint32(d[prefixEnd+sigSize:], math.MaxUint32)
			return d
		}(), nil, "inside its metadata"},
		{"record signature", flip(b.data, b.offsets[3]+1+2*sigSize+8+5), nil, "record 3 (checkpoint, at byte"},
		{"payload size", flip(b.data, b.offsets[5]+1+2*sigSize+7), nil, "record 5 (close"},
		{"hash block", flip(b.data, b.offsets[5]+1+2*sigSize+8), nil, "record 5 (close"},
		{"record type", func() []byte { d := bytes.Clone(b.data); d[b.offsets[4]] = 0x05; return d }(), nil, "record type 0x05 is not one of version 1"},
		{"a record removed", without(3), nil, "record 3 (checkpoint, at byte " + strconv.Itoa(b.offsets[3]) + "): its previous signature"},
		{"two records swapped", swapped(3), nil, "record 3 (checkpoint, at byte " + strconv.Itoa(b.offsets[3]) + "): its previous signature"},
		{"a closed channel used again", reuse(), nil, "record 8 (close, at byte " + strconv.Itoa(len(b.data)) + "): its open signature names no open channel"},
		{"a record of another key", forged(), nil, "record 8 (open, at byte " + strconv.Itoa(len(b.data)) + "): its signature does not verify"},
		{"another key than the reply's", b.data, otherPub, "the ledger's public key is not the expected key"},
		{"no payload size's absolute value", func() []byte {
			w := &writer{key: testKey, buf: bytes.Clone(b.data), prev: b.sigs[len(b.sigs)-1]}
			at := len(w.buf)
			w.record(t, Open, nil, nil, false, -1, nil)
			binary.BigEndian.PutUint64(w.buf[at+1+sigSize:], 1<<63)
			return w.buf
		}(), nil, "has no absolute value"},
	}
	for _, tt := range tests {
		_, err := Verify(tt.data, tt.key)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Verify = %v, want an error containing %q", tt.name, err, tt.want)
		}
	}
	if _, err := Verify(b.data, otherPub); !errors.Is(err, ErrKey) {
		t.Errorf("Verify under another key = %v, want ErrKey", err)
	}
}

// TestVerifyTruncated reads a ledger cut short inside each record as valid
// up to its last whole record.
func TestVerifyTruncated(t *testing.T) {
	t.Parallel()
	b := validLedger(t)
	for i := range b.offsets {
		for _, cut := range []int{1, 70, 140} {
			end := b.offsets[i] + cut
			if i+1 < len(b.offsets) && end >= b.offsets[i+1] {
				continue
			}
			if end >= len(b.data) {
				continue
			}
			l, err := Verify(b.data[:end], pub(t))
			if err != nil {
				t.Errorf("cut %d bytes into record %d: %v", cut, i, err)
				continue
			}
			if len(l.Records) != i || l.Truncated != cut {
				t.Errorf("cut %d bytes into record %d: %d records, Truncated %d", cut, i, len(l.Records), l.Truncated)
			}
		}
	}
	// Cut after record 2, the GET's open: its channel is unclosed.
	l, err := Verify(b.data[:b.offsets[3]], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Unclosed) != 1 || l.Unclosed[0] != 2 {
		t.Errorf("Unclosed = %v, want [2]", l.Unclosed)
	}
}

// TestMetadataIsNotSigned verifies a ledger whose metadata was redacted,
// stripped or spoilt, as the format's Redactability section allows, and
// carries the spoilt metadata's error on its record.
func TestMetadataIsNotSigned(t *testing.T) {
	t.Parallel()
	w := newWriter(t, testKey, nil)
	o := w.record(t, Open, nil, nil, false, 4, map[string]any{"owner": "build.example.com"})
	w.record(t, Checkpoint, o, reqHeaders, true, -1, nil)
	at := len(w.buf)
	w.record(t, Close, o, respBody, false, 2, map[string]any{"status": int64(200)})
	// Spoil the close's CBOR: the head of the status's value, 0x18, becomes
	// the reserved 0x1c.
	w.buf[len(w.buf)-2] = 0x1c
	l, err := Verify(w.buf, pub(t))
	if err != nil {
		t.Fatal(err)
	}
	if r := l.Records[0]; r.Schema != SchemaRedacted || r.Metadata["owner"] != "build.example.com" {
		t.Errorf("record 0: %s %v", r.Schema, r.Metadata)
	}
	if r := l.Records[1]; r.SchemaIndex != NoMetadata || r.Metadata != nil {
		t.Errorf("record 1: index %d, %v", r.SchemaIndex, r.Metadata)
	}
	if r := l.Records[2]; r.Offset != at || r.MetadataErr == nil {
		t.Errorf("record 2 at %d: MetadataErr %v, want an error", r.Offset, r.MetadataErr)
	}
}

// TestCheckPayload holds the hash block and the size against the bytes, and
// the header's hashes list against its declared size.
func TestCheckPayload(t *testing.T) {
	t.Parallel()
	b := validLedger(t)
	l, err := Verify(b.data, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := l.Records[5]
	if err := l.CheckPayload(body, []byte("hellO")); err == nil || !strings.Contains(err.Error(), "hash block is") {
		t.Errorf("another body: %v", err)
	}
	if err := l.CheckPayload(body, []byte("hello!")); err == nil || !strings.Contains(err.Error(), "6 bytes, where the record states 5") {
		t.Errorf("a longer body: %v", err)
	}
	if err := l.CheckPayload(l.Records[0], nil); err != nil {
		t.Errorf("an open record with no payload: %v", err)
	}
	for _, tt := range []struct {
		hashes []string
		want   string
	}{
		{[]string{"blake2b_256", "sha256", "sha1", "md4"}, `the hash "md4"`},
		{[]string{"blake2b_256", "sha256"}, "make a 64-byte block, where it declares 100"},
		{nil, "names no hashes"},
	} {
		h := l.Header
		h.Hashes = tt.hashes
		if _, err := h.HashBlock(respBody); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("hashes %v: %v, want %q", tt.hashes, err, tt.want)
		}
	}
}

// TestParseKey reads the reply's form of the key and nothing else.
func TestParseKey(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("0a", 32)
	if _, err := ParseKey(good); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"", good[:62], strings.ToUpper(good), good[:62] + "zz"} {
		if _, err := ParseKey(s); err == nil {
			t.Errorf("ParseKey(%q) succeeded", s)
		}
	}
}
