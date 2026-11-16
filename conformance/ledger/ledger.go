// Package ledger is the harness's ledger verifier. It reads a build ledger
// as the ledger format's document states it and checks the header, every
// record's signature and its place in the chain, and the hash blocks, and it
// reads the record metadata the cases need by the names the metadata
// schemas' documents give their fields.
//
// It is written from buildwarden/buildwarden's specs/build-ledger/v1.md (the
// ledger wire format, version 1) and the documents
// specs/metadata-<name>/v1.md, as they are at commit
// 623131ad49590a65c679f0f9d949f3cd96f0abac of that repository (where
// build-ledger/v1.md last changed at 3ce5b15 and metadata-http-body/v1.md at
// 353e8a7). It holds no copy of a document or of a schema: validating
// metadata against the schemas stays with that repository until the format
// moves here (seam 4, at M6). A change to those documents that changes what
// a ledger may hold changes this package, and the comment above names the
// new commit.
//
// What the format leaves to a reader, and how this package reads it:
//
//   - The signature scheme it verifies is ed25519-sha512, a 32-byte key and
//     64-byte signatures over the SHA-512 digest of each signature input.
//     The format also names rsa-pkcs1v15-sha512 without saying how its
//     public key is laid out; a ledger that declares it, or any other
//     scheme, is refused as one this verifier does not know.
//   - Each record's open signature must be the signature of an open record
//     whose channel no close or artifact record has closed yet, and a
//     channel is closed once: the open signature names the channel.
//   - A ledger whose bytes end inside a record verifies up to its last whole
//     record, which is how a ledger cut short is read (collector-outputs,
//     COLLOUT-34); Ledger.Truncated says so. One that ends inside its header
//     is an error.
//   - Metadata is outside every signature, so metadata that does not decode
//     never fails verification: the record carries the decoding's error.
package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/cbor"
)

// Magic and Version open every ledger of version 1.
const (
	Magic   = "BLDL"
	Version = 0x01
)

// SchemeEd25519 is the one signature scheme this verifier knows.
const SchemeEd25519 = "ed25519-sha512"

// NoMetadata is the schema index of a record that carries no metadata.
const NoMetadata = 255

// Type is a record's type.
type Type byte

// The record types of version 1.
const (
	Open       Type = 0x01
	Checkpoint Type = 0x02
	Close      Type = 0x03
	Artifact   Type = 0x04
)

func (t Type) String() string {
	switch t {
	case Open:
		return "open"
	case Checkpoint:
		return "checkpoint"
	case Close:
		return "close"
	case Artifact:
		return "artifact"
	}
	return fmt.Sprintf("type 0x%02x", byte(t))
}

// The $ids of the default metadata schemas, by which the header's schemas
// list names them and a record's schema index points to one.
const (
	SchemaHTTPOpen             = "https://github.com/buildwarden/buildwarden/schemas/v1/http-open.json"
	SchemaHTTPHeaders          = "https://github.com/buildwarden/buildwarden/schemas/v1/http-headers.json"
	SchemaHTTPBody             = "https://github.com/buildwarden/buildwarden/schemas/v1/http-body.json"
	SchemaArtifact             = "https://github.com/buildwarden/buildwarden/schemas/v1/artifact.json"
	SchemaRedacted             = "https://github.com/buildwarden/buildwarden/schemas/v1/redacted.json"
	SchemaEnvironment          = "https://github.com/buildwarden/buildwarden/schemas/v1/environment.json"
	SchemaEnvironmentContainer = "https://github.com/buildwarden/buildwarden/schemas/v1/environment-container.json"
)

// Header is a ledger's header.
type Header struct {
	Version byte
	Scheme  string
	// SigSize and HashBlockSize are the sizes the header declares.
	SigSize       int
	HashBlockSize int
	PublicKey     []byte
	// Signature is the header's signature over its binary prefix, the
	// chain's root.
	Signature []byte
	// MetadataRaw is the header's CBOR metadata, and Metadata it decoded,
	// or MetadataErr why it did not decode as a map.
	MetadataRaw []byte
	Metadata    map[string]any
	MetadataErr error
	// Hashes and Schemas are the metadata's lists of hash algorithm names
	// and schema $ids, as far as they could be read.
	Hashes  []string
	Schemas []string
}

// Record is one record of a ledger.
type Record struct {
	// Index is the record's position, from 0, and Offset where it starts
	// in the ledger's bytes.
	Index  int
	Offset int
	Type   Type
	// PrevSig and OpenSig are the signatures the record names; OpenSig is
	// empty on an open record.
	PrevSig []byte
	OpenSig []byte
	// PayloadSize is the signed payload size: positive into the build,
	// negative out of it. HashBlock is empty when it is 0.
	PayloadSize int64
	HashBlock   []byte
	Signature   []byte
	// Channel is the index of the open record of the record's channel; an
	// open record's is its own.
	Channel int
	// SchemaIndex is NoMetadata or an index into the header's schemas, and
	// Schema the $id there, empty when the list has no such entry.
	SchemaIndex int
	Schema      string
	// MetadataRaw is the record's CBOR metadata, and Metadata it decoded,
	// or MetadataErr why it did not decode as a map.
	MetadataRaw []byte
	Metadata    map[string]any
	MetadataErr error
}

// Size is the payload's length in bytes.
func (r Record) Size() int64 {
	if r.PayloadSize < 0 {
		return -r.PayloadSize
	}
	return r.PayloadSize
}

// Text is the text field name of the record's metadata, and whether it has
// one.
func (r Record) Text(name string) (string, bool) {
	s, ok := r.Metadata[name].(string)
	return s, ok
}

// Int is the integer field name of the record's metadata, and whether it has
// one in the range of int64.
func (r Record) Int(name string) (int64, bool) {
	n, ok := r.Metadata[name].(int64)
	return n, ok
}

// Ledger is a verified ledger.
type Ledger struct {
	Header  Header
	Records []Record
	// Truncated is the number of bytes after the last whole record: a
	// ledger cut short inside a record.
	Truncated int
	// Unclosed are the indexes of the open records whose channel is still
	// open; a complete ledger has none.
	Unclosed []int
}

// ParseKey reads a public key as a claim's reply gives it,
// ledger_public_key: 64 lower-case hexadecimal digits.
func ParseKey(s string) (ed25519.PublicKey, error) {
	if len(s) != 2*ed25519.PublicKeySize {
		return nil, fmt.Errorf("ledger key: %d characters, want %d hexadecimal digits", len(s), 2*ed25519.PublicKeySize)
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return nil, fmt.Errorf("ledger key: %q is not lower-case hexadecimal", c)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ledger key: %w", err)
	}
	return ed25519.PublicKey(b), nil
}

// ErrKey is wrapped by Verify's error when the ledger's key is not the key
// it was to be verified under.
var ErrKey = errors.New("the ledger's public key is not the expected key")

// Verify reads data as a ledger and verifies it. When key is not nil, the
// header's public key must be key: a ledger verifies under the key a claim's
// reply names, not merely under its own. The error names the record and the
// byte offset where verification failed.
func Verify(data []byte, key ed25519.PublicKey) (*Ledger, error) {
	r := reader{b: data}
	h, err := readHeader(&r)
	if err != nil {
		return nil, err
	}
	if key != nil && !bytes.Equal(h.PublicKey, key) {
		return nil, fmt.Errorf("%w: the header holds %x, expected %x", ErrKey, h.PublicKey, []byte(key))
	}
	l := &Ledger{Header: h}
	prev := h.Signature
	// open maps the signature of each open record whose channel is open to
	// that record's index.
	open := map[string]int{}
	var order []string
	for r.off < len(data) {
		rec, whole, err := readRecord(&r, h, len(l.Records))
		if err != nil {
			return nil, err
		}
		if !whole {
			l.Truncated = len(data) - rec.Offset
			break
		}
		at := fmt.Sprintf("record %d (%s, at byte %d)", rec.Index, rec.Type, rec.Offset)
		if !bytes.Equal(rec.PrevSig, prev) {
			return nil, fmt.Errorf("%s: its previous signature is not the signature of the record before it: the chain is broken", at)
		}
		if !ed25519.Verify(h.PublicKey, digest(signatureInput(rec)), rec.Signature) {
			return nil, fmt.Errorf("%s: its signature does not verify under the header's key", at)
		}
		switch rec.Type {
		case Open:
			rec.Channel = rec.Index
			sig := string(rec.Signature)
			if _, dup := open[sig]; dup {
				return nil, fmt.Errorf("%s: its signature is that of an open record whose channel is still open", at)
			}
			open[sig] = rec.Index
			order = append(order, sig)
		default:
			ch, ok := open[string(rec.OpenSig)]
			if !ok {
				return nil, fmt.Errorf("%s: its open signature names no open channel", at)
			}
			rec.Channel = ch
			if rec.Type == Close || rec.Type == Artifact {
				delete(open, string(rec.OpenSig))
			}
		}
		prev = rec.Signature
		l.Records = append(l.Records, rec)
	}
	for _, sig := range order {
		if i, ok := open[sig]; ok {
			l.Unclosed = append(l.Unclosed, i)
		}
	}
	return l, nil
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.b)-r.off {
		return nil, false
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s, true
}

func (r *reader) uint(n int) (uint64, bool) {
	s, ok := r.take(n)
	if !ok {
		return 0, false
	}
	var v uint64
	for _, c := range s {
		v = v<<8 | uint64(c)
	}
	return v, true
}

func readHeader(r *reader) (Header, error) {
	var h Header
	short := func(what string) error {
		return fmt.Errorf("header: the ledger ends at byte %d, inside its %s", len(r.b), what)
	}
	magic, ok := r.take(len(Magic))
	if !ok {
		return h, short("magic")
	}
	if string(magic) != Magic {
		return h, fmt.Errorf("header: the magic is %q, not %q", magic, Magic)
	}
	v, ok := r.take(1)
	if !ok {
		return h, short("version")
	}
	h.Version = v[0]
	if h.Version != Version {
		return h, fmt.Errorf("header: version 0x%02x, where this verifier reads version 0x%02x", h.Version, Version)
	}
	end := bytes.IndexByte(r.b[r.off:], 0)
	if end < 0 {
		return h, short("signature scheme, which has no terminating null byte")
	}
	scheme, _ := r.take(end + 1)
	h.Scheme = string(scheme[:end])
	sizes := [3]uint64{}
	for i := range sizes {
		if sizes[i], ok = r.uint(2); !ok {
			return h, short("sizes")
		}
	}
	h.SigSize, h.HashBlockSize = int(sizes[0]), int(sizes[1])
	if h.PublicKey, ok = r.take(int(sizes[2])); !ok {
		return h, short("public key")
	}
	prefix := r.b[:r.off]
	if h.Scheme != SchemeEd25519 {
		return h, fmt.Errorf("header: the signature scheme %q is not one this verifier knows (%s)", h.Scheme, SchemeEd25519)
	}
	if h.SigSize != ed25519.SignatureSize || len(h.PublicKey) != ed25519.PublicKeySize {
		return h, fmt.Errorf("header: %s declares a %d-byte signature and a %d-byte key, where the scheme has %d and %d", h.Scheme, h.SigSize, len(h.PublicKey), ed25519.SignatureSize, ed25519.PublicKeySize)
	}
	if h.Signature, ok = r.take(h.SigSize); !ok {
		return h, short("signature")
	}
	if !ed25519.Verify(h.PublicKey, digest(prefix), h.Signature) {
		return h, errors.New("header: its signature does not verify under its own key")
	}
	n, ok := r.uint(4)
	if !ok {
		return h, short("metadata length")
	}
	if h.MetadataRaw, ok = r.take(int(n)); !ok {
		return h, short("metadata")
	}
	h.Metadata, h.MetadataErr = cbor.DecodeMap(h.MetadataRaw)
	h.Hashes, _ = texts(h.Metadata["hashes"])
	h.Schemas, _ = texts(h.Metadata["schemas"])
	return h, nil
}

func texts(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// readRecord reads the record at r's offset. whole is false when the ledger
// ends inside it, and the record then has only its Index and Offset.
func readRecord(r *reader, h Header, index int) (rec Record, whole bool, err error) {
	rec = Record{Index: index, Offset: r.off, SchemaIndex: NoMetadata}
	at := func() string { return fmt.Sprintf("record %d (at byte %d)", index, rec.Offset) }
	t, _ := r.take(1)
	rec.Type = Type(t[0])
	if rec.Type < Open || rec.Type > Artifact {
		return rec, false, fmt.Errorf("%s: record type 0x%02x is not one of version 1", at(), t[0])
	}
	var ok bool
	if rec.PrevSig, ok = r.take(h.SigSize); !ok {
		return rec, false, nil
	}
	if rec.Type != Open {
		if rec.OpenSig, ok = r.take(h.SigSize); !ok {
			return rec, false, nil
		}
	}
	size, ok := r.uint(8)
	if !ok {
		return rec, false, nil
	}
	rec.PayloadSize = int64(size)
	if rec.PayloadSize == math.MinInt64 {
		return rec, false, fmt.Errorf("%s: payload size %d has no absolute value", at(), rec.PayloadSize)
	}
	if rec.PayloadSize != 0 {
		if rec.HashBlock, ok = r.take(h.HashBlockSize); !ok {
			return rec, false, nil
		}
	}
	if rec.Signature, ok = r.take(h.SigSize); !ok {
		return rec, false, nil
	}
	idx, ok := r.take(1)
	if !ok {
		return rec, false, nil
	}
	rec.SchemaIndex = int(idx[0])
	if rec.SchemaIndex != NoMetadata {
		n, ok := r.uint(4)
		if !ok {
			return rec, false, nil
		}
		if rec.MetadataRaw, ok = r.take(int(n)); !ok {
			return rec, false, nil
		}
		if rec.SchemaIndex < len(h.Schemas) {
			rec.Schema = h.Schemas[rec.SchemaIndex]
		}
		rec.Metadata, rec.MetadataErr = cbor.DecodeMap(rec.MetadataRaw)
	}
	return rec, true, nil
}

// signatureInput is what a record's signature signs: its type, its previous
// signature, its open signature unless it is an open record, its payload
// size, and its hash block when the size is not 0.
func signatureInput(rec Record) []byte {
	var b []byte
	b = append(b, byte(rec.Type))
	b = append(b, rec.PrevSig...)
	if rec.Type != Open {
		b = append(b, rec.OpenSig...)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(rec.PayloadSize))
	if rec.PayloadSize != 0 {
		b = append(b, rec.HashBlock...)
	}
	return b
}

func digest(input []byte) []byte {
	d := sha512.Sum512(input)
	return d[:]
}
