// Package ledgerwriter is the harness's ledger writer: the ledger the
// harness's relay signs and streams to its collector. It writes a build
// ledger as the ledger format's document lays it out, the header with its
// signature and metadata and then each record, every record in one Write so
// that whoever reads the stream sees whole records or a record cut short.
//
// It is written from buildwarden/buildwarden's specs/build-ledger/v1.md and
// the documents specs/metadata-<name>/v1.md at the commit the verifier's
// package comment names, 623131ad49590a65c679f0f9d949f3cd96f0abac, and holds
// no copy of them. It shares no code with the verifier (package ledger)
// beyond the CBOR encoder: the layout, the signature input and the hash
// block are written here again, so that a ledger this package writes and the
// verifier accepts shows two readings of the document agreeing.
//
// What the format leaves to a writer, and how this one writes it:
//
//   - The scheme is ed25519-sha512: the record is signed by Ed25519 over the
//     SHA-512 digest of its signature input.
//   - The hashes are the default list, blake2b_256, sha256, sha1 and md5, a
//     100-byte hash block, and the schemas the six default ones in the
//     order the document's table gives them.
//   - The header metadata names the environment type only when the ledger
//     will have an environment record.
//   - A record that closes a channel must name an open one, and a channel is
//     closed once; anything else is the caller's mistake and an error,
//     written to nothing.
package ledgerwriter

import (
	"crypto/ed25519"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/buildwarden/buildwarden-specs/conformance/internal/cbor"
)

// The header's binary prefix, as version 1 has it.
const (
	magic     = "BLDL"
	version   = 0x01
	scheme    = "ed25519-sha512"
	blockSize = 32 + 32 + 20 + 16
)

// Hashes are the names of the hash algorithms of every ledger this package
// writes, in the order of their digests in a hash block.
var Hashes = []string{"blake2b_256", "sha256", "sha1", "md5"}

// Schema is a record's schema index: a position in the header's schemas
// list, or None.
type Schema int

// The default schemas, at the indexes this package writes them, and None,
// a record with no metadata.
const (
	HTTPOpen Schema = iota
	HTTPHeaders
	HTTPBody
	ArtifactMeta
	Redacted
	Environment
	None Schema = 255
)

// Schemas are the $ids of the header's schemas list, by index.
var Schemas = []string{
	"https://github.com/buildwarden/buildwarden/schemas/v1/http-open.json",
	"https://github.com/buildwarden/buildwarden/schemas/v1/http-headers.json",
	"https://github.com/buildwarden/buildwarden/schemas/v1/http-body.json",
	"https://github.com/buildwarden/buildwarden/schemas/v1/artifact.json",
	"https://github.com/buildwarden/buildwarden/schemas/v1/redacted.json",
	"https://github.com/buildwarden/buildwarden/schemas/v1/environment.json",
}

// The record types of version 1.
const (
	typeOpen       = 0x01
	typeCheckpoint = 0x02
	typeClose      = 0x03
	typeArtifact   = 0x04
)

// Payload is what a record states about its payload: its signed size,
// positive into the build and negative out of it, and its hash block, which
// a size of 0 has none of.
type Payload struct {
	Size  int64
	Block []byte
}

// Hash computes a payload's hash block as its bytes are written to it, so
// that a body streamed elsewhere is recorded without being kept.
type Hash struct {
	hs []hash.Hash
	n  int64
}

// NewHash is a Hash of no bytes yet.
func NewHash() *Hash {
	b2, _ := blake2b.New256(nil) // fails only for a key over 64 bytes
	return &Hash{hs: []hash.Hash{b2, sha256.New(), sha1.New(), md5.New()}}
}

func (h *Hash) Write(p []byte) (int, error) {
	for _, d := range h.hs {
		d.Write(p)
	}
	h.n += int64(len(p))
	return len(p), nil
}

// Len is the number of bytes written.
func (h *Hash) Len() int64 { return h.n }

// Payload is what was written, as a record states it: into the build, or
// out of it when out is set.
func (h *Hash) Payload(out bool) Payload {
	if h.n == 0 {
		return Payload{}
	}
	var block []byte
	for _, d := range h.hs {
		block = d.Sum(block)
	}
	size := h.n
	if out {
		size = -size
	}
	return Payload{Size: size, Block: block}
}

// In is b as a payload into the build, and Out as one out of it.
func In(b []byte) Payload  { return of(b, false) }
func Out(b []byte) Payload { return of(b, true) }

func of(b []byte, out bool) Payload {
	h := NewHash()
	_, _ = h.Write(b)
	return h.Payload(out)
}

// Channel is an open channel: the signature of its open record.
type Channel []byte

// ErrEnded is the error for a record after End.
var ErrEnded = errors.New("the ledger has ended")

// Writer writes one ledger to w. It is safe for concurrent use: records are
// written in the order their calls take the writer.
type Writer struct {
	mu    sync.Mutex
	w     io.Writer
	key   ed25519.PrivateKey
	prev  []byte
	open  map[string]bool
	ended bool
	err   error
	n     int
}

// New writes the header of a ledger signed with key to w. envType is the
// environment type the header's metadata names, or empty for a ledger that
// will have no environment record.
func New(w io.Writer, key ed25519.PrivateKey, envType string) (*Writer, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ledgerwriter: the key is not an Ed25519 key")
	}
	var b []byte
	b = append(b, magic...)
	b = append(b, version)
	b = append(b, scheme...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, ed25519.SignatureSize)
	b = binary.BigEndian.AppendUint16(b, blockSize)
	b = binary.BigEndian.AppendUint16(b, ed25519.PublicKeySize)
	b = append(b, pub...)
	sig := sign(key, b)
	b = append(b, sig...)
	meta := map[string]any{"hashes": Hashes, "schemas": Schemas}
	if envType != "" {
		meta["environment"] = map[string]any{"type": envType}
	}
	m, err := cbor.Encode(meta)
	if err != nil {
		return nil, fmt.Errorf("ledgerwriter: the header's metadata: %w", err)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(m)))
	b = append(b, m...)
	lw := &Writer{w: w, key: key, prev: sig, open: map[string]bool{}}
	if _, err := w.Write(b); err != nil {
		return nil, fmt.Errorf("ledgerwriter: writing the header: %w", err)
	}
	return lw, nil
}

func sign(key ed25519.PrivateKey, input []byte) []byte {
	d := sha512.Sum512(input)
	return ed25519.Sign(key, d[:])
}

// Open writes an open record with no payload and returns its channel.
func (w *Writer) Open(schema Schema, meta map[string]any) (Channel, error) {
	sig, err := w.record(typeOpen, nil, Payload{}, schema, meta)
	return Channel(sig), err
}

// Checkpoint writes a checkpoint record on ch.
func (w *Writer) Checkpoint(ch Channel, p Payload, schema Schema, meta map[string]any) error {
	_, err := w.record(typeCheckpoint, ch, p, schema, meta)
	return err
}

// Close writes a close record, which closes ch.
func (w *Writer) Close(ch Channel, p Payload, schema Schema, meta map[string]any) error {
	_, err := w.record(typeClose, ch, p, schema, meta)
	return err
}

// Artifact writes an artifact record, which closes ch.
func (w *Writer) Artifact(ch Channel, p Payload, schema Schema, meta map[string]any) error {
	_, err := w.record(typeArtifact, ch, p, schema, meta)
	return err
}

// Records is the number of records written.
func (w *Writer) Records() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

// End takes no more records, and returns the first error of a write.
func (w *Writer) End() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ended = true
	return w.err
}

func (w *Writer) record(typ byte, ch Channel, p Payload, schema Schema, meta map[string]any) ([]byte, error) {
	if (p.Size == 0) != (len(p.Block) == 0) || len(p.Block) != 0 && len(p.Block) != blockSize {
		return nil, fmt.Errorf("ledgerwriter: a payload of %d bytes with a %d-byte hash block", p.Size, len(p.Block))
	}
	if schema != None && (schema < 0 || int(schema) >= len(Schemas)) {
		return nil, fmt.Errorf("ledgerwriter: schema index %d is not in the header's list", schema)
	}
	var m []byte
	if schema != None {
		if meta == nil {
			meta = map[string]any{}
		}
		var err error
		if m, err = cbor.Encode(meta); err != nil {
			return nil, fmt.Errorf("ledgerwriter: a record's metadata: %w", err)
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ended {
		return nil, ErrEnded
	}
	if w.err != nil {
		return nil, w.err
	}
	if typ != typeOpen && !w.open[string(ch)] {
		return nil, errors.New("ledgerwriter: the record names no open channel")
	}
	var b []byte
	b = append(b, typ)
	b = append(b, w.prev...)
	if typ != typeOpen {
		b = append(b, ch...)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(p.Size))
	b = append(b, p.Block...)
	sig := sign(w.key, b)
	b = append(b, sig...)
	b = append(b, byte(schema))
	if schema != None {
		b = binary.BigEndian.AppendUint32(b, uint32(len(m)))
		b = append(b, m...)
	}
	if _, err := w.w.Write(b); err != nil {
		w.err = fmt.Errorf("ledgerwriter: writing a record: %w", err)
		return nil, w.err
	}
	switch typ {
	case typeOpen:
		w.open[string(sig)] = true
	case typeClose, typeArtifact:
		delete(w.open, string(ch))
	}
	w.prev = sig
	w.n++
	return sig, nil
}
