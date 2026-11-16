package ledger

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// hashes are the algorithms a header's hashes list may name, by the names
// the format's document gives them.
var hashes = map[string]func() hash.Hash{
	"blake2b_256": func() hash.Hash {
		h, _ := blake2b.New256(nil) // fails only for a key over 64 bytes
		return h
	},
	"sha256": sha256.New,
	"sha1":   sha1.New,
	"md5":    md5.New,
}

// HashBlock is the hash block of payload under the header: the digests of
// the algorithms its hashes list names, in its order. It is an error when the
// list names an algorithm this verifier does not know, or when the digests'
// sizes do not add up to the header's hash block size.
func (h Header) HashBlock(payload []byte) ([]byte, error) {
	if len(h.Hashes) == 0 {
		if h.MetadataErr != nil {
			return nil, fmt.Errorf("the header's metadata does not decode, so its hashes are not known: %w", h.MetadataErr)
		}
		return nil, errors.New("the header's metadata names no hashes")
	}
	var block []byte
	for _, name := range h.Hashes {
		newHash, ok := hashes[name]
		if !ok {
			return nil, fmt.Errorf("the header names the hash %q, which this verifier does not know", name)
		}
		d := newHash()
		d.Write(payload)
		block = d.Sum(block)
	}
	if len(block) != h.HashBlockSize {
		return nil, fmt.Errorf("the header's hashes %v make a %d-byte block, where it declares %d", h.Hashes, len(block), h.HashBlockSize)
	}
	return block, nil
}

// CheckPayload checks that payload is the payload rec states: its size is
// the record's, and its hash block is the record's.
func (l *Ledger) CheckPayload(rec Record, payload []byte) error {
	at := fmt.Sprintf("record %d (%s)", rec.Index, rec.Type)
	if int64(len(payload)) != rec.Size() {
		return fmt.Errorf("%s: the payload is %d bytes, where the record states %d", at, len(payload), rec.Size())
	}
	if rec.PayloadSize == 0 {
		return nil
	}
	block, err := l.Header.HashBlock(payload)
	if err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	if !bytes.Equal(block, rec.HashBlock) {
		return fmt.Errorf("%s: the payload's hash block is %x, where the record states %x", at, block, rec.HashBlock)
	}
	return nil
}

// PrimaryHash is the hexadecimal of the first hash of rec's hash block, the
// name the format gives its payload's file (payloads/<hash>), or empty when
// the record has no payload or the header's first hash is not known.
func (l *Ledger) PrimaryHash(rec Record) string {
	if rec.PayloadSize == 0 || len(l.Header.Hashes) == 0 {
		return ""
	}
	newHash, ok := hashes[l.Header.Hashes[0]]
	if !ok {
		return ""
	}
	n := newHash().Size()
	if n > len(rec.HashBlock) {
		return ""
	}
	return hex.EncodeToString(rec.HashBlock[:n])
}

// Environment is the ledger's environment record: the close record of the
// channel its first two records open and close on the environment schema
// (or the legacy environment-container schema), whose hash block is the
// environment payload's. ok is false for a ledger that has none.
func (l *Ledger) Environment() (rec Record, ok bool) {
	if len(l.Records) < 2 {
		return Record{}, false
	}
	o, c := l.Records[0], l.Records[1]
	env := func(r Record) bool { return r.Schema == SchemaEnvironment || r.Schema == SchemaEnvironmentContainer }
	if o.Type != Open || c.Type != Close || c.Channel != o.Index || !env(o) || !env(c) {
		return Record{}, false
	}
	return c, true
}
