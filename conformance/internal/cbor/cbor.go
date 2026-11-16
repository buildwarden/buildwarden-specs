// Package cbor reads and writes the CBOR (RFC 8949) of a ledger's metadata:
// the header's metadata map and each record's. It is the harness's own, so
// that the ledger verifier shares no decoder with a ledger's writer.
//
// Decode gives each data item as a Go value:
//
//	unsigned and negative integers  int64, or uint64 above the range of int64
//	byte strings                    []byte
//	text strings                    string
//	arrays                          []any
//	maps                            map[string]any; a key that is not a text
//	                                string, or a key given twice, is an error
//	tags                            Tag
//	false, true                     bool
//	null                            nil
//	undefined                       Undefined
//	other simple values             Simple
//	floating-point numbers          float64
//
// Indefinite-length strings, arrays and maps are read. Encode writes the
// same values back, with definite lengths only, each length in its shortest
// form and each map's keys in the order of their encoded bytes (RFC 8949,
// section 4.2.1), so that a value has one encoding.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"
)

// Tag is a tagged data item: its tag number and the item it tags.
type Tag struct {
	Number  uint64
	Content any
}

// Undefined is the simple value undefined.
type Undefined struct{}

// Simple is a simple value other than false, true, null and undefined.
type Simple uint8

// maxDepth bounds how deeply arrays, maps and tags may nest, so that a
// hostile item cannot exhaust the stack.
const maxDepth = 64

// Decode reads exactly one data item from b, and is an error when anything
// follows it.
func Decode(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, fmt.Errorf("cbor: %d bytes after the data item", len(b)-d.off)
	}
	return v, nil
}

// DecodeMap reads exactly one data item from b, which must be a map.
func DecodeMap(b []byte) (map[string]any, error) {
	v, err := Decode(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cbor: the data item is %s, not a map", kind(v))
	}
	return m, nil
}

// errBreak is the "break" stop code, returned by item to the indefinite-length
// item that is reading its contents.
var errBreak = errors.New("cbor: unexpected break")

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) byte() (byte, error) {
	if d.off >= len(d.b) {
		return 0, fmt.Errorf("cbor: the data ends at byte %d inside an item", d.off)
	}
	c := d.b[d.off]
	d.off++
	return c, nil
}

func (d *decoder) bytes(n uint64) ([]byte, error) {
	if n > uint64(len(d.b)-d.off) {
		return nil, fmt.Errorf("cbor: an item of %d bytes at byte %d runs past the end of the data", n, d.off)
	}
	s := d.b[d.off : d.off+int(n)]
	d.off += int(n)
	return s, nil
}

// head reads an item's initial byte and its argument. Additional information
// 31, an indefinite length or the break stop code, has no argument.
func (d *decoder) head() (major byte, info byte, arg uint64, err error) {
	c, err := d.byte()
	if err != nil {
		return 0, 0, 0, err
	}
	major, info = c>>5, c&0x1f
	switch {
	case info < 24:
		return major, info, uint64(info), nil
	case info <= 27:
		n := 1 << (info - 24)
		s, err := d.bytes(uint64(n))
		if err != nil {
			return 0, 0, 0, err
		}
		var v uint64
		for _, x := range s {
			v = v<<8 | uint64(x)
		}
		return major, info, v, nil
	case info == 31:
		return major, info, 0, nil
	}
	return 0, 0, 0, fmt.Errorf("cbor: reserved additional information %d at byte %d", info, d.off-1)
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("cbor: items nest deeper than %d", maxDepth)
	}
	start := d.off
	major, info, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	indefinite := info == 31
	switch major {
	case 0:
		if indefinite {
			return nil, fmt.Errorf("cbor: an integer at byte %d has indefinite length", start)
		}
		if arg > math.MaxInt64 {
			return arg, nil
		}
		return int64(arg), nil
	case 1:
		if indefinite {
			return nil, fmt.Errorf("cbor: an integer at byte %d has indefinite length", start)
		}
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("cbor: the negative integer at byte %d is below the range of int64", start)
		}
		return -1 - int64(arg), nil
	case 2, 3:
		s, err := d.str(major, indefinite, arg, depth)
		if err != nil {
			return nil, err
		}
		if major == 2 {
			return s, nil
		}
		if !utf8.Valid(s) {
			return nil, fmt.Errorf("cbor: the text string at byte %d is not UTF-8", start)
		}
		return string(s), nil
	case 4:
		a := []any{}
		for i := uint64(0); indefinite || i < arg; i++ {
			v, err := d.item(depth + 1)
			if indefinite && errors.Is(err, errBreak) {
				break
			}
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case 5:
		m := map[string]any{}
		for i := uint64(0); indefinite || i < arg; i++ {
			at := d.off
			k, err := d.item(depth + 1)
			if indefinite && errors.Is(err, errBreak) {
				break
			}
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("cbor: the map key at byte %d is %s, not a text string", at, kind(k))
			}
			if _, dup := m[ks]; dup {
				return nil, fmt.Errorf("cbor: the map key %q at byte %d is given twice", ks, at)
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, notBreak(err)
			}
			m[ks] = v
		}
		return m, nil
	case 6:
		if indefinite {
			return nil, fmt.Errorf("cbor: a tag at byte %d has indefinite length", start)
		}
		v, err := d.item(depth + 1)
		if err != nil {
			return nil, notBreak(err)
		}
		return Tag{Number: arg, Content: v}, nil
	}
	// Major type 7: simple values, floats and the break stop code.
	switch info {
	case 20:
		return false, nil
	case 21:
		return true, nil
	case 22:
		return nil, nil
	case 23:
		return Undefined{}, nil
	case 24:
		if arg < 32 {
			return nil, fmt.Errorf("cbor: the simple value %d at byte %d is in two bytes", arg, start)
		}
		return Simple(arg), nil
	case 25:
		return float64(half(uint16(arg))), nil
	case 26:
		return float64(math.Float32frombits(uint32(arg))), nil
	case 27:
		return math.Float64frombits(arg), nil
	case 31:
		return nil, errBreak
	}
	return Simple(arg), nil
}

// str reads a byte or text string's bytes; an indefinite-length one is the
// concatenation of definite-length chunks of its own major type.
func (d *decoder) str(major byte, indefinite bool, arg uint64, depth int) ([]byte, error) {
	if !indefinite {
		s, err := d.bytes(arg)
		if err != nil {
			return nil, err
		}
		return bytes.Clone(s), nil
	}
	var out []byte
	for {
		at := d.off
		m, info, n, err := d.head()
		if err != nil {
			return nil, err
		}
		if m == 7 && info == 31 {
			return out, nil
		}
		if m != major || info == 31 {
			return nil, fmt.Errorf("cbor: the chunk at byte %d of an indefinite-length string is not a definite-length string of its type", at)
		}
		s, err := d.bytes(n)
		if err != nil {
			return nil, err
		}
		out = append(out, s...)
	}
}

func notBreak(err error) error {
	if errors.Is(err, errBreak) {
		return errors.New("cbor: a break where an item was expected")
	}
	return err
}

// half converts an IEEE 754 half-precision number.
func half(h uint16) float32 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1f
	frac := uint32(h & 0x3ff)
	switch exp {
	case 0:
		f := float32(frac) / 1024 * float32(math.Pow(2, -14))
		if sign != 0 {
			return -f
		}
		return f
	case 0x1f:
		return math.Float32frombits(sign | 0xff<<23 | frac<<13)
	}
	return math.Float32frombits(sign | (exp+127-15)<<23 | frac<<13)
}

func kind(v any) string {
	switch v.(type) {
	case int64, uint64:
		return "an integer"
	case []byte:
		return "a byte string"
	case string:
		return "a text string"
	case []any:
		return "an array"
	case map[string]any:
		return "a map"
	case Tag:
		return "a tagged item"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	case Undefined:
		return "undefined"
	case float64:
		return "a floating-point number"
	}
	return "a simple value"
}

// Encode writes v as one data item. It takes the values Decode gives, and
// also int, []string and [][]string, so that a caller can write metadata
// such as http-headers' list of pairs without converting it first.
func Encode(v any) ([]byte, error) {
	var b []byte
	return appendItem(b, v, 0)
}

func appendHead(b []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(b, m|byte(arg))
	case arg <= math.MaxUint8:
		return append(b, m|24, byte(arg))
	case arg <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(arg))
	case arg <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(arg))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), arg)
}

func appendInt(b []byte, n int64) []byte {
	if n >= 0 {
		return appendHead(b, 0, uint64(n))
	}
	return appendHead(b, 1, uint64(-1-n))
}

func appendItem(b []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("cbor: values nest deeper than %d", maxDepth)
	}
	switch x := v.(type) {
	case nil:
		return append(b, 0xf6), nil
	case Undefined:
		return append(b, 0xf7), nil
	case bool:
		if x {
			return append(b, 0xf5), nil
		}
		return append(b, 0xf4), nil
	case Simple:
		if x < 24 {
			return append(b, 0xe0|byte(x)), nil
		}
		if x < 32 {
			return nil, fmt.Errorf("cbor: the simple value %d is reserved", x)
		}
		return append(b, 0xf8, byte(x)), nil
	case int:
		return appendInt(b, int64(x)), nil
	case int64:
		return appendInt(b, x), nil
	case uint64:
		return appendHead(b, 0, x), nil
	case float64:
		return binary.BigEndian.AppendUint64(append(b, 0xfb), math.Float64bits(x)), nil
	case []byte:
		return append(appendHead(b, 2, uint64(len(x))), x...), nil
	case string:
		if !utf8.ValidString(x) {
			return nil, fmt.Errorf("cbor: the text %q is not UTF-8", x)
		}
		return append(appendHead(b, 3, uint64(len(x))), x...), nil
	case []string:
		b = appendHead(b, 4, uint64(len(x)))
		for _, s := range x {
			var err error
			if b, err = appendItem(b, s, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case [][]string:
		b = appendHead(b, 4, uint64(len(x)))
		for _, s := range x {
			var err error
			if b, err = appendItem(b, s, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case []any:
		b = appendHead(b, 4, uint64(len(x)))
		for _, e := range x {
			var err error
			if b, err = appendItem(b, e, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case map[string]any:
		type entry struct{ k, v []byte }
		entries := make([]entry, 0, len(x))
		for k, e := range x {
			kb, err := appendItem(nil, k, depth+1)
			if err != nil {
				return nil, err
			}
			vb, err := appendItem(nil, e, depth+1)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{kb, vb})
		}
		slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.k, b.k) })
		b = appendHead(b, 5, uint64(len(x)))
		for _, e := range entries {
			b = append(append(b, e.k...), e.v...)
		}
		return b, nil
	case Tag:
		return appendItem(appendHead(b, 6, x.Number), x.Content, depth+1)
	}
	return nil, fmt.Errorf("cbor: cannot encode a value of type %T", v)
}
