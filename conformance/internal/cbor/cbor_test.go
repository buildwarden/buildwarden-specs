package cbor

import (
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
)

// TestDecode reads examples of RFC 8949's Appendix A, and the forms a
// ledger's metadata takes.
func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		hex  string
		want any
	}{
		{"00", int64(0)},
		{"17", int64(23)},
		{"1818", int64(24)},
		{"1903e8", int64(1000)},
		{"1b000000e8d4a51000", int64(1000000000000)},
		{"1bffffffffffffffff", uint64(math.MaxUint64)},
		{"20", int64(-1)},
		{"3903e7", int64(-1000)},
		{"f90000", float64(0)},
		{"f93c00", float64(1)},
		{"f97bff", float64(65504)},
		{"fa47c35000", float64(100000)},
		{"fb3ff199999999999a", 1.1},
		{"f4", false},
		{"f5", true},
		{"f6", nil},
		{"f7", Undefined{}},
		{"f0", Simple(16)},
		{"f8ff", Simple(255)},
		{"c11a514b67b0", Tag{Number: 1, Content: int64(1363896240)}},
		{"4401020304", []byte{1, 2, 3, 4}},
		{"6449455446", "IETF"},
		{"62c3bc", "ü"},
		{"80", []any{}},
		{"83010203", []any{int64(1), int64(2), int64(3)}},
		{"a0", map[string]any{}},
		{"a26161016162820203", map[string]any{"a": int64(1), "b": []any{int64(2), int64(3)}}},
		{"5f42010243030405ff", []byte{1, 2, 3, 4, 5}},
		{"7f657374726561646d696e67ff", "streaming"},
		{"9f018202039f0405ffff", []any{int64(1), []any{int64(2), int64(3)}, []any{int64(4), int64(5)}}},
		{"bf61610161629f0203ffff", map[string]any{"a": int64(1), "b": []any{int64(2), int64(3)}}},
	}
	for _, tt := range tests {
		b, err := hex.DecodeString(tt.hex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Errorf("Decode(%s): %v", tt.hex, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Decode(%s) = %#v, want %#v", tt.hex, got, tt.want)
		}
	}
}

// TestDecodeErrors holds each malformed item to an error that says what is
// wrong with it.
func TestDecodeErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, hex, want string
	}{
		{"empty", "", "the data ends"},
		{"trailing bytes", "0000", "1 bytes after the data item"},
		{"short argument", "19", "runs past the end"},
		{"short string", "4401", "runs past the end"},
		{"reserved information", "1c", "reserved additional information"},
		{"indefinite integer", "1f", "indefinite length"},
		{"bad UTF-8", "61ff", "not UTF-8"},
		{"integer key", "a10102", "not a text string"},
		{"repeated key", "a2616101616102", "given twice"},
		{"lone break", "ff", "unexpected break"},
		{"break as a map value", "bf6161ff", "a break where an item was expected"},
		{"mixed chunks", "5f6161ff", "not a definite-length string of its type"},
		{"negative below int64", "3bffffffffffffffff", "below the range of int64"},
		{"simple value in two bytes", "f818", "in two bytes"},
	}
	for _, tt := range tests {
		b, err := hex.DecodeString(tt.hex)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Decode(b)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Decode(%s) = %v, want an error containing %q", tt.name, tt.hex, err, tt.want)
		}
	}
	deep := strings.Repeat("81", maxDepth+2) + "00"
	b, _ := hex.DecodeString(deep)
	if _, err := Decode(b); err == nil || !strings.Contains(err.Error(), "nest deeper") {
		t.Errorf("Decode of deep nesting = %v, want the depth error", err)
	}
	if _, err := DecodeMap([]byte{0x80}); err == nil || !strings.Contains(err.Error(), "an array, not a map") {
		t.Errorf("DecodeMap of an array = %v", err)
	}
}

// TestEncode writes the canonical form: shortest lengths, map keys sorted
// by their encoded bytes, and reads it back.
func TestEncode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v    any
		want string
	}{
		{0, "00"},
		{int64(24), "1818"},
		{int64(-1000), "3903e7"},
		{uint64(math.MaxUint64), "1bffffffffffffffff"},
		{"IETF", "6449455446"},
		{[]byte{1, 2}, "420102"},
		{nil, "f6"},
		{true, "f5"},
		{[]string{"a", "b"}, "8261616162"},
		{[][]string{{"X-A", "1"}}, "818263582d416131"},
		{map[string]any{"bb": int64(1), "a": int64(2), "c": int64(3)}, "a3616102616303626262" + "01"},
		{Tag{Number: 1, Content: int64(0)}, "c100"},
		{1.5, "fb3ff8000000000000"},
	}
	for _, tt := range tests {
		got, err := Encode(tt.v)
		if err != nil {
			t.Errorf("Encode(%#v): %v", tt.v, err)
			continue
		}
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("Encode(%#v) = %x, want %s", tt.v, got, tt.want)
		}
		if _, err := Decode(got); err != nil {
			t.Errorf("Decode(Encode(%#v)): %v", tt.v, err)
		}
	}
	if _, err := Encode(struct{}{}); err == nil {
		t.Error("Encode of a struct succeeded")
	}
	if _, err := Encode("\xff"); err == nil {
		t.Error("Encode of text that is not UTF-8 succeeded")
	}
}
