package runner

import (
	"reflect"
	"testing"
)

func TestT(t *testing.T) {
	var ct T
	if ct.Failed() {
		t.Fatal("a fresh T has failed")
	}
	ct.Errorf("first %d", 1)
	ct.Errorf("second")
	if !ct.Failed() {
		t.Fatal("T has not failed after Errorf")
	}
	want := []string{"first 1", "second"}
	got := ct.Failures()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Failures() = %q, want %q", got, want)
	}
	got[0] = "changed"
	if ct.Failures()[0] != "first 1" {
		t.Fatal("Failures() shares its slice with T")
	}
}
