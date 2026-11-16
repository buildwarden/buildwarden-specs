package coverage

import (
	"strings"
	"testing"

	"github.com/buildwarden/buildwarden-specs/conformance/runner"
	"github.com/buildwarden/buildwarden-specs/conformance/spec"
)

func TestCheck(t *testing.T) {
	s := spec.Spec{Directory: "relay-claim", Prefix: "CLAIM", Document: "v1.md"}
	three := spec.Loaded{
		Version:      "v0.1.0",
		Requirements: []string{"CLAIM-1", "CLAIM-2", "CLAIM-3"},
		Unchecked:    []spec.Unchecked{{ID: "CLAIM-3", Reason: "a person reads it"}},
	}
	covering := []runner.Case{
		{Name: "claim", Cites: []string{"CLAIM-1"}},
		{Name: "again", Cites: []string{"CLAIM-1", "CLAIM-2"}},
	}
	tests := []struct {
		name    string
		l       spec.Loaded
		cases   []runner.Case
		wantErr []string
	}{
		{name: "every requirement cited or listed", l: three, cases: covering},
		{name: "a skeleton with no suite", l: spec.Loaded{Version: "v0.1.0"}},
		{name: "every requirement listed, no suite", l: spec.Loaded{
			Requirements: []string{"CLAIM-1"}, Unchecked: []spec.Unchecked{{ID: "CLAIM-1", Reason: "S2's"}},
		}},
		{name: "a requirement with no case", l: three, cases: covering[:1],
			wantErr: []string{"relay-claim/v1.md: CLAIM-2 is neither cited by a case of the suite nor listed in not-machine-checked.txt"}},
		{name: "a case citing an identifier the document lacks", l: three, cases: append(covering, runner.Case{Name: "ghost", Cites: []string{"CLAIM-9"}}),
			wantErr: []string{`relay-claim/cases: case "ghost" cites CLAIM-9, which v1.md does not state`}},
		{name: "a case citing another specification", l: three, cases: append(covering, runner.Case{Name: "guest", Cites: []string{"GUEST-1"}}),
			wantErr: []string{`case "guest" cites GUEST-1, which v1.md does not state`}},
		{name: "a case citing nothing", l: three, cases: append(covering, runner.Case{Name: "empty"}),
			wantErr: []string{`relay-claim/cases: case "empty" cites no requirement`}},
		{name: "two cases with one name", l: three, cases: append(covering, runner.Case{Name: "claim", Cites: []string{"CLAIM-1"}}),
			wantErr: []string{`relay-claim/cases: two cases are named "claim"`}},
		{name: "a case with no name", l: three, cases: append(covering, runner.Case{Cites: []string{"CLAIM-1"}}),
			wantErr: []string{"relay-claim/cases: case 3 has no name"}},
		{name: "a listed requirement that a case cites", l: spec.Loaded{
			Requirements: three.Requirements, Unchecked: []spec.Unchecked{{ID: "CLAIM-2", Reason: "x"}, {ID: "CLAIM-3", Reason: "y"}},
		}, cases: covering, wantErr: []string{`relay-claim/not-machine-checked.txt: lists CLAIM-2 as not machine-checked, and case "again" cites it`}},
		{name: "a listed identifier the document lacks", l: spec.Loaded{
			Requirements: three.Requirements, Unchecked: []spec.Unchecked{{ID: "CLAIM-3", Reason: "y"}, {ID: "CLAIM-4", Reason: "z"}},
		}, cases: covering, wantErr: []string{"relay-claim/not-machine-checked.txt: lists CLAIM-4, which v1.md does not state"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(s, tt.l, tt.cases)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error:\n%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error, want %q", tt.wantErr)
			}
			for _, w := range tt.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not contain %q:\n%v", w, err)
				}
			}
		})
	}
}
