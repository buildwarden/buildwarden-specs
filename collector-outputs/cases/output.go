package cases

import (
	"net/http"

	"github.com/buildwarden/buildwarden-specs/conformance/attach"
	"github.com/buildwarden/buildwarden-specs/conformance/relay"
	"github.com/buildwarden/buildwarden-specs/conformance/runner"
)

// oneOutput has the harness's relay, with no build side, claimed by the
// collector under test, send it one piece of console output, which the
// collector answers 200 with an empty body. The collector is started for
// this case's relay alone, and so is a fresh instance. It is given an output
// location of its own and the capture mode "none", which a collector that
// claims may need on its command line; it is given no build script and no
// context.
var oneOutput = runner.Case{
	Name:    "a collector accepts a piece of console output",
	Cites:   []string{"COLLOUT-21"},
	Role:    "collector",
	Ends:    true,
	Applies: claims,
	Run: func(t *runner.T) {
		s := claimedBy(t, attach.Params{Capture: relay.CaptureNone})
		rep, err := s.s.Output(t.Context(), []byte("console\n"))
		if err != nil {
			t.Fatalf("POST /v1/output: %v", err)
		}
		s.wantEmpty("POST /v1/output", rep, http.StatusOK)
	},
}
