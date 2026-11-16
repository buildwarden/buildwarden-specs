package relay

import (
	"io"
	"net/http"
	"strconv"
)

// serveControl serves the control plane on port 8300 (GUEST-35 to
// GUEST-40), which does not route by Host. /health and /ca.pem are served
// for GET and HEAD and refused 405 for another method, which relay-guest-api
// leaves to the relay (the Go relay serves them whatever the method).
func (g *Guest) serveControl(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		if !getOrHead(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	case "/ca.pem":
		if !getOrHead(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(g.session.CA().PEM)
	case "/v1/output":
		if !post(w, r) {
			return
		}
		g.serveOutput(w, r)
	case "/v1/complete":
		if !post(w, r) {
			return
		}
		if rp, refused := g.complete(r); refused {
			writeRefusal(w, rp.status, string(rp.body[:len(rp.body)-1]))
			return
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	default:
		writeRefusal(w, http.StatusNotFound, "not found")
	}
}

func getOrHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	writeRefusal(w, http.StatusMethodNotAllowed, "GET only")
	return false
}

// post refuses every method but POST with 405 "POST only" (GUEST-40).
func post(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	writeRefusal(w, http.StatusMethodNotAllowed, "POST only")
	return false
}

// writeRefusal is a refusal on the control plane: text/plain, one line
// (GUEST-56).
func writeRefusal(w http.ResponseWriter, status int, line string) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(line)+1))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, line+"\n")
}

// serveOutput forwards a piece of the build's console to the collector as
// one POST /v1/output, and answers 200 once the collector has (GUEST-38).
// It forwards at most OutputLimit in all: the request that crosses it is cut
// short at it and answered 413, which relay-guest-api recommends (the Go
// relay answers it 200, D11), and every later one is answered 413 and not
// forwarded.
func (g *Guest) serveOutput(w http.ResponseWriter, r *http.Request) {
	s := g.session
	if s.Completed() {
		writeRefusal(w, http.StatusConflict, "the build has completed")
		return
	}
	g.mu.Lock()
	left := OutputLimit - g.output
	g.mu.Unlock()
	if left <= 0 {
		writeRefusal(w, http.StatusRequestEntityTooLarge, "output limit exceeded")
		return
	}
	piece, err := io.ReadAll(io.LimitReader(r.Body, left+1))
	if err != nil {
		writeRefusal(w, http.StatusBadRequest, "the output did not arrive whole")
		return
	}
	cut := int64(len(piece)) > left
	if cut {
		piece = piece[:left]
	}
	g.mu.Lock()
	g.output += int64(len(piece))
	g.mu.Unlock()
	rep, err := s.Output(g.ctx, piece)
	switch {
	case err != nil:
		writeRefusal(w, http.StatusInternalServerError, "the collector did not take the output: "+err.Error())
		return
	case rep.Status != http.StatusOK:
		writeRefusal(w, http.StatusInternalServerError, "the collector answered "+strconv.Itoa(rep.Status))
		return
	case cut:
		writeRefusal(w, http.StatusRequestEntityTooLarge, "output limit exceeded")
		return
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}
