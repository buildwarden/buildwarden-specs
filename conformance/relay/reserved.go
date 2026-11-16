package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The fixed paths of artifacts (relay-guest-api, The reserved host
// artifacts), each served for the one method the build environment uses
// (GUEST-31). This relay serves a fixed path for no other method, and
// answers such a request 404 as any other request that is not an upload
// (GUEST-32); the Go relay serves them whatever the method (D9).
var fixedPaths = map[string]string{
	"/heartbeat":    http.MethodGet,
	"/exit":         http.MethodPost,
	"/ca.pem":       http.MethodGet,
	"/ca.crl":       http.MethodGet,
	"/build-script": http.MethodGet,
	"/bootstrap":    http.MethodGet,
}

// serveArtifacts serves the reserved host artifacts. The path is the
// target's, percent-decoded, without its query (GUEST-17).
func (g *Guest) serveArtifacts(req *http.Request, scheme string) response {
	s := g.session
	path := req.URL.Path
	if method, fixed := fixedPaths[path]; fixed {
		if req.Method != method {
			return refusalOf(req, http.StatusNotFound, "not found")
		}
		switch path {
		case "/heartbeat":
			s.Activity()
			return own(req, http.StatusOK, "text/plain", []byte("ok\n"))
		case "/exit":
			if rp, refused := g.complete(req); refused {
				return rp
			}
			return own(req, http.StatusOK, "text/plain", []byte("ok\n"))
		case "/ca.pem":
			return own(req, http.StatusOK, "application/x-pem-file", s.CA().PEM)
		case "/ca.crl":
			return own(req, http.StatusOK, "application/pkix-crl", s.CA().CRL)
		case "/build-script":
			return g.serveInput(req, scheme, s.BuildScript, "application/octet-stream", "build script unavailable")
		default:
			// bootstrap-config: the collector's bytes, unparsed and
			// unchanged, recorded (BOOTCFG-1, BOOTCFG-2); 404 for any other
			// answer of the collector (BOOTCFG-3).
			return g.serveInput(req, scheme, s.Bootstrap, "application/json", "no bootstrap config")
		}
	}
	if req.Method != http.MethodPost {
		return refusalOf(req, http.StatusNotFound, "not found")
	}
	return g.storeArtifact(req, scheme)
}

// complete completes the build at /exit or /v1/complete (GUEST-21,
// GUEST-39): the session ends its ledger, waits for the ledger request's
// reply, and only then sends the completion. A failed completion at the
// collector is logged and does not change the reply. It returns a refusal,
// and true, for an exit code it cannot read.
func (g *Guest) complete(req *http.Request) (response, bool) {
	code, err := exitCode(req)
	if err != nil {
		return refusalOf(req, http.StatusBadRequest, err.Error()), true
	}
	if _, err := g.session.Complete(g.ctx, Completion{ExitCode: code}); err != nil {
		g.session.relay.logf("the completion: %v", err)
	}
	return response{}, false
}

// exitCode reads the query parameter code (GUEST-22): absent or empty is 0,
// and otherwise a signed 64-bit decimal integer. A value that is not one,
// which relay-guest-api leaves undefined, is refused here rather than read
// as success (the Go relay reads it as 0 or as its leading integer, N21).
func exitCode(req *http.Request) (int64, error) {
	v := req.URL.Query().Get("code")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || strings.HasPrefix(v, "+") {
		return 0, fmt.Errorf("invalid exit code %q", v)
	}
	return n, nil
}

// serveInput fetches an input of the collector and serves it unchanged
// with ctype, recorded as a GET's response with status 200 (GUEST-25,
// GUEST-26, GUEST-49), or answers 404 with missing for any other answer of
// the collector.
func (g *Guest) serveInput(req *http.Request, scheme string, fetch func(context.Context) Input, ctype, missing string) response {
	s := g.session
	if s.Completed() {
		return refusalOf(req, http.StatusConflict, "the build has completed")
	}
	in := fetch(g.ctx)
	if !in.OK() {
		return refusalOf(req, http.StatusNotFound, missing)
	}
	rp := own(req, http.StatusOK, ctype, in.Reply.Body)
	return g.recordServed(req, scheme, rp)
}

// recordServed records rp as the response to req, an input served to the
// build, and returns it; after the completion it is refused instead.
func (g *Guest) recordServed(req *http.Request, scheme string, rp response) response {
	x := Exchange{Request: recorded(req, scheme), Status: rp.status, ResponseHeader: rp.head, ResponseBody: rp.body}
	if err := g.session.Record(x); err != nil {
		if errors.Is(err, ErrCompleted) {
			return refusalOf(req, http.StatusConflict, "the build has completed")
		}
		g.session.relay.logf("recording %s: %v", x.URL, err)
	}
	return rp
}

// storeArtifact stores the body of a POST as an artifact (GUEST-27 to
// GUEST-29), streaming it to the collector as it arrives.
func (g *Guest) storeArtifact(req *http.Request, scheme string) response {
	s := g.session
	name := strings.TrimPrefix(req.URL.Path, "/")
	if name == "" {
		name = "unnamed"
	}
	if !validName(name, false) {
		return refusalOf(req, http.StatusBadRequest, "invalid artifact name")
	}
	if req.ContentLength > ArtifactLimit {
		rp := refusalOf(req, http.StatusRequestEntityTooLarge, "artifact size limit exceeded")
		rp.close = true
		return rp
	}
	if s.Completed() {
		return refusalOf(req, http.StatusConflict, "the build has completed")
	}
	body := &limited{r: req.Body, left: ArtifactLimit}
	rep, n, err := s.Artifact(g.ctx, recorded(req, scheme), name, body)
	switch {
	case body.over:
		rp := refusalOf(req, http.StatusRequestEntityTooLarge, "artifact size limit exceeded")
		rp.close = true
		return rp
	case errors.Is(err, ErrCompleted):
		return refusalOf(req, http.StatusConflict, "the build has completed")
	case err != nil || rep.Status != http.StatusOK:
		if err != nil {
			s.relay.logf("artifact %s: %v", name, err)
		} else {
			s.relay.logf("artifact %s: the collector answered %d", name, rep.Status)
		}
		rp := refusalOf(req, http.StatusInternalServerError, "storage error")
		rp.close = body.read != req.ContentLength
		return rp
	}
	return own(req, http.StatusOK, "text/plain", fmt.Appendf(nil, "artifact stored: %s (%d bytes)\n", name, n))
}

// limited reads at most left bytes of r and fails past them.
type limited struct {
	r    io.Reader
	left int64
	read int64
	over bool
}

var errTooLarge = errors.New("artifact size limit exceeded")

// Read reads into at most one byte more than is left, so that a body one
// byte over the limit is seen to be over it.
func (l *limited) Read(p []byte) (int, error) {
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.r.Read(p)
	if int64(n) > l.left {
		l.over = true
		return 0, errTooLarge
	}
	l.left -= int64(n)
	l.read += int64(n)
	return n, err
}

// serveCwd serves the reserved host cwd for a GET (GUEST-33, GUEST-34).
func (g *Guest) serveCwd(req *http.Request, scheme string) response {
	s := g.session
	p := strings.TrimPrefix(req.URL.Path, "/")
	name := strings.TrimSuffix(p, "/")
	if name != "" && !validName(name, true) {
		return refusalOf(req, http.StatusForbidden, "forbidden")
	}
	if s.Completed() {
		return refusalOf(req, http.StatusConflict, "the build has completed")
	}
	fetch := name
	if strings.HasSuffix(p, "/") && name != "" {
		fetch += "/"
	}
	in := s.Context(g.ctx, fetch)
	switch {
	case !in.OK():
		return refusalOf(req, http.StatusNotFound, "not found: "+name)
	case in.List:
		// A listing is not recorded (GUEST-34).
		return own(req, http.StatusOK, "text/plain", in.Reply.Body)
	}
	return g.recordServed(req, scheme, own(req, http.StatusOK, "application/octet-stream", in.Reply.Body))
}

// validName applies GUEST-28 to an artifact's name and, with context, the
// rule as it stands for a context path (GUEST-33): at most NameLimit bytes,
// no leading or trailing "/", and segments of ASCII letters, digits, ".",
// "-" and "_", none empty, none ending with ".", "-" or "_"; an artifact's
// segment does not start with one either, and a context path's may.
func validName(name string, context bool) bool {
	if len(name) > NameLimit || name == "" {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_') {
				return false
			}
		}
		// seg is not empty here, so its last byte exists.
		if strings.ContainsAny(seg[len(seg)-1:], ".-_") {
			return false
		}
		if context {
			if seg == "." || seg == ".." {
				return false
			}
			continue
		}
		if strings.ContainsAny(seg[:1], ".-_") {
			return false
		}
	}
	return true
}
