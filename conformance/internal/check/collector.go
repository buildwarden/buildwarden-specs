package check

import (
	"fmt"
	"regexp"
	"strings"
)

// The two specifications of seam 2, which state a common part alike.
const (
	CollectorOutputs = "collector-outputs"
	CollectorInputs  = "collector-inputs"
)

// The comment lines that open and close a block of the common part.
const (
	CommonBegin = "<!-- collector-common: begin -->"
	CommonEnd   = "<!-- collector-common: end -->"
)

// collectorID is an identifier of either collector document. The common
// part is compared with each one's prefix read as the same.
var collectorID = regexp.MustCompile(`\b(?:COLLOUT|COLLIN)-([1-9][0-9]*)\b`)

// Common checks that collector-outputs and collector-inputs state their
// common part alike: for each version either has, the documents' marked
// blocks are as many, and each is the same text in both but for the
// identifiers' prefix. A document that states a requirement must mark its
// common part; two skeletons, which state none, need not.
func Common(outputs, inputs map[int][]byte) error {
	var p problems
	versions := map[int]bool{}
	for n := range outputs {
		versions[n] = true
	}
	for n := range inputs {
		versions[n] = true
	}
	for _, n := range sortedKeys(versions) {
		outFile := fmt.Sprintf("%s/v%d.md", CollectorOutputs, n)
		inFile := fmt.Sprintf("%s/v%d.md", CollectorInputs, n)
		out, okOut := outputs[n]
		in, okIn := inputs[n]
		if !okOut || !okIn {
			p.addf(fmt.Sprintf("v%d.md", n), "%s and %s are released as a pair of documents: only one of them has it", CollectorOutputs, CollectorInputs)
			continue
		}
		outBlocks, outErr := commonBlocks(out)
		inBlocks, inErr := commonBlocks(in)
		p.add(outFile, outErr)
		p.add(inFile, inErr)
		if outErr != nil || inErr != nil {
			continue
		}
		if len(outBlocks) == 0 && len(inBlocks) == 0 && !states(out) && !states(in) {
			continue
		}
		if len(outBlocks) == 0 || len(inBlocks) == 0 {
			if len(outBlocks) == 0 {
				p.addf(outFile, "marks no common part (%s ... %s), which it states alike with %s", CommonBegin, CommonEnd, CollectorInputs)
			}
			if len(inBlocks) == 0 {
				p.addf(inFile, "marks no common part (%s ... %s), which it states alike with %s", CommonBegin, CommonEnd, CollectorOutputs)
			}
			continue
		}
		if len(outBlocks) != len(inBlocks) {
			p.addf(outFile, "has %d blocks of the common part where %s has %d", len(outBlocks), inFile, len(inBlocks))
			continue
		}
		for k := range outBlocks {
			if line, a, b, same := compare(outBlocks[k], inBlocks[k]); !same {
				p.addf(outFile, "block %d of the common part (line %d) differs from %s's (line %d) at its line %d: %q against %q", k+1, outBlocks[k].start, inFile, inBlocks[k].start, line, a, b)
			}
		}
	}
	return p.err()
}

// block is one marked block of the common part: its lines, and the line
// number of its opening comment.
type block struct {
	start int
	lines []string
}

// commonBlocks returns the document's marked blocks, in order. A marker
// inside a fenced code block is text, and a block's text includes its code
// blocks.
func commonBlocks(doc []byte) ([]block, error) {
	var p problems
	var out []block
	var cur *block
	fence := ""
	for i, line := range strings.Split(string(doc), "\n") {
		line = strings.TrimRight(line, "\r")
		n := i + 1
		marker := ""
		switch {
		case fence != "":
			if closesFence(line, fence) {
				fence = ""
			}
		case openFence.MatchString(line):
			fence = openFence.FindStringSubmatch(line)[1]
		default:
			marker = strings.TrimSpace(line)
		}
		switch {
		case marker == CommonBegin && cur != nil:
			p.addf(fmt.Sprintf("line %d", n), "opens a common block inside the one opened on line %d", cur.start)
		case marker == CommonBegin:
			cur = &block{start: n}
		case marker == CommonEnd && cur == nil:
			p.addf(fmt.Sprintf("line %d", n), "closes a common block that is not open")
		case marker == CommonEnd:
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			cur.lines = append(cur.lines, line)
		}
	}
	if cur != nil {
		p.addf(fmt.Sprintf("line %d", cur.start), "opens a common block that is never closed")
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	return out, nil
}

// states reports whether the document states any requirement.
func states(doc []byte) bool {
	for _, l := range lines(doc) {
		if statementLine.MatchString(l.text) {
			return true
		}
	}
	return false
}

var statementLine = regexp.MustCompile(`^ {0,3}(?:[-*+] +|[0-9]+[.)] +)?\*\*[A-Za-z0-9]+-[0-9A-Za-z]+\.\*\*`)

// compare returns whether two blocks are the same text but for the
// identifiers' prefix, and otherwise the first line, counted from 1, at
// which they differ, with the two lines.
func compare(a, b block) (int, string, string, bool) {
	norm := func(s string) string { return collectorID.ReplaceAllString(s, "COLL*-$1") }
	for i := 0; i < len(a.lines) || i < len(b.lines); i++ {
		var la, lb string
		if i < len(a.lines) {
			la = a.lines[i]
		}
		if i < len(b.lines) {
			lb = b.lines[i]
		}
		if i >= len(a.lines) || i >= len(b.lines) || norm(la) != norm(lb) {
			return i + 1, la, lb, false
		}
	}
	return 0, "", "", true
}
