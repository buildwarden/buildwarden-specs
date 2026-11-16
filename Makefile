.PHONY: check check-docs check-suite check-coverage check-modules check-tidy check-release tidy vet test

# The six specifications, each a Go module in its own directory, and the
# harness they share. Every target that works on modules goes through these.
SPECS := bootstrap-config collector-inputs collector-outputs executor-initialize relay-claim relay-guest-api
MODULES := conformance $(SPECS)
HARNESS := github.com/buildwarden/buildwarden-specs/conformance

# The repository's own checks, run from the root through the workspace.
SPECCHECK := go run ./conformance/internal/speccheck

# The ref a change is measured from by the release checks.
BASE ?= origin/main

# Everything ci runs. Each module is built from the working tree, through
# go.work, so a change to the harness is tested against every specification's
# cases.
check: check-docs vet test check-coverage check-modules check-tidy check-release

# The checks that read documents only, over the six directories: layout,
# headers and sections, requirement identifiers and lists, schemas and
# examples, the OpenAPI files, and the collector documents' common part.
check-docs:
	@echo "speccheck docs: $(SPECS)"; $(SPECCHECK) docs $(SPECS)

# The green of a suite stage and of its merge: check-docs, then go vet, go
# test and the coverage check for the directories DIRS names.
check-suite:
	@set -e; [ -n "$(DIRS)" ] || { echo 'check-suite: name the directories, DIRS="<directory>..."' >&2; exit 2; }; \
	for d in $(DIRS); do \
		case " $(MODULES) " in *" $$d "*) ;; *) echo "check-suite: $$d is not one of: $(MODULES)" >&2; exit 2;; esac; \
	done
	@$(MAKE) --no-print-directory check-docs
	@set -e; for m in $(DIRS); do echo "go vet: $$m"; (cd $$m && go vet ./...); done
	@set -e; for m in $(DIRS); do echo "go test: $$m"; (cd $$m && go test ./...); done
	@$(MAKE) --no-print-directory check-coverage SPECS="$(filter $(SPECS),$(DIRS))"

# Each requirement of each specification is cited by a case of its own suite
# or listed as not machine-checked; each command runs the check on its own
# suite.
check-coverage:
	@set -e; for m in $(SPECS); do (cd $$m && go run ./cmd/bw-conformance-$$m requirements -check); done

# No go.mod requires the kit or carries a replace line, and go.work's replace
# line names the version at the head of conformance/CHANGELOG.md.
check-modules:
	@echo "speccheck modules"; $(SPECCHECK) modules $(SPECS)

# Each module's go.mod and go.sum are what make tidy writes: their digests
# are the same after make tidy as before. The files are left as make tidy
# wrote them, so that a failure is fixed by committing them.
TIDY_FILES = for m in $(MODULES); do for f in go.mod go.sum; do \
		if [ -f $$m/$$f ]; then cksum $$m/$$f; else echo "absent $$m/$$f"; fi; done; done
check-tidy:
	@set -e; before=$$($(TIDY_FILES)); \
	$(MAKE) --no-print-directory tidy >/dev/null; \
	after=$$($(TIDY_FILES)); \
	if [ "$$before" != "$$after" ]; then \
		echo "check-tidy: make tidy changes these files; commit what it wrote:" >&2; \
		printf '%s\n' "$$after" | grep -vxF -e "$$before" | awk '{ print "  " $$NF }' >&2; exit 1; \
	fi; \
	echo "check-tidy: make tidy changes nothing"

# A change to a directory adds a version to its CHANGELOG.md higher than its
# newest tag, and a changed specification's go.mod names the harness version
# at the head of conformance/CHANGELOG.md. The change is measured from the
# merge base of BASE and HEAD, so the history and the tags must be there.
check-release:
	@echo "speccheck release: from $(BASE)"; $(SPECCHECK) release -base $(BASE) $(SPECS)

vet:
	@set -e; for m in $(MODULES); do echo "go vet: $$m"; (cd $$m && go vet ./...); done

test:
	@set -e; for m in $(MODULES); do echo "go test: $$m"; (cd $$m && go test ./...); done

# Tidies every module's go.mod and go.sum outside the workspace. A
# specification names a harness version that has no tag until it is released,
# which go mod tidy cannot resolve, so each specification is tidied with a
# temporary replace of the harness by ../conformance, which is dropped again
# whether or not the tidy succeeded. The go.mod is then left listing the
# harness's own dependencies at the versions the harness names, and go.sum
# has no line for the harness itself.
tidy:
	@set -e; echo "go mod tidy: conformance"; cd conformance && GOWORK=off go mod tidy
	@set -e; for m in $(SPECS); do \
		echo "go mod tidy: $$m"; \
		( cd $$m; \
		  go mod edit -replace=$(HARNESS)=../conformance; \
		  status=0; GOWORK=off go mod tidy || status=$$?; \
		  go mod edit -dropreplace=$(HARNESS); \
		  exit $$status ); \
	done
