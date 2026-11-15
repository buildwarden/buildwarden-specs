.PHONY: check tidy vet test

# The six specifications, each a Go module in its own directory, and the
# harness they share. Every target that works on modules goes through these.
SPECS := bootstrap-config collector-inputs collector-outputs executor-initialize relay-claim relay-guest-api
MODULES := conformance $(SPECS)
HARNESS := github.com/buildwarden/buildwarden-specs/conformance

# Everything ci runs. Each module is built from the working tree, through
# go.work, so a change to the harness is tested against every specification's
# cases.
check: vet test

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
