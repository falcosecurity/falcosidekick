SHELL=/bin/bash -o pipefail

GO ?= go

TEST_FLAGS ?= -v -race

.PHONY: falcosidekick
falcosidekick:
	$(GO) build -o $@

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...