# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL=/bin/bash -o pipefail

.DEFAULT_GOAL:=help
GOARCH  := $(shell go env GOARCH)
GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
GOPROXY := https://proxy.golang.org
endif
export GOPROXY
GO ?= go
DOCKER ?= docker
BUN ?= $(HOME)/.bun/bin/bun
TEST_FLAGS ?= -v -race

GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif

# Version: closest v3.* release tag, or `dev-<short-sha>` before the first one.
GIT_DESCRIBE := $(shell git describe --tags --match 'v3.*' --dirty 2>/dev/null)
GIT_DIRTY    := $(shell git diff --quiet 2>/dev/null || echo -dirty)
GIT_SHORT    := $(shell git rev-parse --short HEAD 2>/dev/null)
ifeq ($(GIT_DESCRIBE),)
GIT_VERSION := dev-$(GIT_SHORT)$(GIT_DIRTY)
else
GIT_VERSION := $(GIT_DESCRIBE)
endif

VERSION_PKG = github.com/falcosecurity/falcosidekick/internal/version
LDFLAGS     = -X $(VERSION_PKG).Version=$(GIT_VERSION) -X $(VERSION_PKG).Commit=$(GIT_HASH) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

PACKAGES    = ./internal/... ./cmd/...
BINARY      := falcosidekick
BINARY_SLIM := falcosidekick-slim
IMAGE       ?= falcosidekick
DIST        := dist
LOCAL_PLATFORM ?= linux/$(GOARCH)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-24s %s\n", $$1, $$2}'

## --------------------------------------
## Build
## --------------------------------------

.PHONY: falcosidekick
falcosidekick: ui-build ## Build the binary with the embedded UI (host OS and arch)
	CGO_ENABLED=0 $(GO) build -trimpath -tags=builtinui -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/falcosidekick/

.PHONY: falcosidekick-slim
falcosidekick-slim: ## Build the binary without the UI (host OS and arch)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_SLIM) ./cmd/falcosidekick/

# Pattern rules: GNU make skips implicit rules for .PHONY targets, so these
# are not declared phony. Static like the release build: the image has no libc.
falcosidekick-linux-%: ui-build
	CGO_ENABLED=0 GOOS=linux GOARCH=$* $(GO) build -trimpath -tags=builtinui -ldflags "$(LDFLAGS)" \
		-o $(DIST)/linux/$*/$(BINARY) ./cmd/falcosidekick/

falcosidekick-slim-linux-%:
	CGO_ENABLED=0 GOOS=linux GOARCH=$* $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/linux/$*/$(BINARY_SLIM) ./cmd/falcosidekick/

.PHONY: dist-license
dist-license:
	mkdir -p $(DIST) && cp LICENSE $(DIST)/LICENSE

.PHONY: image
image: falcosidekick-linux-$(GOARCH) dist-license ## Build the UI image for the host arch and load it as falcosidekick:local
	$(DOCKER) buildx build --platform $(LOCAL_PLATFORM) -f Dockerfile \
		--build-arg BINARY=$(BINARY) \
		-t $(IMAGE):local --load $(DIST)

.PHONY: image-slim
image-slim: falcosidekick-slim-linux-$(GOARCH) dist-license ## Build the slim image for the host arch and load it as falcosidekick:local-slim
	$(DOCKER) buildx build --platform $(LOCAL_PLATFORM) -f Dockerfile \
		--build-arg BINARY=$(BINARY_SLIM) \
		-t $(IMAGE):local-slim --load $(DIST)

.PHONY: image-multiarch
image-multiarch: falcosidekick-linux-amd64 falcosidekick-linux-arm64 dist-license ## Build the UI image for amd64 and arm64 (no --load)
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64 -f Dockerfile \
		--build-arg BINARY=$(BINARY) \
		-t $(IMAGE):local $(DIST)

.PHONY: goreleaser-snapshot
goreleaser-snapshot: ## Dry-run a goreleaser snapshot build (no sign, no publish)
	goreleaser release --snapshot --clean --skip=sign,publish

## --------------------------------------
## Test and lint
## --------------------------------------

.PHONY: test
test: ## Run Go vet and tests (default build, includes ./ui)
	$(GO) vet $(PACKAGES) ./ui
	$(GO) test $(TEST_FLAGS) $(PACKAGES) ./ui

.PHONY: test-ui-tag
test-ui-tag: ui-build ## Run Go vet and tests with -tags=builtinui
	$(GO) vet -tags=builtinui $(PACKAGES) ./ui
	$(GO) test -tags=builtinui $(TEST_FLAGS) $(PACKAGES) ./ui

.PHONY: test-hack
test-hack: ## Run release and helper script tests
	$(GO) test $(TEST_FLAGS) ./hack/...

.PHONY: docs
docs: ## Write docs/outputs from the output schema (hand-written text outside the generated blocks is kept)
	$(GO) run ./hack/outputdocs

# The second run covers the files behind build tags; builtinui embeds ui/dist, hence ui-build.
LINT_TAGS := builtinui,e2e,integration

.PHONY: lint
lint: ui-build ## Run golangci-lint on every Go package, without and with the build tags
	golangci-lint run $(PACKAGES) ./ui ./hack/...
	golangci-lint run --build-tags=$(LINT_TAGS) $(PACKAGES) ./ui ./hack/... ./test/...

.PHONY: lint-fix
lint-fix: ui-build ## Run golangci-lint with auto-fix
	golangci-lint run --fix $(PACKAGES) ./ui ./hack/...
	golangci-lint run --fix --build-tags=$(LINT_TAGS) $(PACKAGES) ./ui ./hack/... ./test/...
	fieldalignment -fix ./internal/...

GOVULNCHECK_VERSION ?= v1.9.0
ACTIONLINT_VERSION  ?= v1.7.12

.PHONY: go.mod.check
go.mod.check: ## Check that go.mod and go.sum are tidy and that the module cache matches go.sum
	$(GO) mod verify
	$(GO) mod tidy -diff

.PHONY: govulncheck
govulncheck: ## Report known vulnerabilities reachable from the code, tests and tagged files included
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -test -tags=e2e,integration ./...

.PHONY: actionlint
actionlint: ## Lint the GitHub workflows (and their run: scripts, when shellcheck is installed)
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: coverage
coverage: ## Run tests with coverage and check the 80% threshold
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic $(PACKAGES)
	@$(GO) tool cover -func=coverage.out | tail -1
	@COVERAGE=$$($(GO) tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	if [ $$(echo "$$COVERAGE < 80" | bc -l) -eq 1 ]; then \
		echo "FAIL: coverage $$COVERAGE% is below 80% threshold"; exit 1; \
	else \
		echo "OK: coverage $$COVERAGE%"; \
	fi

.PHONY: verify
verify: lint test test-hack test-ui-tag ui-build ui-lint ui-typecheck ui-test chart.lint chart.docs.check go.mod.check govulncheck actionlint ## Full verification: Go default and tagged, golangci-lint, UI build, lint, typecheck and tests, Helm chart lint and README, go.mod, vulnerabilities, workflows

## --------------------------------------
## Helm chart
## --------------------------------------

CHART             := chart/falcosidekick
HELM              ?= helm
HELM_DOCS_VERSION ?= v1.11.0
HELM_DOCS         ?= $(GO) run github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)

.PHONY: chart.lint
chart.lint: ## Lint the Helm chart
	$(HELM) lint --strict $(CHART)

.PHONY: chart.template
chart.template: ## Render the Helm chart with its default values
	$(HELM) template falcosidekick $(CHART) --namespace falco

.PHONY: chart.secret-fields
chart.secret-fields: ## Write the chart's list of secret settings from the output schema
	$(GO) run ./hack/secretfields

.PHONY: chart.docs
chart.docs: ## Write the Helm chart README from README.gotmpl and values.yaml
	$(HELM_DOCS) -c $(CHART) -t ./README.gotmpl -o ./README.md

.PHONY: chart.docs.check
chart.docs.check: ## Check that the Helm chart README matches README.gotmpl and values.yaml
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && cp -R $(CHART) "$$tmp/" && \
		$(HELM_DOCS) -c "$$tmp/$(notdir $(CHART))" -t ./README.gotmpl -o ./README.md && \
		diff -u $(CHART)/README.md "$$tmp/$(notdir $(CHART))/README.md" || \
		{ echo "$(CHART)/README.md is out of date: run make chart.docs"; exit 1; }

## --------------------------------------
## UI (ui/, Bun only)
## --------------------------------------

.PHONY: ui-install
ui-install: ## Install UI dependencies
	cd ui && $(BUN) install --frozen-lockfile

.PHONY: ui-build
ui-build: ui-install ## Build the UI for production (ui/dist/)
	cd ui && $(BUN) run build

.PHONY: ui-lint
ui-lint: ## Lint UI sources with ESLint
	cd ui && $(BUN) run lint

.PHONY: ui-typecheck
ui-typecheck: ## Typecheck UI sources
	cd ui && $(BUN) run typecheck

.PHONY: ui-test
ui-test: ## Run UI tests
	cd ui && $(BUN) test

.PHONY: ui-dev
ui-dev: ## Start the UI dev server with API proxy
	cd ui && $(BUN) run dev

.PHONY: ui-dev-cluster
ui-dev-cluster: ## Run the UI dev server against a backend in the selected kind cluster
	hack/ui-dev-cluster.sh

## --------------------------------------
## Local cluster
## --------------------------------------

.PHONY: live-test
live-test: image ## Deploy to the local kind cluster and run the live-test protocol
	./hack/live-test/run.sh

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST) $(BINARY) $(BINARY_SLIM) coverage.out
	rm -rf ui/dist ui/node_modules
