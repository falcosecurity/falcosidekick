# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL=/bin/bash -o pipefail

.DEFAULT_GOAL:=help
GOPATH  := $(shell go env GOPATH)
GOARCH  := $(shell go env GOARCH)
GOOS    := $(shell go env GOOS)
GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
GOPROXY := https://proxy.golang.org
endif
export GOPROXY
GO ?= go
DOCKER ?= docker
TEST_FLAGS ?= -v -race

GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif

VERSION_PKG=github.com/falcosecurity/falcosidekick/internal/version
LDFLAGS=-X $(VERSION_PKG).Version=$(GIT_VERSION) -X $(VERSION_PKG).Commit=$(GIT_HASH) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

# Directories.
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Docker
IMAGE_TAG := falcosecurity/falcosidekick:latest

## --------------------------------------
## Build
## --------------------------------------

.PHONY: falcosidekick
falcosidekick: ## Build falcosidekick binary
	$(GO) mod download
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -gcflags all=-trimpath=/src -asmflags all=-trimpath=/src -a -installsuffix cgo -o $@ ./cmd/falcosidekick/

.PHONY: falcosidekick-linux
falcosidekick-linux: ## Build falcosidekick binary for Linux
	$(GO) mod download
	GOOS=linux GOARCH=$(GOARCH) $(GO) build -ldflags "$(LDFLAGS)" -gcflags all=-trimpath=/src -asmflags all=-trimpath=/src -a -installsuffix cgo -o falcosidekick ./cmd/falcosidekick/

.PHONY: build-image
build-image: falcosidekick-linux ## Build Docker image
	$(DOCKER) build -t $(IMAGE_TAG) .

.PHONY: push-image
push-image: ## Push Docker image
	$(DOCKER) push $(IMAGE_TAG)

## --------------------------------------
## Test
## --------------------------------------

.PHONY: test
test: ## Run unit tests with race detection
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report and threshold check
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	@$(GO) tool cover -func=coverage.out | tail -1
	@COVERAGE=$$($(GO) tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	if [ $$(echo "$$COVERAGE < 80" | bc -l) -eq 1 ]; then \
		echo "FAIL: Coverage $$COVERAGE% is below 80% threshold"; exit 1; \
	else \
		echo "OK: Coverage $$COVERAGE%"; \
	fi

## --------------------------------------
## Linting
## --------------------------------------

.PHONY: lint
lint: ## Run golangci-lint (Go)
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with auto-fix and struct field alignment
	golangci-lint run --fix ./...
	golangci-lint fmt ./...
	fieldalignment -fix ./internal/...

## --------------------------------------
## v3 Targets (scoped to internal/ and cmd/ only)
## These will replace the root-level targets when v2 legacy is removed.
## --------------------------------------

V3_PACKAGES=./internal/... ./cmd/...

.PHONY: v3-test
v3-test: ## Run v3 unit tests with race detection
	$(GO) vet $(V3_PACKAGES)
	$(GO) test $(TEST_FLAGS) $(V3_PACKAGES)

.PHONY: v3-lint
v3-lint: ## Run golangci-lint on v3 packages
	golangci-lint run $(V3_PACKAGES)

.PHONY: v3-lint-fix
v3-lint-fix: ## Run golangci-lint with auto-fix on v3 packages
	golangci-lint run --fix $(V3_PACKAGES)
	fieldalignment -fix ./internal/...

.PHONY: v3-coverage
v3-coverage: ## Run v3 tests with coverage report and threshold check
	$(GO) test -race -coverprofile=coverage-v3.out -covermode=atomic $(V3_PACKAGES)
	@$(GO) tool cover -func=coverage-v3.out | tail -1
	@COVERAGE=$$($(GO) tool cover -func=coverage-v3.out | grep total | awk '{print $$3}' | tr -d '%'); \
	if [ $$(echo "$$COVERAGE < 80" | bc -l) -eq 1 ]; then \
		echo "FAIL: v3 coverage $$COVERAGE% is below 80% threshold"; exit 1; \
	else \
		echo "OK: v3 coverage $$COVERAGE%"; \
	fi

.PHONY: v3-verify
v3-verify: v3-lint v3-test ui-build ui-lint ui-v3-typecheck ui-v3-test ## Run all v3 Go and UI checks

## --------------------------------------
## Frontend (ui/)
## UI helpers run through Bun (see $(BUN) in the v3 section below). npm is
## not required by any target; the UI toolchain is Bun-exclusive.
## --------------------------------------

.PHONY: ui-install
ui-install: ## Install frontend dependencies (Bun)
	cd ui && $(BUN) install --frozen-lockfile

.PHONY: ui-build
ui-build: ## Build frontend for production (Bun)
	cd ui && $(BUN) install --frozen-lockfile
	cd ui && $(BUN) run build

.PHONY: ui-lint
ui-lint: ## Lint frontend (Bun)
	cd ui && $(BUN) run lint

.PHONY: ui-dev
ui-dev: ## Start frontend dev server (Bun)
	cd ui && $(BUN) run dev

## --------------------------------------
## Full verification
## --------------------------------------

.PHONY: verify
verify: lint test ui-build ui-lint ## Run all Go and UI checks

## --------------------------------------
## Release
## --------------------------------------

.PHONY: goreleaser-snapshot
goreleaser-snapshot: ## Release snapshot using goreleaser
	LDFLAGS="$(LDFLAGS)" goreleaser --snapshot --skip=sign --clean

## --------------------------------------
## Cleanup / Verification
## --------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf dist
	rm -rf coverage.out

## --------------------------------------
## v3 Build Surface (parallel to v2)
## v2 targets above stay unchanged. Everything below is v3-only.
## --------------------------------------

BUN            ?= $(HOME)/.bun/bin/bun
V3_BINARY_UI   := falcosidekick-v3
V3_BINARY_SLIM := falcosidekick-v3-slim
V3_IMAGE       ?= falcosidekick
V3_DIST        := dist

# v3 version string: closest v3.* tag, or `v3-dev-<short-sha>` before the
# first v3 tag exists. v2 git tags are explicitly ignored.
V3_GIT_DESCRIBE := $(shell git describe --tags --match 'v3.*' --dirty 2>/dev/null)
V3_GIT_DIRTY    := $(shell git diff --quiet 2>/dev/null || echo -dirty)
V3_GIT_SHORT    := $(shell git rev-parse --short HEAD 2>/dev/null)
ifeq ($(V3_GIT_DESCRIBE),)
V3_GIT_VERSION := v3-dev-$(V3_GIT_SHORT)$(V3_GIT_DIRTY)
else
V3_GIT_VERSION := $(V3_GIT_DESCRIBE)
endif
V3_LDFLAGS = -X $(VERSION_PKG).Version=$(V3_GIT_VERSION) -X $(VERSION_PKG).Commit=$(GIT_HASH) -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: ui-v3-install
ui-v3-install: ## Install UI dependencies via Bun
	cd ui && $(BUN) install --frozen-lockfile

.PHONY: ui-v3-build
ui-v3-build: ## Build the UI for production (populates ui/dist/)
	cd ui && $(BUN) install --frozen-lockfile
	cd ui && $(BUN) run build

.PHONY: ui-v3-lint
ui-v3-lint: ## Lint UI sources with ESLint
	cd ui && $(BUN) run lint

.PHONY: ui-v3-typecheck
ui-v3-typecheck: ## Typecheck UI sources with tsc --noEmit
	cd ui && $(BUN) run typecheck

.PHONY: ui-v3-dev
ui-v3-dev: ## Start the Bun.serve dev server with API proxy
	cd ui && $(BUN) run dev

.PHONY: ui-v3-test
ui-v3-test: ## Run UI unit/component tests via Bun test + happy-dom
	cd ui && $(BUN) test

.PHONY: ui-v3-dev-cluster
ui-v3-dev-cluster: ## Run the UI dev server against a backend running in the selected kind cluster
	hack/ui-dev-cluster.sh

.PHONY: falcosidekick-v3
falcosidekick-v3: ui-v3-build ## Build v3 binary with embedded UI (host OS+arch, tag builtinui)
	$(GO) build -trimpath -tags=builtinui -ldflags "$(V3_LDFLAGS)" -o $(V3_BINARY_UI) ./cmd/falcosidekick/

.PHONY: falcosidekick-v3-slim
falcosidekick-v3-slim: ## Build v3 binary without the UI (host OS+arch)
	$(GO) build -trimpath -ldflags "$(V3_LDFLAGS)" -o $(V3_BINARY_SLIM) ./cmd/falcosidekick/

.PHONY: falcosidekick-v3-linux-amd64
falcosidekick-v3-linux-amd64: ui-v3-build
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -tags=builtinui -ldflags "$(V3_LDFLAGS)" \
		-o $(V3_DIST)/linux/amd64/$(V3_BINARY_UI) ./cmd/falcosidekick/

.PHONY: falcosidekick-v3-linux-arm64
falcosidekick-v3-linux-arm64: ui-v3-build
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -tags=builtinui -ldflags "$(V3_LDFLAGS)" \
		-o $(V3_DIST)/linux/arm64/$(V3_BINARY_UI) ./cmd/falcosidekick/

.PHONY: falcosidekick-v3-linux-amd64-slim
falcosidekick-v3-linux-amd64-slim:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(V3_LDFLAGS)" \
		-o $(V3_DIST)/linux/amd64/$(V3_BINARY_SLIM) ./cmd/falcosidekick/

.PHONY: falcosidekick-v3-linux-arm64-slim
falcosidekick-v3-linux-arm64-slim:
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(V3_LDFLAGS)" \
		-o $(V3_DIST)/linux/arm64/$(V3_BINARY_SLIM) ./cmd/falcosidekick/

V3_LOCAL_PLATFORM ?= linux/$(GOARCH)

.PHONY: v3-dist-license
v3-dist-license:
	cp LICENSE $(V3_DIST)/LICENSE

.PHONY: build-image-v3-local
build-image-v3-local: falcosidekick-v3-linux-$(GOARCH) v3-dist-license ## Build v3 UI image locally (host arch) using Dockerfile.v3 and --load into Docker
	$(DOCKER) buildx build --platform $(V3_LOCAL_PLATFORM) \
		-f Dockerfile.v3 \
		--build-arg BINARY=$(V3_BINARY_UI) \
		--build-arg VARIANT=ui \
		-t $(V3_IMAGE):v3-local \
		--load $(V3_DIST)

.PHONY: build-image-v3-slim-local
build-image-v3-slim-local: falcosidekick-v3-linux-$(GOARCH)-slim v3-dist-license ## Build v3 slim image locally (host arch)
	$(DOCKER) buildx build --platform $(V3_LOCAL_PLATFORM) \
		-f Dockerfile.v3 \
		--build-arg BINARY=$(V3_BINARY_SLIM) \
		--build-arg VARIANT=slim \
		-t $(V3_IMAGE):v3-local-slim \
		--load $(V3_DIST)

.PHONY: build-image-v3-multiarch
build-image-v3-multiarch: falcosidekick-v3-linux-amd64 falcosidekick-v3-linux-arm64 v3-dist-license ## Build v3 UI image for both archs (no --load; requires --push or additional output)
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64 \
		-f Dockerfile.v3 \
		--build-arg BINARY=$(V3_BINARY_UI) \
		--build-arg VARIANT=ui \
		-t $(V3_IMAGE):v3-local \
		$(V3_DIST)

.PHONY: v3-test-default
v3-test-default: ## Run v3 Go tests (default build, includes ./ui)
	$(GO) vet $(V3_PACKAGES) ./ui
	$(GO) test $(TEST_FLAGS) $(V3_PACKAGES) ./ui

.PHONY: v3-test-ui-tag
v3-test-ui-tag: ui-v3-build ## Run v3 Go tests with -tags=builtinui (includes ./ui)
	$(GO) vet -tags=builtinui $(V3_PACKAGES) ./ui
	$(GO) test -tags=builtinui $(TEST_FLAGS) $(V3_PACKAGES) ./ui

.PHONY: v3-test-hack
v3-test-hack: ## Run release and helper script tests
	$(GO) test $(TEST_FLAGS) ./hack

.PHONY: v3-lint-full
v3-lint-full: ## Run golangci-lint across v3 Go packages including ./ui
	golangci-lint run $(V3_PACKAGES) ./ui ./hack

.PHONY: v3-verify-full
v3-verify-full: v3-lint-full v3-test-default v3-test-hack v3-test-ui-tag ui-v3-build ui-v3-lint ui-v3-typecheck ui-v3-test ## Full v3 verification: Go default + tagged, golangci, Bun install/build/lint/typecheck/test

.PHONY: v3-live-test
v3-live-test: build-image-v3-local ## Deploy v3 to the local kind cluster and run the live-test protocol
	./hack/live-test/run.sh

.PHONY: v3-goreleaser-snapshot
v3-goreleaser-snapshot: ## Dry-run v3 goreleaser snapshot build (no sign, no publish)
	LDFLAGS="$(LDFLAGS)" goreleaser release --config .goreleaser.v3.yml --snapshot --clean --skip=sign,publish

.PHONY: v3-clean
v3-clean: ## Remove v3 build artifacts
	rm -rf $(V3_DIST) $(V3_BINARY_UI) $(V3_BINARY_SLIM) coverage-v3.out
	rm -rf ui/dist ui/node_modules
