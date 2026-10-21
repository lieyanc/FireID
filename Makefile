.PHONY: all web build binary run start dev dev-web test lint clean fmt vet race check release-local docker

BIN     ?= bin/fireid
CONFIG  ?= config.json
PKG     := github.com/lieyanc/FireID/internal/version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildTime=$(BUILD_TIME)

# Release archives: fireid_<version without v>_<os>_<arch>.tar.gz in DIST.
DIST      ?= dist
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
SHA256    := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)
IMAGE     ?= fireid

# Every Go file of both modules, without the npm tree.
GOFILES = $(shell find . -name '*.go' -not -path './web/node_modules/*' -not -path './.git/*')

all: build

web/node_modules: web/package-lock.json
	npm ci --prefix web
	@touch $@

# Build the UI into web/dist (embedded by the Go binary).
web: web/node_modules
	npm run --prefix web build

build: web binary

# Static binary only, embedding whatever is already in web/dist.
binary:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/fireid

# Full build (UI + binary), then run it.
run: build
	./$(BIN) -c $(CONFIG)

# Build the binary without rebuilding the UI, then run it.
start: binary
	./$(BIN) -c $(CONFIG)

# Backend with the UI currently in web/dist; run `make dev-web` alongside for hot reload.
dev:
	go run ./cmd/fireid -c $(CONFIG)

dev-web: web/node_modules
	npm run --prefix web dev

test:
	go vet ./...
	go test -race ./...

lint: web/node_modules
	npm run --prefix web lint
	npm run --prefix web typecheck

# Fails if any Go file is not gofmt-clean; it lists them and changes nothing.
fmt:
	@out=$$(gofmt -l $(GOFILES)); \
	if [ -n "$$out" ]; then echo "not gofmt-clean (run gofmt -w on them):"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	cd client && go vet ./...

# Tests with the race detector, for the main module and the client module.
race:
	go test -race ./...
	cd client && go test -race ./...

# What CI runs, minus the UI build.
check: fmt vet race lint

# Cross-compiled archives and SHA256SUMS in $(DIST), with a freshly built UI.
release-local: web
	rm -rf $(DIST)
	mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		name=fireid_$(patsubst v%,%,$(VERSION))_$${os}_$${arch}; \
		echo "building $$name"; \
		mkdir -p $(DIST)/$$name && \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/$$name/fireid ./cmd/fireid && \
		cp LICENSE README.md CHANGELOG.md $(DIST)/$$name/ && \
		tar -C $(DIST) -czf $(DIST)/$$name.tar.gz $$name && \
		rm -rf $(DIST)/$$name || exit 1; \
	done
	cd $(DIST) && $(SHA256) *.tar.gz > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

# Container image for the local architecture; the release workflow builds the multi-arch one.
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

clean:
	rm -rf bin $(DIST) web/dist/assets web/dist/*.html web/dist/*.svg
