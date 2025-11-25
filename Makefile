# Makefile for go-frost
# FROST threshold signature scheme implementation

.PHONY: all build build-fips build-lib build-lib-shared build-lib-static build-lib-fips build-all-fips build-release test test-unit test-integration test-transport integration-test-transport test-coverage clean lint fmt vet docker-build docker-test bench help ci gosec govulncheck staticcheck test-ristretto255-sha512 coverage-ristretto255-sha512 bench-ristretto255-sha512 test-keystore coverage-keystore bench-keystore test-ed25519 coverage-ed25519 bench-ed25519 test-ed25519-sha512 coverage-ed25519-sha512 bench-ed25519-sha512 test-ed448 coverage-ed448 bench-ed448 test-ed448-shake256 coverage-ed448-shake256 bench-ed448-shake256 test-p256 coverage-p256 bench-p256 test-p256-sha256 coverage-p256-sha256 bench-p256-sha256 test-secp256k1 coverage-secp256k1 bench-secp256k1 test-secp256k1-sha256 coverage-secp256k1-sha256 bench-secp256k1-sha256

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary names
BINARY_NAME=frost
BINARY_PATH=./cmd/frost
LIB_NAME=libfrost
LIB_PATH=./cmd/libfrost

# Library output directory
DIST_DIR=./dist

# Directories
PKG_DIR=./pkg/...
INTERNAL_DIR=./internal/...
CMD_DIR=./cmd/...
TEST_DIR=./test/...

# Coverage
COVERAGE_DIR=./coverage
COVERAGE_PROFILE=$(COVERAGE_DIR)/coverage.out
COVERAGE_HTML=$(COVERAGE_DIR)/coverage.html

# Docker
DOCKER_IMAGE=go-frost
DOCKER_TAG=latest

# Version info
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS = -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)

all: test build build-lib

## build: Build the binary
build:
	@echo "Building..."
	@VERSION=$$(cat VERSION 2>/dev/null || echo "dev") && \
	$(GOBUILD) -ldflags="-X main.Version=$$VERSION" -o $(BINARY_NAME) $(BINARY_PATH)

## build-release: Build release binaries with version info
build-release:
	@echo "Building release binaries..."
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) $(BINARY_PATH)
	@echo "Built $(BINARY_NAME) version $(VERSION)"

## build-lib: Build both shared and static libraries
build-lib: build-lib-shared build-lib-static
	@echo "Libraries built in $(DIST_DIR)/"

## build-lib-shared: Build shared library (libfrost.so)
build-lib-shared:
	@echo "Building shared library..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(LIB_NAME).so $(LIB_PATH)
	@echo "Built $(DIST_DIR)/$(LIB_NAME).so"

## build-lib-static: Build static library (libfrost.a)
build-lib-static:
	@echo "Building static library..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-archive -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(LIB_NAME).a $(LIB_PATH)
	@echo "Built $(DIST_DIR)/$(LIB_NAME).a"

## build-fips: Build CLI binary with FIPS 140 mode enabled (Go 1.24+)
build-fips:
	@echo "Building FIPS-compliant CLI binary..."
	@mkdir -p $(DIST_DIR)/fips
	GOFIPS140=latest CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(BINARY_NAME)-fips $(BINARY_PATH)
	@echo "Built $(DIST_DIR)/fips/$(BINARY_NAME)-fips"

## build-lib-fips: Build libraries with FIPS 140 mode enabled (Go 1.24+)
build-lib-fips:
	@echo "Building FIPS-compliant libraries..."
	@mkdir -p $(DIST_DIR)/fips
	GOFIPS140=latest CGO_ENABLED=1 $(GOBUILD) -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(LIB_NAME)-fips.so $(LIB_PATH)
	GOFIPS140=latest CGO_ENABLED=1 $(GOBUILD) -buildmode=c-archive -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(LIB_NAME)-fips.a $(LIB_PATH)
	@echo "Built FIPS libraries in $(DIST_DIR)/fips/"

## build-all-fips: Build both FIPS CLI binary and libraries
build-all-fips: build-fips build-lib-fips
	@echo "All FIPS builds complete in $(DIST_DIR)/fips/"

## build-all: Build CLI, libraries, FIPS binary, and FIPS libraries
build-all: build build-lib build-fips build-lib-fips
	@echo "All builds complete"

## test: Run all tests
test: test-unit

## test-unit: Run unit tests for all packages
test-unit:
	@echo "Running unit tests..."
	@$(GOCMD) list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./pkg/... | \
		xargs -r $(GOTEST) -v -race -timeout 30s
	@if [ -n "$$(find internal -name '*.go' 2>/dev/null)" ]; then \
		$(GOTEST) -v -race -timeout 30s $(INTERNAL_DIR); \
	else \
		echo "Skipping internal/ (no Go packages found)"; \
	fi

## test-integration: Run integration tests in Docker
test-integration:
	@echo "Building integration test Docker image..."
	docker build -t $(DOCKER_IMAGE)-test:$(DOCKER_TAG) -f test/integration/Dockerfile .
	@echo "Running integration tests..."
	docker run --rm $(DOCKER_IMAGE)-test:$(DOCKER_TAG)

## integration-test: Alias for test-integration (matches CLAUDE.md requirements)
integration-test: test-integration

## integration-test-internal: Internal target for running integration tests inside container
integration-test-internal:
	$(GOTEST) -v -race -timeout 300s -tags=integration ./test/integration/...

## test-transport: Run distributed network transport tests in Docker
test-transport:
	@echo "Building transport test Docker image..."
	docker build -t $(DOCKER_IMAGE)-transport:$(DOCKER_TAG) -f test/transport/Dockerfile .
	@echo "Running transport tests..."
	docker run --rm $(DOCKER_IMAGE)-transport:$(DOCKER_TAG)

## integration-test-transport: Alias for test-transport (matches CLAUDE.md requirements)
integration-test-transport: test-transport

## coverage: Generate code coverage report
coverage:
	@echo "Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic $(PKG_DIR)
	$(GOCMD) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated at $(COVERAGE_HTML)"

## coverage-frost: Generate coverage for frost core package
coverage-frost:
	@echo "Generating coverage for pkg/frost..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/frost.out -covermode=atomic ./pkg/frost
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/frost.out

## coverage-group: Generate coverage for group package
coverage-group:
	@echo "Generating coverage for pkg/frost/group..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/group.out -covermode=atomic ./pkg/frost/group/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/group.out

## coverage-ciphersuite: Generate coverage for ciphersuite package
coverage-ciphersuite:
	@echo "Generating coverage for pkg/frost/ciphersuite..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ciphersuite.out -covermode=atomic ./pkg/frost/ciphersuite/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ciphersuite.out

## coverage-helpers: Generate coverage for helpers package
coverage-helpers:
	@echo "Generating coverage for pkg/frost/helpers..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/helpers.out -covermode=atomic ./pkg/frost/helpers/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/helpers.out

## coverage-signing: Generate coverage for signing package
coverage-signing:
	@echo "Generating coverage for pkg/frost/signing..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/signing.out -covermode=atomic ./pkg/frost/signing/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/signing.out

## coverage-keygen: Generate coverage for keygen package
coverage-keygen:
	@echo "Generating coverage for pkg/frost/keygen..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/keygen.out -covermode=atomic ./pkg/frost/keygen/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/keygen.out

## coverage-service: Generate coverage for service package
coverage-service:
	@echo "Generating coverage for pkg/frost/service..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/service.out -covermode=atomic ./pkg/frost/service/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/service.out

## test-keystore: Run tests for keystore package
test-keystore:
	@echo "Running tests for pkg/frost/keystore..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/keystore/...

## coverage-keystore: Generate coverage for keystore package
coverage-keystore:
	@echo "Generating coverage for pkg/frost/keystore..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/keystore.out -covermode=atomic ./pkg/frost/keystore/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/keystore.out

## bench-keystore: Run benchmarks for keystore package
bench-keystore:
	@echo "Running benchmarks for pkg/frost/keystore..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/keystore/...

## coverage-ristretto255: Generate coverage for ristretto255 group package
coverage-ristretto255:
	@echo "Generating coverage for pkg/frost/group/ristretto255..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ristretto255.out -covermode=atomic ./pkg/frost/group/ristretto255/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ristretto255.out

## test-ristretto255: Run tests for ristretto255 group package
test-ristretto255:
	@echo "Running tests for pkg/frost/group/ristretto255..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/group/ristretto255/...

## bench-ristretto255: Run benchmarks for ristretto255 group package
bench-ristretto255:
	@echo "Running benchmarks for pkg/frost/group/ristretto255..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/group/ristretto255/...

## test-ristretto255-sha512: Run tests for ristretto255-SHA512 ciphersuite
test-ristretto255-sha512:
	@echo "Running tests for pkg/frost/ciphersuite/ristretto255_sha512..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/ciphersuite/ristretto255_sha512/...

## coverage-ristretto255-sha512: Generate coverage for ristretto255-SHA512 ciphersuite
coverage-ristretto255-sha512:
	@echo "Generating coverage for pkg/frost/ciphersuite/ristretto255_sha512..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ristretto255_sha512.out -covermode=atomic ./pkg/frost/ciphersuite/ristretto255_sha512/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ristretto255_sha512.out

## bench-ristretto255-sha512: Run benchmarks for ristretto255-SHA512 ciphersuite
bench-ristretto255-sha512:
	@echo "Running benchmarks for pkg/frost/ciphersuite/ristretto255_sha512..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/ciphersuite/ristretto255_sha512/...

## test-ed25519: Run tests for Ed25519 group package
test-ed25519:
	@echo "Running tests for pkg/frost/group/ed25519..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/group/ed25519/...

## coverage-ed25519: Generate coverage for Ed25519 group package
coverage-ed25519:
	@echo "Generating coverage for pkg/frost/group/ed25519..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ed25519.out -covermode=atomic ./pkg/frost/group/ed25519/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ed25519.out

## bench-ed25519: Run benchmarks for Ed25519 group package
bench-ed25519:
	@echo "Running benchmarks for pkg/frost/group/ed25519..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/group/ed25519/...

## test-ed25519-sha512: Run tests for Ed25519-SHA512 ciphersuite
test-ed25519-sha512:
	@echo "Running tests for pkg/frost/ciphersuite/ed25519_sha512..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/ciphersuite/ed25519_sha512/...

## coverage-ed25519-sha512: Generate coverage for Ed25519-SHA512 ciphersuite
coverage-ed25519-sha512:
	@echo "Generating coverage for pkg/frost/ciphersuite/ed25519_sha512..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ed25519_sha512.out -covermode=atomic ./pkg/frost/ciphersuite/ed25519_sha512/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ed25519_sha512.out

## bench-ed25519-sha512: Run benchmarks for Ed25519-SHA512 ciphersuite
bench-ed25519-sha512:
	@echo "Running benchmarks for pkg/frost/ciphersuite/ed25519_sha512..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/ciphersuite/ed25519_sha512/...

## test-ed448: Run tests for Ed448 group package
test-ed448:
	@echo "Running tests for pkg/frost/group/ed448..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/group/ed448/...

## coverage-ed448: Generate coverage for Ed448 group package
coverage-ed448:
	@echo "Generating coverage for pkg/frost/group/ed448..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ed448.out -covermode=atomic ./pkg/frost/group/ed448/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ed448.out

## bench-ed448: Run benchmarks for Ed448 group package
bench-ed448:
	@echo "Running benchmarks for pkg/frost/group/ed448..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/group/ed448/...

## test-ed448-shake256: Run tests for Ed448-SHAKE256 ciphersuite
test-ed448-shake256:
	@echo "Running tests for pkg/frost/ciphersuite/ed448_shake256..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/ciphersuite/ed448_shake256/...

## coverage-ed448-shake256: Generate coverage for Ed448-SHAKE256 ciphersuite
coverage-ed448-shake256:
	@echo "Generating coverage for pkg/frost/ciphersuite/ed448_shake256..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ed448_shake256.out -covermode=atomic ./pkg/frost/ciphersuite/ed448_shake256/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ed448_shake256.out

## bench-ed448-shake256: Run benchmarks for Ed448-SHAKE256 ciphersuite
bench-ed448-shake256:
	@echo "Running benchmarks for pkg/frost/ciphersuite/ed448_shake256..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/ciphersuite/ed448_shake256/...

## test-p256: Run tests for P-256 group package
test-p256:
	@echo "Running tests for pkg/frost/group/p256..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/group/p256/...

## coverage-p256: Generate coverage for P-256 group package
coverage-p256:
	@echo "Generating coverage for pkg/frost/group/p256..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/p256.out -covermode=atomic ./pkg/frost/group/p256/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/p256.out

## bench-p256: Run benchmarks for P-256 group package
bench-p256:
	@echo "Running benchmarks for pkg/frost/group/p256..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/group/p256/...

## test-p256-sha256: Run tests for P-256 SHA-256 ciphersuite
test-p256-sha256:
	@echo "Running tests for pkg/frost/ciphersuite/p256_sha256..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/ciphersuite/p256_sha256/...

## coverage-p256-sha256: Generate coverage for P-256 SHA-256 ciphersuite
coverage-p256-sha256:
	@echo "Generating coverage for pkg/frost/ciphersuite/p256_sha256..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/p256_sha256.out -covermode=atomic ./pkg/frost/ciphersuite/p256_sha256/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/p256_sha256.out

## bench-p256-sha256: Run benchmarks for P-256 SHA-256 ciphersuite
bench-p256-sha256:
	@echo "Running benchmarks for pkg/frost/ciphersuite/p256_sha256..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/ciphersuite/p256_sha256/...

## test-secp256k1: Run tests for secp256k1 group package
test-secp256k1:
	@echo "Running tests for pkg/frost/group/secp256k1..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/group/secp256k1/...

## coverage-secp256k1: Generate coverage for secp256k1 group package
coverage-secp256k1:
	@echo "Generating coverage for pkg/frost/group/secp256k1..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/secp256k1.out -covermode=atomic ./pkg/frost/group/secp256k1/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/secp256k1.out

## bench-secp256k1: Run benchmarks for secp256k1 group package
bench-secp256k1:
	@echo "Running benchmarks for pkg/frost/group/secp256k1..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/group/secp256k1/...

## test-secp256k1-sha256: Run tests for secp256k1 SHA-256 ciphersuite
test-secp256k1-sha256:
	@echo "Running tests for pkg/frost/ciphersuite/secp256k1_sha256..."
	$(GOTEST) -v -race -timeout 30s ./pkg/frost/ciphersuite/secp256k1_sha256/...

## coverage-secp256k1-sha256: Generate coverage for secp256k1 SHA-256 ciphersuite
coverage-secp256k1-sha256:
	@echo "Generating coverage for pkg/frost/ciphersuite/secp256k1_sha256..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/secp256k1_sha256.out -covermode=atomic ./pkg/frost/ciphersuite/secp256k1_sha256/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/secp256k1_sha256.out

## bench-secp256k1-sha256: Run benchmarks for secp256k1 SHA-256 ciphersuite
bench-secp256k1-sha256:
	@echo "Running benchmarks for pkg/frost/ciphersuite/secp256k1_sha256..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/ciphersuite/secp256k1_sha256/...

## bench: Run all benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem $(PKG_DIR)

## bench-frost: Run benchmarks for frost core package
bench-frost:
	@echo "Running benchmarks for pkg/frost..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost

## bench-signing: Run benchmarks for signing package
bench-signing:
	@echo "Running benchmarks for pkg/frost/signing..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/signing/...

## bench-keygen: Run benchmarks for keygen package
bench-keygen:
	@echo "Running benchmarks for pkg/frost/keygen..."
	$(GOTEST) -bench=. -benchmem ./pkg/frost/keygen/...

## lint: Run linters
lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null 2>&1 || test -f "$$(go env GOPATH)/bin/golangci-lint" || (echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	@if which golangci-lint > /dev/null 2>&1; then \
		golangci-lint run --timeout=5m ./...; \
	else \
		$$(go env GOPATH)/bin/golangci-lint run --timeout=5m ./...; \
	fi

## gosec: Run security scanner
## Excludes: G101 (hardcoded creds), G104 (unhandled errors), G115 (int overflow), G304 (file inclusion), G306 (file perms), G404 (weak rand)
gosec:
	@echo "Running gosec security scanner..."
	@which gosec > /dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@which gosec > /dev/null 2>&1 && gosec -quiet -exclude=G101,G104,G115,G304,G306,G404 ./... || $$(go env GOPATH)/bin/gosec -quiet -exclude=G101,G104,G115,G304,G306,G404 ./...

## govulncheck: Check for known vulnerabilities
govulncheck:
	@echo "Running govulncheck..."
	@which govulncheck > /dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	@which govulncheck > /dev/null 2>&1 && govulncheck ./... || $$(go env GOPATH)/bin/govulncheck ./...

## staticcheck: Run staticcheck linter
staticcheck:
	@echo "Running staticcheck..."
	@which staticcheck > /dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || $$(go env GOPATH)/bin/staticcheck ./...

## ci: Run all CI checks (lint, security, tests, build)
## Note: staticcheck is included in golangci-lint, so we skip the standalone version
ci: tidy vet lint gosec govulncheck test build build-lib
	@echo ""
	@echo "========================================"
	@echo "CI pipeline completed successfully!"
	@echo "========================================"

## ci-quick: Run quick CI checks (skip integration tests)
ci-quick: tidy vet lint gosec test-unit build
	@echo ""
	@echo "========================================"
	@echo "Quick CI completed successfully!"
	@echo "========================================"

## ci-full: Run full CI including integration tests and FIPS builds
ci-full: ci test-integration build-lib-fips
	@echo ""
	@echo "========================================"
	@echo "Full CI pipeline completed successfully!"
	@echo "========================================"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) $(PKG_DIR)
	@if [ -d "./internal" ]; then $(GOFMT) $(INTERNAL_DIR); fi
	$(GOFMT) $(CMD_DIR)

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) $(PKG_DIR)
	@if [ -d "./internal" ]; then $(GOVET) $(INTERNAL_DIR); fi
	$(GOVET) $(CMD_DIR)

## tidy: Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(DIST_DIR)
	rm -rf ./test/integration/data

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

## docker-test: Run tests in Docker
docker-test: docker-build
	@echo "Running tests in Docker..."
	docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) make test

## docker-run: Run the application in Docker
docker-run: docker-build
	@echo "Running application in Docker..."
	docker run --rm -it $(DOCKER_IMAGE):$(DOCKER_TAG)

## help: Display this help message
help:
	@echo "Available targets:"
	@grep -E '^##' Makefile | sed 's/^## //'

.DEFAULT_GOAL := help

## test-rfc: Run RFC 9591 compliance tests (fast mode, skips intensive timing tests)
test-rfc:
	@echo "Running RFC 9591 compliance tests (fast mode)..."
	$(GOTEST) -v -race -short -timeout 30s ./test/rfc/...

## test-rfc-full: Run ALL RFC 9591 tests including intensive timing tests
test-rfc-full:
	@echo "Running RFC 9591 compliance tests (full mode with timing tests)..."
	$(GOTEST) -v -race -timeout 120s ./test/rfc/...

## test-rfc-section: Run specific RFC section tests (e.g., make test-rfc-section SECTION=3)
test-rfc-section:
	@echo "Running RFC Section $(SECTION) tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section$(SECTION)

## coverage-rfc: Generate coverage for RFC tests
coverage-rfc:
	@echo "Generating coverage for RFC tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/rfc.out -covermode=atomic ./test/rfc/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/rfc.out

## test-sidechannel: Run side-channel timing tests
test-sidechannel:
	@echo "Running side-channel timing tests..."
	$(GOTEST) -v -timeout 300s ./test/rfc -run Section7_1

## bench-sidechannel: Run side-channel benchmarks
bench-sidechannel:
	@echo "Running side-channel benchmarks..."
	$(GOTEST) -bench=. -benchmem ./test/rfc -run Section7_1

## test-section3: Run RFC Section 3 tests (Cryptographic Dependencies)
test-section3:
	@echo "Running RFC Section 3 tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section3

## test-section4: Run RFC Section 4 tests (Helper Functions)
test-section4:
	@echo "Running RFC Section 4 tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section4

## test-section5: Run RFC Section 5 tests (Two-Round Signing Protocol)
test-section5:
	@echo "Running RFC Section 5 tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section5

## test-section6: Run RFC Section 6 tests (Ciphersuites)
test-section6:
	@echo "Running RFC Section 6 tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section6

## test-section7: Run RFC Section 7 tests (Security Considerations - All)
test-section7:
	@echo "Running RFC Section 7 tests..."
	$(GOTEST) -v -race -timeout 300s ./test/rfc -run Section7

## test-section7-1: Run RFC Section 7.1 tests (Side-Channel Mitigations)
test-section7-1:
	@echo "Running RFC Section 7.1 tests (Side-Channel Mitigations)..."
	$(GOTEST) -v -timeout 300s ./test/rfc -run Section7_1

## test-section7-2: Run RFC Section 7.2 tests (Participant Authentication)
test-section7-2:
	@echo "Running RFC Section 7.2 tests (Participant Authentication)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_2

## test-section7-3: Run RFC Section 7.3 tests (Nonce Reuse Prevention)
test-section7-3:
	@echo "Running RFC Section 7.3 tests (Nonce Reuse Prevention)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_3

## test-section7-4: Run RFC Section 7.4 tests (Protocol Failures and Abort)
test-section7-4:
	@echo "Running RFC Section 7.4 tests (Protocol Failures and Abort)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_4

## test-section7-5: Run RFC Section 7.5 tests (Error Handling)
test-section7-5:
	@echo "Running RFC Section 7.5 tests (Error Handling)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_5

## test-section7-6: Run RFC Section 7.6 tests (Pre-Hashing)
test-section7-6:
	@echo "Running RFC Section 7.6 tests (Pre-Hashing)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_6

## test-section7-7: Run RFC Section 7.7 tests (Input Validation)
test-section7-7:
	@echo "Running RFC Section 7.7 tests (Input Validation)..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run Section7_7

## test-appendixc: Run RFC Appendix C tests (Key Generation)
test-appendixc:
	@echo "Running RFC Appendix C tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run AppendixC

## test-appendixd: Run RFC Appendix D tests (Random Scalars)
test-appendixd:
	@echo "Running RFC Appendix D tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run AppendixD

## test-appendixe: Run RFC Appendix E tests (Test Vectors)
test-appendixe:
	@echo "Running RFC Appendix E tests..."
	$(GOTEST) -v -race -timeout 30s ./test/rfc -run AppendixE
