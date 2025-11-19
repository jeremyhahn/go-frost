# Makefile for go-frost
# FROST threshold signature scheme implementation

.PHONY: all build test test-unit test-integration test-transport integration-test-transport test-coverage clean lint fmt vet docker-build docker-test bench help test-ristretto255-sha512 coverage-ristretto255-sha512 bench-ristretto255-sha512 test-keystore coverage-keystore bench-keystore

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary name
BINARY_NAME=frost
BINARY_PATH=./cmd/frost

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

all: test build

## build: Build the binary
build:
	@echo "Building..."
	@VERSION=$$(cat VERSION 2>/dev/null || echo "dev") && \
	$(GOBUILD) -ldflags="-X main.Version=$$VERSION" -o $(BINARY_NAME) $(BINARY_PATH)

## build-release: Build release binaries with version info
build-release:
	@echo "Building release binaries..."
	@VERSION=$$(cat VERSION 2>/dev/null || echo "dev") && \
	GIT_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo "none") && \
	BUILD_DATE=$$(date -u +"%Y-%m-%dT%H:%M:%SZ") && \
	LDFLAGS="-s -w -X main.Version=$$VERSION -X main.GitCommit=$$GIT_COMMIT -X main.BuildDate=$$BUILD_DATE" && \
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$$LDFLAGS" -o $(BINARY_NAME) $(BINARY_PATH)
	@echo "Built $(BINARY_NAME) version $$VERSION"

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
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin" && exit 1)
	golangci-lint run --timeout=5m ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) $(PKG_DIR)
	$(GOFMT) $(INTERNAL_DIR)
	$(GOFMT) $(CMD_DIR)

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) $(PKG_DIR)
	$(GOVET) $(INTERNAL_DIR)
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
