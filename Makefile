# Makefile for go-frost
# FROST threshold signature scheme implementation

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

.PHONY: all
all: test build build-lib

.PHONY: build
## build: Build the binary
build:
	@echo "Building..."
	@VERSION=$$(cat VERSION 2>/dev/null || echo "dev") && \
	$(GOBUILD) -ldflags="-X main.Version=$$VERSION" -o $(BINARY_NAME) $(BINARY_PATH)

.PHONY: build-release
## build-release: Build release binaries with version info
build-release:
	@echo "Building release binaries..."
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) $(BINARY_PATH)
	@echo "Built $(BINARY_NAME) version $(VERSION)"

.PHONY: build-lib
## build-lib: Build both shared and static libraries
build-lib: build-lib-shared build-lib-static
	@echo "Libraries built in $(DIST_DIR)/"

.PHONY: build-lib-shared
## build-lib-shared: Build shared library (libfrost.so)
build-lib-shared:
	@echo "Building shared library..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(LIB_NAME).so $(LIB_PATH)
	@echo "Built $(DIST_DIR)/$(LIB_NAME).so"

.PHONY: build-lib-static
## build-lib-static: Build static library (libfrost.a)
build-lib-static:
	@echo "Building static library..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-archive -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(LIB_NAME).a $(LIB_PATH)
	@echo "Built $(DIST_DIR)/$(LIB_NAME).a"

.PHONY: build-fips
## build-fips: Build CLI binary with FIPS 140 mode enabled (Go 1.24+)
build-fips:
	@echo "Building FIPS-compliant CLI binary..."
	@mkdir -p $(DIST_DIR)/fips
	GOFIPS140=latest CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(BINARY_NAME)-fips $(BINARY_PATH)
	@echo "Built $(DIST_DIR)/fips/$(BINARY_NAME)-fips"

.PHONY: build-lib-fips
## build-lib-fips: Build libraries with FIPS 140 mode enabled (Go 1.24+)
build-lib-fips:
	@echo "Building FIPS-compliant libraries..."
	@mkdir -p $(DIST_DIR)/fips
	GOFIPS140=latest CGO_ENABLED=1 $(GOBUILD) -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(LIB_NAME)-fips.so $(LIB_PATH)
	GOFIPS140=latest CGO_ENABLED=1 $(GOBUILD) -buildmode=c-archive -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/fips/$(LIB_NAME)-fips.a $(LIB_PATH)
	@echo "Built FIPS libraries in $(DIST_DIR)/fips/"

.PHONY: build-all-fips
## build-all-fips: Build both FIPS CLI binary and libraries
build-all-fips: build-fips build-lib-fips
	@echo "All FIPS builds complete in $(DIST_DIR)/fips/"

.PHONY: build-all
## build-all: Build CLI, libraries, FIPS binary, and FIPS libraries
build-all: build build-lib build-fips build-lib-fips
	@echo "All builds complete"

.PHONY: test
## test: Run all unit tests
test:
	@echo "Running unit tests..."
	@$(GOCMD) list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./pkg/... | \
		xargs -r $(GOTEST) -v -race -timeout 60s
	@if [ -n "$$(find internal -name '*.go' 2>/dev/null)" ]; then \
		$(GOTEST) -v -race -timeout 30s $(INTERNAL_DIR); \
	else \
		echo "Skipping internal/ (no Go packages found)"; \
	fi

.PHONY: test-transport
## test-transport: Run distributed network transport tests in Docker
test-transport:
	@echo "Building transport test Docker image..."
	docker build -t $(DOCKER_IMAGE)-transport:$(DOCKER_TAG) -f test/transport/Dockerfile .
	@echo "Running transport tests..."
	docker run --rm $(DOCKER_IMAGE)-transport:$(DOCKER_TAG)

.PHONY: coverage
## coverage: Generate coverage report
coverage:
	@echo "Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -race -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic $(PKG_DIR)
	$(GOCMD) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	$(GOCMD) tool cover -func=$(COVERAGE_PROFILE)
	@echo ""
	@echo "========================================"
	@echo "Coverage report generated at $(COVERAGE_HTML)"
	@echo ""
	@TOTAL=$$($(GOCMD) tool cover -func=$(COVERAGE_PROFILE) | grep total | awk '{print $$3}'); \
	echo "TOTAL PROJECT COVERAGE: $$TOTAL"; \
	echo "========================================"

.PHONY: coverage-frost
## coverage-frost: Generate coverage for frost core package
coverage-frost:
	@echo "Generating coverage for pkg/frost..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/frost.out -covermode=atomic ./pkg/frost
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/frost.out

.PHONY: coverage-group
## coverage-group: Generate coverage for group package
coverage-group:
	@echo "Generating coverage for pkg/frost/group..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/group.out -covermode=atomic ./pkg/frost/group/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/group.out

.PHONY: coverage-ciphersuite
## coverage-ciphersuite: Generate coverage for ciphersuite package
coverage-ciphersuite:
	@echo "Generating coverage for pkg/frost/ciphersuite..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/ciphersuite.out -covermode=atomic ./pkg/frost/ciphersuite/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/ciphersuite.out

.PHONY: coverage-helpers
## coverage-helpers: Generate coverage for helpers package
coverage-helpers:
	@echo "Generating coverage for pkg/frost/helpers..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/helpers.out -covermode=atomic ./pkg/frost/helpers/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/helpers.out

.PHONY: coverage-signing
## coverage-signing: Generate coverage for signing package
coverage-signing:
	@echo "Generating coverage for pkg/frost/signing..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/signing.out -covermode=atomic ./pkg/frost/signing/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/signing.out

.PHONY: coverage-keygen
## coverage-keygen: Generate coverage for keygen package
coverage-keygen:
	@echo "Generating coverage for pkg/frost/keygen..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/keygen.out -covermode=atomic ./pkg/frost/keygen/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/keygen.out

.PHONY: coverage-service
## coverage-service: Generate coverage for service package
coverage-service:
	@echo "Generating coverage for pkg/frost/service..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/service.out -covermode=atomic ./pkg/frost/service/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/service.out

.PHONY: bench
## bench: Run all benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem $(PKG_DIR)

.PHONY: lint
## lint: Run linters
lint:
	@echo "Running linters..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$$(go env GOPATH)/bin/golangci-lint run --timeout=5m ./...

.PHONY: gosec
## gosec: Run security scanner
gosec:
	@echo "Running gosec security scanner..."
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	$$(go env GOPATH)/bin/gosec -quiet -exclude=G101,G104,G115,G304,G306,G404 ./...

.PHONY: govulncheck
## govulncheck: Check for known vulnerabilities
govulncheck:
	@echo "Running govulncheck..."
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	$$(go env GOPATH)/bin/govulncheck ./...

.PHONY: staticcheck
## staticcheck: Run staticcheck linter
staticcheck:
	@echo "Running staticcheck..."
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	$$(go env GOPATH)/bin/staticcheck ./...

.PHONY: ci
## ci: Run all CI checks (lint, security, static analysis, tests, build)
ci: tidy vet lint staticcheck gosec govulncheck test build build-lib
	@echo ""
	@echo "========================================"
	@echo "CI pipeline completed successfully!"
	@echo "========================================"

.PHONY: fmt
## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) $(PKG_DIR)
	@if [ -d "./internal" ]; then $(GOFMT) $(INTERNAL_DIR); fi
	$(GOFMT) $(CMD_DIR)

.PHONY: vet
## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) $(PKG_DIR)
	@if [ -d "./internal" ]; then $(GOVET) $(INTERNAL_DIR); fi
	$(GOVET) $(CMD_DIR)

.PHONY: tidy
## tidy: Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

.PHONY: clean
## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(DIST_DIR)

.PHONY: docker-build
## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-test
## docker-test: Run tests in Docker
docker-test: docker-build
	@echo "Running tests in Docker..."
	docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) make test

.PHONY: docker-run
## docker-run: Run the application in Docker
docker-run: docker-build
	@echo "Running application in Docker..."
	docker run --rm -it $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: help
## help: Display this help message
help:
	@echo "Available targets:"
	@grep -E '^##' Makefile | sed 's/^## //'

.DEFAULT_GOAL := help

.PHONY: test-rfc
## test-rfc: Run RFC 9591 compliance tests
test-rfc:
	@echo "Running RFC 9591 compliance tests..."
	$(GOTEST) -v -race -short -timeout 30s ./test/rfc/...

.PHONY: test-rfc-full
## test-rfc-full: Run ALL RFC 9591 tests including intensive timing tests
test-rfc-full:
	@echo "Running RFC 9591 compliance tests (full mode with timing tests)..."
	$(GOTEST) -v -race -timeout 120s ./test/rfc/...

.PHONY: coverage-rfc
## coverage-rfc: Generate coverage for RFC tests
coverage-rfc:
	@echo "Generating coverage for RFC tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/rfc.out -covermode=atomic ./test/rfc/...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/rfc.out
