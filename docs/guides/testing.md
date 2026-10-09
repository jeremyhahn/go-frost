# Testing Guide

> **Status: REFERENCE** · Last verified: 2026-10-09
> How go-frost is tested.

Testing guide for go-frost. The `make` targets named here are the ones in the repository `Makefile` (`make help` lists them). Snippets are illustrative unless they point at a file.

## Table of Contents

- [Overview](#overview)
- [Testing Philosophy](#testing-philosophy)
- [Test Types](#test-types)
- [Running Tests](#running-tests)
- [Code Coverage](#code-coverage)
- [Benchmarks](#benchmarks)
- [Writing Tests](#writing-tests)
- [Continuous Integration](#continuous-integration)

## Overview

go-frost follows Test-Driven Development (TDD) principles with a goal of 90%+ code coverage. All tests are meant to be meaningful and to give real protection against regressions and bugs. The 90% figure is a project goal: CI collects coverage and uploads it to Codecov, but it does not fail the build on a threshold, and this guide does not claim a measured number. Run `make coverage` for the current figures.

### Testing Principles

1. **Meaningful Tests**: No tests for the sake of coverage
2. **Fast Unit Tests**: Run quickly without modifying the host
3. **Isolated Tests**: No dependencies between tests
4. **Clear Assertions**: Easy to understand what failed
5. **Comprehensive Coverage**: Edge cases and error paths

## Testing Philosophy

### Test-Driven Development (TDD)

All features follow TDD workflow:

1. **Write test first**: Define expected behavior
2. **Run test**: Verify it fails (red)
3. **Implement feature**: Make test pass (green)
4. **Refactor**: Improve code quality
5. **Repeat**: Continue cycle

### Coverage Goals

- **Goal**: 90% code coverage per package (not enforced by CI)
- **Edge Cases**: All error paths tested
- **No Skip Guards**: unit tests should not hide behind `-short`. The one exception is `test/rfc`, whose side-channel timing tests call `testing.Short()` and are skipped by `make test-rfc` (see [RFC Compliance Tests](#rfc-compliance-tests)).

### Test Pyramid

Most tests are fast unit tests next to the code; a small number of end-to-end tests sit on top (`test/transport`, `test/testvectors`, `test/rfc`). The proportions are a guideline, not a measured split.

## Test Types

### Unit Tests

Fast, in-memory tests for individual functions and components.

**Characteristics**:
- Run in memory
- No network I/O
- No file system modifications
- No Docker required
- `make test` gives each package a 60 second timeout (30 seconds for `internal/`)

**Location**: Alongside source files (`*_test.go`)

**Example**:
```go
func TestParticipant_RoundOne(t *testing.T) {
    // Setup
    suite := ristretto255_sha512.New()
    keyPkg := createTestKeyPackage(1, suite)
    participant := signing.NewParticipant(keyPkg, suite)

    // Execute
    nonces, commitments, err := participant.RoundOne()

    // Assert
    require.NoError(t, err)
    assert.NotNil(t, nonces.HidingNonce)
    assert.NotNil(t, nonces.BindingNonce)
    assert.NotNil(t, commitments.HidingNonceCommitment)
    assert.NotNil(t, commitments.BindingNonceCommitment)
}
```

### Integration Tests

End-to-end tests that validate complete protocol flows.

**Characteristics**:
- `test/transport/` runs a real distributed FROST exchange over HTTP between in-process participant nodes
- Guarded by the `integration` build tag, so plain `go test ./...` skips it
- Nodes bind port 0, so concurrent runs on one host do not collide
- `make integration-test` runs it directly; `make test-transport` runs it inside Docker

**Location**: `test/transport/` (see `test/transport/README.md`)

**Example** (a generic end-to-end flow through `service.FrostService`, not a copy of a test in the repository):
```go
func TestFROST_EndToEnd_2of3(t *testing.T) {
    // This test runs the complete FROST protocol
    suite := ristretto255_sha512.New()
    service := service.NewFrostService(suite)

    // Key generation
    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }
    keyPackages, pubKey, err := service.GenerateKeys(config, []frost.Identifier{1, 2, 3})
    require.NoError(t, err)

    // Signing
    message := []byte("Integration test message")
    signers := []frost.KeyPackage{keyPackages[0], keyPackages[1]}
    signature, err := service.Sign(signers, message)
    require.NoError(t, err)

    // Verification
    err = service.Verify(message, signature, pubKey)
    require.NoError(t, err)
}
```

### Test Vector Validation

Validates implementation against RFC 9591 test vectors.

**Location**: `test/testvectors/`

**Purpose**: Ensure RFC compliance

**Example**:
```go
func TestRFC9591_Ristretto255SHA512_FullProtocol(t *testing.T) {
    // Validates all components against RFC test vectors
    tv := Ristretto255SHA512Vector()
    suite := ristretto255_sha512.New()

    // Validate group keys
    // Validate participant shares
    // Validate round 1 commitments
    // Validate binding factors
    // Validate signature shares
    // Validate final signature
}
```

`test/testvectors/rfc9591_test.go` also has `TestRFC9591_AllCiphersuites_*` tests and a `FullProtocol` test per ciphersuite (Ed25519, Ed448, P-256, secp256k1).

### RFC Compliance Tests

`test/rfc/` holds per-section RFC 9591 tests (`section3_test.go` through `appendixe_test.go`; see `test/rfc/README.md`).

- `make test-rfc` runs them with `-short`, which skips the timing-based side-channel tests in `section7_1_sidechannel_test.go`
- `make test-rfc-full` runs everything, including those timing tests
- `make coverage-rfc` generates coverage for the suite

The side-channel tests measure nanosecond timing differences and can flake on a CPU-capped shared runner, so no CI workflow runs `test/rfc` or `test/testvectors`; run them locally.

### Benchmark Tests

Benchmarks for critical operations. They live alongside the source in several packages (for example `pkg/frost/signing/participant_test.go`, the `group` and `ciphersuite` packages, and `pkg/frost/helpers`).

**Example** (illustrative; `BenchmarkSign_2of3` is not a benchmark in the repository):
```go
func BenchmarkSign_2of3(b *testing.B) {
    suite := ristretto255_sha512.New()
    service := service.NewFrostService(suite)

    // Setup
    config := frost.Configuration{MinSigners: 2, MaxSigners: 3, Group: suite.Group()}
    keyPackages, _, _ := service.GenerateKeys(config, []frost.Identifier{1, 2, 3})
    message := []byte("Benchmark message")
    signers := []frost.KeyPackage{keyPackages[0], keyPackages[1]}

    // Benchmark
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = service.Sign(signers, message)
    }
}
```

## Running Tests

### All Tests

```bash
# Run all unit tests (./pkg/..., verbose, with the race detector)
make test
```

### Package-Specific Tests

There are no per-package `make test-*` targets; use `go test` directly:

```bash
# Core frost package
go test -race ./pkg/frost/

# Signing package
go test -race ./pkg/frost/signing/

# Key generation packages
go test -race ./pkg/frost/keygen/...

# Ristretto255 group
go test -race ./pkg/frost/group/ristretto255/

# Ristretto255-SHA512 ciphersuite
go test -race ./pkg/frost/ciphersuite/ristretto255_sha512/
```

### Integration Tests

```bash
# Run the build-tagged transport suite directly (no Docker)
make integration-test

# Run the same suite inside a Docker container
make test-transport
```

### Test Vector Validation

```bash
# Run RFC 9591 test vector validation
go test -v ./test/testvectors/

# Specific test vector
go test -v ./test/testvectors/ -run TestRFC9591_Ristretto255SHA512_FullProtocol
```

### Specific Tests

```bash
# Run specific test by name
go test -v ./pkg/frost/signing/ -run TestParticipant_RoundOne

# Run tests matching pattern
go test -v ./pkg/frost/... -run TestSign
```

### Race Detection

`make test`, `make coverage`, `make integration-test` and the CI unit job all run with `-race`:

```bash
# Race detection is enabled by default in the Makefile
make test

# Manually enable race detection
go test -race ./...
```

## Code Coverage

### Generate Coverage Report

```bash
# Generate coverage for all packages
make coverage

# HTML report is written to coverage/coverage.html (it is not opened for you)
# and a per-function summary plus the total is printed
```

### Package-Specific Coverage

```bash
# Frost core package
make coverage-frost

# Signing package
make coverage-signing

# Key generation package
make coverage-keygen

# Helpers package
make coverage-helpers

# Group implementations
make coverage-group

# Ciphersuite implementations (all suites)
make coverage-ciphersuite

# Service layer
make coverage-service

# RFC compliance tests
make coverage-rfc
```

Each prints `go tool cover -func` output: one line per function with its coverage, then a `total:` line. Profiles are written under `coverage/`.

### Coverage Goals

Each package should aim for:
- **Statement coverage**: 90% (the project goal; not enforced by CI)
- **Functions**: All public functions tested
- **Error Paths**: All error conditions tested
- **Edge Cases**: Boundary conditions tested

## Benchmarks

### Run Benchmarks

```bash
# Run all benchmarks under ./pkg/... (go test -bench=. -benchmem)
make bench

# One package
go test -bench=. -benchmem ./pkg/frost/signing/
```

### Performance

go-frost defines no performance targets and publishes no benchmark results. Timings depend on the ciphersuite, hardware and Go version; run `make bench` on the machine you care about.

## Writing Tests

### Test Structure

Follow the AAA pattern:

```go
func TestFeature_Scenario(t *testing.T) {
    // Arrange: Setup test data
    suite := ristretto255_sha512.New()
    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }

    // Act: Execute the operation
    keyPackages, pubKey, err := service.GenerateKeys(config, []frost.Identifier{1, 2, 3})

    // Assert: Verify expectations
    require.NoError(t, err)
    assert.Len(t, keyPackages, 3)
    assert.NotNil(t, pubKey)
}
```

### Test Naming

```go
// Pattern: Test{Component}_{Scenario}
func TestParticipant_RoundOne_Success(t *testing.T) {}
func TestParticipant_RoundOne_InvalidKeyPackage(t *testing.T) {}
func TestAggregator_Aggregate_InsufficientShares(t *testing.T) {}
```

### Error Testing

Always test error paths:

```go
func TestGenerateKeys_InvalidThreshold(t *testing.T) {
    suite := ristretto255_sha512.New()
    service := service.NewFrostService(suite)

    // MinSigners > MaxSigners (invalid)
    config := frost.Configuration{
        MinSigners: 3,
        MaxSigners: 2,
        Group:      suite.Group(),
    }

    _, _, err := service.GenerateKeys(config, []frost.Identifier{1, 2})

    // Verify error
    require.Error(t, err)
    assert.ErrorIs(t, err, frost.ErrInvalidThreshold)
}
```

### Table-Driven Tests

Use table-driven tests for multiple scenarios:

```go
func TestLagrangeCoefficient(t *testing.T) {
    tests := []struct {
        name         string
        identifier   frost.Identifier
        participants []frost.Identifier
        wantErr      bool
    }{
        {
            name:         "2-of-3 first participant",
            identifier:   1,
            participants: []frost.Identifier{1, 2},
            wantErr:      false,
        },
        {
            name:         "participant not in list",
            identifier:   1,
            participants: []frost.Identifier{2, 3},
            wantErr:      true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Mock Objects

Use mocks for testing interfaces. The repository ships `MockGroup`, `MockElement` and `MockScalar` (`NewMockGroup`, `NewMockGroupWithName`) and a mock ciphersuite:

```go
// Illustrative: a hand-rolled mock implements the group.Group interface
type mockGroup struct {
    name string
    // ... other fields
}

func (m *mockGroup) Name() string { return m.name }
// ... implement other interface methods
```

**Location**: `pkg/frost/helpers/testutil/` (`mock_group.go`, `mock_ciphersuite.go`)

### Test Helpers

Create helper functions for common test setup:

```go
func createTestKeyPackage(id frost.Identifier, suite ciphersuite.Ciphersuite) frost.KeyPackage {
    grp := suite.Group()
    secret, _ := grp.RandomScalar()
    pubKey := grp.ScalarBaseMult(secret)

    return frost.KeyPackage{
        Identifier:     id,
        SecretShare:    secret,
        GroupPublicKey: pubKey,
    }
}
```

## Test Organization

### File Structure

```
pkg/frost/signing/
├── participant.go           # Implementation
├── participant_test.go      # Unit tests
├── aggregator.go            # Implementation
├── aggregator_test.go       # Unit tests
├── coordinator.go           # Implementation
└── coordinator_test.go      # Unit tests

test/
├── rfc/                     # RFC 9591 section-by-section tests
│   ├── section3_test.go ... appendixe_test.go
│   └── README.md
├── testvectors/             # RFC 9591 test vectors
│   ├── vectors.go
│   └── rfc9591_test.go
└── transport/               # build-tagged distributed integration suite
    ├── node.go
    ├── coordinator.go
    ├── transport_test.go
    ├── Dockerfile
    └── README.md
```

### Test Dependencies

`github.com/stretchr/testify` is a dependency (see `go.mod`) and is used by some tests (for example `pkg/secmem` and `pkg/frost/keygen`); many packages, including `pkg/frost/signing` and `test/rfc`, use only the standard `testing` package. Either style is fine; match the package you are editing.

```go
import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)
```

## Continuous Integration

### Pre-commit Checks

Before committing:

```bash
# Run all tests
make test

# Check coverage
make coverage

# Run linters
make lint

# Format code
make fmt
```

### CI Pipeline

The workflow is `.github/workflows/ci.yml`; `make ci` runs a similar set of checks locally.

**Checks** (see the workflow for the exact trigger rules):
1. Unit tests pass (`go test -race ./pkg/... ./cmd/...`)
2. Integration suite passes (`make integration-test`)
3. Coverage is generated and uploaded to Codecov (no threshold gate)
4. Linters and static analysis pass (`go vet`, golangci-lint, staticcheck)
5. Security scans pass (gosec, govulncheck, `go mod verify`, trivy)
6. The CLI and the C libraries build

Benchmarks are not run or compared in CI, and neither are `test/rfc` or `test/testvectors`.

## Debugging Tests

### Verbose Output

```bash
# Run with verbose output
go test -v ./pkg/frost/signing/

# Show individual test results
go test -v ./... | grep -E '(PASS|FAIL)'
```

### Debug Specific Test

```bash
# Run single test with verbose output
go test -v ./pkg/frost/signing/ -run TestParticipant_RoundOne

# Without the test cache
go test -count=1 -v ./pkg/frost/signing/ -run TestParticipant_RoundOne
```

### Test Timeout

```bash
# Increase timeout for slow tests
go test -timeout 5m ./...

# make test uses -timeout 60s per package; plain go test defaults to 10m
```

### Failed Test Analysis

When tests fail:

1. **Read error message**: Understand what failed
2. **Check test vector**: Compare with expected values
3. **Add logging**: Use t.Logf() for debugging
4. **Isolate test**: Run failing test individually
5. **Check race conditions**: Run with -race flag

## Best Practices

### DO

- Write tests first (TDD)
- Test error paths
- Use meaningful test names
- Keep tests independent
- Use table-driven tests
- Mock external dependencies
- Aim for 90%+ coverage
- Run tests before committing

### DON'T

- Use skip guards (-short flags) to hide unit tests
- Write tests just for coverage
- Create interdependent tests
- Modify host system in unit tests
- Use time.Sleep() in tests
- Commit without running tests
- Ignore failing tests
- Test implementation details

## Troubleshooting

### Tests Hang

```bash
# Add timeout
go test -timeout 30s ./...

# Check for deadlocks
go test -race -timeout 30s ./...
```

### Flaky Tests

- Remove time-dependent logic
- Ensure test isolation
- Check for race conditions
- Use deterministic randomness in tests

### Coverage Not Updating

```bash
# Clean and regenerate
make clean
make coverage
```

### Integration Tests Fail

```bash
# Run the suite without Docker first
make integration-test

# For the containerized run, check Docker is running
docker ps

# Rebuild the transport test image
make test-transport
```

## References

- [Go Testing Documentation](https://pkg.go.dev/testing)
- [Testify Framework](https://github.com/stretchr/testify)
- [Table-Driven Tests](https://go.dev/wiki/TableDrivenTests)
- [CLAUDE.md Testing Requirements](../../CLAUDE.md)
