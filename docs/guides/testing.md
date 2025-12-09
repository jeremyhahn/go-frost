# Testing Guide

Comprehensive testing guide for go-frost.

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

go-frost follows Test-Driven Development (TDD) principles with a goal of 90%+ code coverage. All tests are meaningful and provide real value against regressions and bugs.

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

- **Minimum**: 90% code coverage per package
- **Unit Tests**: 90%+ coverage
- **Integration Tests**: 90%+ coverage
- **Edge Cases**: All error paths tested
- **No Skip Guards**: All tests must run (no `-short` flags)

### Test Pyramid

```
        /\
       /  \    E2E (Integration)
      /____\   10%
     /      \
    / Unit   \ 90%
   /__________\
```

- **90% Unit Tests**: Fast, isolated, comprehensive
- **10% Integration Tests**: End-to-end validation

## Test Types

### Unit Tests

Fast, in-memory tests for individual functions and components.

**Characteristics**:
- Run in memory
- No network I/O
- No file system modifications
- No Docker required
- Execute in < 30 seconds
- 90%+ coverage required

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
- Run in Docker containers
- Test all layers together
- Use real service resources
- Execute in < 5 minutes
- 90%+ coverage required

**Location**: `test/integration/`

**Example**:
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

### Benchmark Tests

Performance tests for critical operations.

**Location**: Alongside source files (`*_test.go`)

**Example**:
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
# Run all unit tests
make test

# Verbose output
make test ARGS="-v"
```

### Package-Specific Tests

```bash
# Core frost package
make test-frost

# Signing package
make test-signing

# Key generation package
make test-keygen

# Ristretto255 group
make test-ristretto255

# Ristretto255-SHA512 ciphersuite
make test-ristretto255-sha512
```

### Integration Tests

```bash
# Run integration tests (requires Docker)
make test

# This builds a Docker image and runs tests inside
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

All tests run with race detector enabled:

```bash
# Race detection is enabled by default in Makefile
make test

# Manually enable race detection
go test -race ./...
```

## Code Coverage

### Generate Coverage Report

```bash
# Generate coverage for all packages
make coverage

# Opens HTML report in browser
# Report saved to: coverage/coverage.html
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

# Ciphersuite implementations
make coverage-ciphersuite
make coverage-ristretto255-sha512

# Service layer
make coverage-service
```

### Coverage Output Example

```
pkg/frost/signing/participant.go:42:    NewParticipant     100.0%
pkg/frost/signing/participant.go:52:    Identifier         100.0%
pkg/frost/signing/participant.go:57:    RoundOne           100.0%
pkg/frost/signing/participant.go:75:    RoundTwo           100.0%
pkg/frost/signing/participant.go:123:   computeChallenge   100.0%
total:                                  (statements)        94.2%
```

### Coverage Requirements

Each package must maintain:
- **Minimum**: 90% statement coverage
- **Functions**: All public functions tested
- **Error Paths**: All error conditions tested
- **Edge Cases**: Boundary conditions tested

## Benchmarks

### Run Benchmarks

```bash
# Run all benchmarks
make bench

# Package-specific benchmarks
make bench-signing
make bench-keygen
make bench-ristretto255
make bench-ristretto255-sha512
```

### Benchmark Output Example

```
BenchmarkSign_2of3-8              1000    1123456 ns/op    12345 B/op    123 allocs/op
BenchmarkSign_3of5-8               500    2234567 ns/op    23456 B/op    234 allocs/op
BenchmarkVerify-8                 2000     567890 ns/op     5678 B/op     56 allocs/op
```

### Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Key Generation (3 participants) | < 10ms | Per participant |
| Round One | < 1ms | Per participant |
| Round Two | < 5ms | Per participant |
| Aggregation | < 5ms | For 5 participants |
| Verification | < 2ms | Single verification |

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

Use mocks for testing interfaces:

```go
// Mock group for testing
type mockGroup struct {
    name string
    // ... other fields
}

func (m *mockGroup) Name() string { return m.name }
// ... implement other interface methods
```

**Location**: `pkg/frost/helpers/testutil/`

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
├── aggregator.go           # Implementation
├── aggregator_test.go      # Unit tests
└── coordinator_test.go     # Unit tests

test/
├── integration/
│   ├── frost_integration_test.go
│   └── Dockerfile
└── testvectors/
    ├── vectors.go
    └── rfc9591_test.go
```

### Test Dependencies

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

Automated testing runs on:
- Every commit
- Every pull request
- Before merges

**Checks**:
1. Unit tests pass
2. Integration tests pass
3. Coverage meets 90%+ threshold
4. Linters pass
5. Race detector clean
6. Benchmarks don't regress

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

# With additional logging
go test -v -args -debug ./pkg/frost/signing/ -run TestParticipant_RoundOne
```

### Test Timeout

```bash
# Increase timeout for slow tests
go test -timeout 5m ./...

# Default timeout is 30s for unit tests
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

- Use skip guards (-short flags)
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
# Check Docker is running
docker ps

# Rebuild integration test image
docker build -t go-frost-test:latest -f test/integration/Dockerfile .

# Check logs
docker logs <container-id>
```

## References

- [Go Testing Documentation](https://pkg.go.dev/testing)
- [Testify Framework](https://github.com/stretchr/testify)
- [Table-Driven Tests](https://go.dev/wiki/TableDrivenTests)
- [CLAUDE.md Testing Requirements](../CLAUDE.md)
