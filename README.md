# go-frost

A production-ready Go implementation of the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme as specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![RFC 9591](https://img.shields.io/badge/RFC-9591-green.svg)](https://www.rfc-editor.org/rfc/rfc9591.html)

## Overview

FROST is a threshold signature scheme that enables a threshold number of participants to cooperatively generate a signature, providing improved distribution of trust and redundancy with respect to secret keys. This implementation follows RFC 9591 and achieves 100% compliance.

### Key Features

- **RFC 9591 Compliant**: Full implementation with all RFC requirements met
- **Production Ready**: 90%+ test coverage, comprehensive benchmarks, extensive documentation
- **Secure by Design**: Constant-time operations, nonce reuse prevention, side-channel protection
- **Clean Architecture**: Service layer abstraction, typed errors, clear interfaces
- **High Performance**: Lock-free algorithms, optimized for low latency and high throughput
- **Type Safe**: No unsafe operations or pointer magic, pure Go implementation

### Supported Ciphersuites

- **FROST(ristretto255, SHA-512)** - Production ready, fully tested

Architecture supports additional RFC 9591 ciphersuites:
- FROST(Ed25519, SHA-512)
- FROST(Ed448, SHAKE256)
- FROST(P-256, SHA-256)
- FROST(secp256k1, SHA-256)

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

func main() {
    // Create FROST service with ristretto255 ciphersuite
    suite := ristretto255_sha512.New()
    frostService := service.NewFrostService(suite)

    // Configure 2-of-3 threshold signature scheme
    config := frost.Configuration{
        MinSigners: 2,  // Threshold
        MaxSigners: 3,  // Total participants
        Group:      suite.Group(),
    }

    // Generate keys for 3 participants
    participantIDs := []frost.Identifier{1, 2, 3}
    keyPackages, groupPublicKey, err := frostService.GenerateKeys(config, participantIDs)
    if err != nil {
        panic(err)
    }

    // Sign a message using participants 1 and 2
    message := []byte("Hello, FROST!")
    signingPackages := []frost.KeyPackage{keyPackages[0], keyPackages[1]}
    signature, err := frostService.Sign(signingPackages, message)
    if err != nil {
        panic(err)
    }

    // Verify the signature
    err = frostService.Verify(message, signature, groupPublicKey)
    if err != nil {
        fmt.Println("Signature verification failed:", err)
        return
    }

    fmt.Println("Signature verified successfully!")
}
```

### CLI: Distributed Threshold Signing

The `frost` CLI enables distributed signing where participants on different machines collaborate:

```bash
# Coordinator: Generate keys for 2-of-3 threshold
frost keygen --min 2 --max 3 --output keys.json

# Round 1: Each participant generates their commitment (on separate machines)
# Participant 1:
frost commit --keys keys.json --id 1
# Participant 2:
frost commit --keys keys.json --id 2

# Coordinator: Collect commitments and distribute to participants
frost collect-commitments --output commitments.json

# Round 2: Each participant creates signature share
# Participant 1:
frost sign-share --keys keys.json --id 1 --commitments commitments.json --message "Hello FROST"
# Participant 2:
frost sign-share --keys keys.json --id 2 --commitments commitments.json --message "Hello FROST"

# Coordinator: Collect shares and aggregate into final signature
frost collect-shares --output shares.json
frost aggregate --keys keys.json --commitments commitments.json --shares shares.json --message "Hello FROST"

# Anyone: Verify the signature
frost verify --signature frost-signature.json
```

See [CLI Documentation](docs/cli/README.md) for details.

## Installation

```bash
go get github.com/jeremyhahn/go-frost
```

### Requirements

- Go 1.21 or higher
- No external dependencies for core library

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[Getting Started](docs/getting-started/README.md)** - Installation and first signature
- **[Examples](docs/examples/README.md)** - Complete code examples
- **[API Reference](docs/api/reference.md)** - Full API documentation
- **[Implementation Guides](docs/guides/README.md)** - Integration and best practices
- **[Security](docs/security/README.md)** - Security considerations and best practices
- **[Architecture](docs/architecture/README.md)** - System design and architecture
- **[RFC Compliance](docs/rfc-compliance/README.md)** - RFC 9591 compliance status

## Building and Testing

```bash
# Clone the repository
git clone https://github.com/jeremyhahn/go-frost
cd go-frost

# Build
make build

# Run unit tests
make test

# Run integration tests (Docker required)
make integration-test

# Generate coverage report
make coverage

# Run benchmarks
make bench

# Run linters
make lint
```

## Architecture

The implementation follows a clean, layered architecture:

```
pkg/frost/
├── types.go              # Core type definitions
├── errors.go             # Typed error definitions
├── group/                # Prime-order group interface and implementations
├── ciphersuite/          # Ciphersuite implementations
├── helpers/              # Protocol helper functions
├── signing/              # Two-round signing protocol
│   ├── participant.go    # Participant implementation
│   ├── aggregator.go     # Signature aggregation
│   └── coordinator.go    # Optional coordinator
├── keygen/               # Key generation (trusted dealer)
└── service/              # High-level service API
```

See [Architecture Documentation](docs/architecture/README.md) for details.

## Security

This implementation prioritizes security:

- **Nonce Reuse Prevention**: Comprehensive tracking prevents catastrophic key exposure
- **Input Validation**: All inputs validated at API boundaries
- **Constant-Time Operations**: Timing attack mitigation where applicable
- **No Unsafe Code**: Pure Go, no pointer magic or unsafe operations
- **Identifiable Abort**: Malicious participants can be identified
- **Error Sanitization**: Prevents information leakage

**IMPORTANT**: Before deploying to production, read the [Security Documentation](docs/security/README.md), especially [Error Sanitization](docs/security/error-sanitization.md) to prevent signing oracle attacks.

## Testing

The project follows Test-Driven Development (TDD) with comprehensive coverage:

- **Unit Tests**: 90%+ coverage on all packages, fast in-memory tests
- **Integration Tests**: End-to-end testing in Docker containers
- **RFC Test Vectors**: All official RFC 9591 test vectors passing
- **Benchmarks**: Performance tests for critical operations
- **Security Tests**: Side-channel and attack vector validation

```bash
# Run specific test suites
make test-unit
make test-integration
make test-rfc

# Run benchmarks
make bench

# View coverage
make coverage
```

## Performance

Designed for high performance:

- Lock-free algorithms where possible
- Efficient memory management
- Optimized cryptographic operations
- Minimal allocations in hot paths

See benchmark results:
```bash
make bench
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [RFC 9591: The FROST Protocol for Two-Round Schnorr Signatures](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST20: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)

## Acknowledgments

This implementation is based on the FROST protocol as specified in RFC 9591 and the original FROST20 paper by Komlo and Goldberg.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/jeremyhahn/go-frost/issues)
