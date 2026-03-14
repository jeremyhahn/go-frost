# go-frost

A production-ready Go implementation of the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme as specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.26.1-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![RFC 9591](https://img.shields.io/badge/RFC-9591-green.svg)](https://www.rfc-editor.org/rfc/rfc9591.html)

## Overview

FROST is a threshold signature scheme that enables a threshold number of participants to cooperatively generate a signature, providing improved distribution of trust and redundancy with respect to secret keys. This library follows RFC 9591 and the [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) implementation.

### Key Features

- Implements all RFC 9591 requirements across all 5 ciphersuites
- 90%+ test coverage, benchmarks, and documentation in docs/
- Constant-time operations, nonce reuse prevention, and side-channel protection
- Service layer abstraction with typed errors and clear interfaces
- Lock-free algorithms, optimized for low latency and high throughput
- Type safe: minimal, audited unsafe usage limited to secure memory zeroing

### Supported Ciphersuites

All 5 RFC 9591 ciphersuites are implemented:

- **FROST(Ed25519, SHA-512)** - RFC 6.1 (Edwards curve, 128-bit security)
- **FROST(ristretto255, SHA-512)** - RFC 6.2 (extra safety checks, default)
- **FROST(Ed448, SHAKE256)** - RFC 6.3 (highest security, 224-bit security)
- **FROST(P-256, SHA-256)** - RFC 6.4 (NIST standard, 128-bit security)
- **FROST(secp256k1, SHA-256)** - RFC 6.5 (Bitcoin curve, 128-bit security)

All ciphersuites: 95%+ test coverage, benchmarks, table-driven integration tests

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

- Go 1.26.1 or higher
- No external dependencies for core library
- Optional: go-xkms or go-objstore for advanced storage backends
- Optional: HSM/TPM libraries if using hardware-backed keys

## Documentation

Documentation is in the [docs/](docs/) directory:

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
pkg/
├── frost/
│   ├── types.go              # Core type definitions
│   ├── errors.go             # Typed error definitions
│   ├── group/                # Prime-order group interface and implementations
│   ├── ciphersuite/          # Ciphersuite implementations
│   ├── helpers/              # Protocol helper functions
│   ├── signing/              # Two-round signing protocol
│   │   ├── participant.go    # Participant implementation
│   │   ├── aggregator.go     # Signature aggregation
│   │   └── coordinator.go    # Optional coordinator
│   ├── keygen/               # Key generation (trusted dealer)
│   ├── keystore/             # Secure key storage
│   ├── security/             # Authentication and security
│   └── service/              # High-level service API
├── storage/                  # Storage backends (file, memory)
└── signer/                   # Crypto signer abstraction (HSM, TPM support)
```

See [Architecture Documentation](docs/architecture/README.md) for details.

### Storage and Key Management

go-frost includes its own storage and cryptographic signer implementations, with interface compatibility for external providers:

**Storage Backends** (`pkg/storage/`):
- **Memory Backend**: Fast in-memory storage for testing and development
- **File Backend**: Secure file-based storage with atomic writes and configurable permissions
- **Interface Compatible**: Works with go-xkms and go-objstore implementations
- **Extensible**: Implement `storage.Backend` for custom backends (HSM, TPM, cloud KMS, DHT, etc.)

**Crypto Signers** (`pkg/signer/`):
- **Software Keys**: Ed25519 signing using crypto/ed25519
- **HSM/TPM Support**: Use any `crypto.Signer` implementation (PKCS#11, cloud KMS, etc.)
- **go-xkms Compatible**: Works with go-xkms backed signers
- **Standard Interface**: All signers implement Go's `crypto.Signer`

Example with custom storage:
```go
import (
    "github.com/jeremyhahn/go-frost/pkg/storage"
    "github.com/jeremyhahn/go-frost/pkg/frost/keystore"
)

// Use built-in file storage
backend, err := storage.NewFileBackend("/var/lib/frost")
if err != nil {
    return err
}

// Or use go-xkms backend (interface compatible)
// backend, err := keychain.NewFileBackend("/var/lib/frost")

// Create keystore with any compatible backend
store := keystore.NewKeychainStore(backend, groupCfg)
```

Example with HSM-backed signer:
```go
import (
    "github.com/jeremyhahn/go-frost/pkg/signer"
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Use software signer
softwareSigner, err := signer.GenerateEd25519Signer()

// Or use HSM/TPM backed crypto.Signer
hsmSigner := getHSMSigner() // Returns crypto.Signer
frostSigner, err := signer.FromCryptoSigner(hsmSigner)

// Sign FROST commitments with either signer
proof, err := security.SignCommitmentWithSigner(participantID, commitment, frostSigner)
```

## Security

This implementation prioritizes security:

- Nonce reuse prevention: tracking prevents catastrophic key exposure
- Input validation: all inputs validated at API boundaries
- Constant-time operations: timing attack mitigation where applicable
- Unsafe usage is limited to the `pkg/secmem` package for zeroing secret string backing memory, with gosec annotations
- Secure memory via memguard: the `pkg/secmem` package provides mlock'd memory (protected from swap), encrypted-at-rest storage via Enclave (XSalsa20-Poly1305), and guard pages for sensitive byte slices
- Identifiable abort: malicious participants can be identified
- Error sanitization: prevents information leakage

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
make test
make test-rfc

# Run benchmarks
make bench

# View coverage
make coverage
```

## Performance

The implementation uses lock-free algorithms where possible, optimized cryptographic operations, and minimal allocations in hot paths.

See benchmark results:
```bash
make bench
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [go-frostdkg](https://github.com/jeremyhahn/go-frostdkg) - FROST Distributed Key Generation for trustless key setup
- [go-xkms](https://github.com/jeremyhahn/go-xkms) - Key management and storage
- [go-trusted-ca](https://github.com/jeremyhahn/go-trusted-ca) - Certificate Authority
- [go-trusted-platform](https://github.com/jeremyhahn/go-trusted-platform) - Trusted Computing Platform

**Note**: This library uses a trusted dealer for key generation. For distributed key generation where no single party sees the full secret, use [go-frostdkg](https://github.com/jeremyhahn/go-frostdkg).

## References

- [RFC 9591: The FROST Protocol for Two-Round Schnorr Signatures](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST20: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)

## Acknowledgments

This implementation is based on the FROST protocol as specified in RFC 9591 and the original FROST20 paper by Komlo and Goldberg.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/jeremyhahn/go-frost/issues)
