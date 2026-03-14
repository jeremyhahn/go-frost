# go-frost Documentation

Complete documentation for go-frost, a production-ready Go implementation of the FROST threshold signature scheme ([RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)).

## Quick Navigation

### New Users - Start Here

1. **[Getting Started](getting-started/README.md)** - Installation and first signature
2. **[Examples](examples/README.md)** - Complete code examples
3. **[API Reference](api/reference.md)** - API documentation
4. **[RFC 9591](rfc9591.txt)** - RFC 9591
5. **[FROST: Flexible Round-Optimized Schnorr Threshold Signatures](2020-852.pdf)** - FROST Whitepaper

### Implementation Guides

6. **[Guides](guides/README.md)** - Implementation and integration guides
   - [Integration Guide](guides/integration.md)
   - [Implementation Best Practices](guides/implementation.md)
   - [Testing Strategies](guides/testing.md)
   - [Keystore Management](guides/keystore.md)
   - [Scalability Patterns](guides/scalability.md)
   - [Abort Protocol](guides/abort-protocol.md)
   - [Pre-hashing Modes](guides/pre-hashing.md)

### Security - Critical Reading

7. **[Security](security/README.md)** - Security best practices and considerations
   - **[Error Sanitization](security/error-sanitization.md)** - CRITICAL: Signing oracle prevention
   - [Channel Security](security/channel-security.md) - TLS and authentication
   - [Misbehavior Tracking](security/misbehavior-tracking.md) - Participant reputation
   - [Side-Channel Protection](security/side-channel-protection.md) - Timing attack prevention
   - [Security Testing](security/testing.md) - Security test procedures

### Architecture & Design

8. **[Architecture](architecture/README.md)** - System architecture and design
   - [Components](architecture/components.md) - Detailed component architecture

### RFC Compliance

9. **[RFC 9591 Compliance](rfc-compliance/README.md)** - RFC compliance documentation
   - [Compliance Status](rfc-compliance/status.md) - Detailed compliance tracking
   - [Test Coverage](rfc-compliance/test-coverage.md) - RFC test vector coverage

## Documentation Structure

```
docs/
├── README.md (this file)
├── getting-started/          # Quick start and installation
├── guides/                   # Implementation guides
├── examples/                 # Code examples
├── api/                      # API reference
├── security/                 # Security documentation
├── architecture/             # System design
└── rfc-compliance/          # RFC 9591 compliance
```

## Overview

**go-frost** is a production-ready Go implementation of the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme. FROST enables a threshold number of participants to cooperatively generate a signature, providing improved distribution of trust and redundancy with respect to secret keys.

### Key Features

- RFC 9591 compliant with full test vector coverage
- 90%+ test coverage with comprehensive documentation
- Constant-time operations, typed errors, secure memory management via memguard
- Service layer with clear abstractions
- Lock-free algorithms optimized for low latency

### Supported Ciphersuites

- FROST(ristretto255, SHA-512)
- Architecture supports: Ed25519, Ed448, P-256, secp256k1

## Quick Start

```go
import (
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// Create FROST service
suite := ristretto255_sha512.New()
frostService := service.NewFrostService(suite)

// Generate keys (2-of-3 threshold)
config := frost.Configuration{
    MinSigners: 2,
    MaxSigners: 3,
    Group:      suite.Group(),
}
participantIDs := []frost.Identifier{1, 2, 3}
keyPackages, groupPublicKey, err := frostService.GenerateKeys(config, participantIDs)

// Sign with 2 participants
msg := []byte("Hello, FROST!")
signingPackages := []frost.KeyPackage{keyPackages[0], keyPackages[1]}
signature, err := frostService.Sign(signingPackages, msg)

// Verify signature
err = frostService.Verify(msg, signature, groupPublicKey)
```

See [Getting Started](getting-started/README.md) for detailed instructions.

## Building and Testing

```bash
# Build
make build

# Run tests
make test

# Run integration tests (Docker required)
make test

# Coverage report
make coverage

# Benchmarks
make bench

# Linters
make lint
```

See [Testing Guide](guides/testing.md) for detailed testing information.

## Security Considerations

Before deploying to production:

1. [Error Sanitization](security/error-sanitization.md) - Prevents signing oracle attacks (read this first)
2. [Channel Security](security/channel-security.md) - TLS and authentication
3. [Misbehavior Tracking](security/misbehavior-tracking.md) - Participant reputation
4. [Side-Channel Protection](security/side-channel-protection.md) - Timing attacks
5. [Security Testing](security/testing.md) - Security test suite

See [Security Documentation](security/README.md) for complete security guidance.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code coverage remains at 90%+
- Code follows [Go style guidelines](https://google.github.io/styleguide/go/guide)
- Documentation is updated

## License

See [LICENSE](../LICENSE) file for details.

## References

- [RFC 9591: The FROST Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST20: Original Paper](https://eprint.iacr.org/2020/852)
- [Project Repository](https://github.com/jeremyhahn/go-frost)

## Support

- [GitHub Issues](https://github.com/jeremyhahn/go-frost/issues)
- [GitHub Discussions](https://github.com/jeremyhahn/go-frost/discussions)
- [Security Policy](security/README.md#reporting-security-issues)
