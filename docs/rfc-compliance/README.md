# RFC 9591 Compliance

go-frost is a compliant implementation of the FROST threshold signature scheme as specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).

## Compliance Status

**Current Status**: 100% RFC 9591 Compliant

See [status.md](status.md) for detailed compliance tracking and progress.

## RFC 9591 Overview

The FROST (Flexible Round-Optimized Schnorr Threshold) protocol enables a threshold number of participants to cooperatively generate a Schnorr signature. The protocol is two-round and provides security against malicious participants.

### Key Features

- **Two-round signing protocol**: Minimizes communication rounds
- **Threshold signatures**: t-of-n signature generation
- **Security**: Proven secure in the Random Oracle Model
- **Flexibility**: Supports multiple ciphersuites and group configurations

## Implemented Components

### Core Protocol (RFC 9591 Sections 4-6)

- **Section 4**: Prime-order group operations
- **Section 5**: Two-round signing protocol
  - Round 1: Commitment generation
  - Round 2: Signature share generation
  - Aggregation: Signature combination
- **Section 6**: FROST ciphersuites
  - FROST(ristretto255, SHA-512) - Fully implemented
  - Additional ciphersuites: Architecture ready

### Security Requirements (RFC 9591 Section 7)

All security requirements from Section 7 are implemented:

1. **Nonce Reuse Prevention** - Tracked and prevented
2. **Participant Authentication** - Cryptographic verification
3. **Identifiable Abort** - Malicious participants identified
4. **Input Validation** - All inputs validated
5. **Side-Channel Protection** - Constant-time operations
6. **Error Sanitization** - No information leakage

See [../security/README.md](../security/README.md) for detailed security documentation.

## Test Coverage

Comprehensive test coverage validates RFC compliance:

- **RFC Test Vectors**: All official test vectors passing
- **Unit Tests**: 90%+ coverage on all packages
- **Integration Tests**: End-to-end protocol validation
- **Security Tests**: Side-channel and attack vector testing

See [test-coverage.md](test-coverage.md) for detailed test documentation.

## Ciphersuite Support

### Supported Ciphersuites

All five RFC 9591 standard ciphersuites are implemented:

- **FROST(ristretto255, SHA-512)**
- **FROST(Ed25519, SHA-512)**
- **FROST(Ed448, SHAKE256)**
- **FROST(P-256, SHA-256)**
- **FROST(secp256k1, SHA-256)**

## Compliance Verification

To verify RFC compliance:

```bash
# Run RFC test vectors
make test-rfc

# Run compliance test suite
go test -v ./test/rfc/...

# View test coverage
make coverage-rfc
```

## Differences from RFC

This implementation maintains full RFC compliance while adding:

1. **Service Layer**: Clean API abstraction over core protocol
2. **Session Management**: Coordinated multi-participant sessions
3. **Enhanced Security**: Additional protections beyond RFC minimums
4. **Operational Features**: Monitoring, logging, and observability

All additions are backward-compatible and maintain RFC compliance.

## References

- [RFC 9591: The FROST Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST20 Paper](https://eprint.iacr.org/2020/852)
- [Security Documentation](../security/README.md)
