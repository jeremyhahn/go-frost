# RFC 9591 Compliance

> **Status: NORMATIVE** · Scope: RFC 9591 conformance of go-frost · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

go-frost implements the FROST threshold signature scheme as specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html). The RFC test vectors run under `test/rfc` and `test/testvectors`.

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
- **Section 6**: FROST ciphersuites (all five, see below)

### Security Requirements (RFC 9591 Section 7)

Section 7 requirements map to code in `pkg/frost/security` (nonce tracking, authentication, reputation, validation) and `pkg/frost/signing` (identifiable abort via `AggregateWithVerification`). See [../security/README.md](../security/README.md).

## Test Coverage

- **RFC Test Vectors**: `test/rfc`, `test/testvectors`
- **Unit Tests**: next to each package
- **Transport Tests**: `test/transport`

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

1. **Service Layer**: Clean API abstraction over core protocol (`pkg/frost/service`)
2. **Session Management**: Coordinated multi-participant sessions (`SessionManager`)
3. **Enhanced Security**: Additional protections beyond RFC minimums (`pkg/frost/security`)

## References

- [RFC 9591: The FROST Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST20 Paper](https://eprint.iacr.org/2020/852)
- [Security Documentation](../security/README.md)
