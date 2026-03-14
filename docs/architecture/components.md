# go-frost Architecture Design Summary

## Overview

Architecture for the RFC 9591 FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme in Go. The design uses layered abstractions, typed errors, and a service-oriented structure.

## Project Statistics

- **Packages**: group, ciphersuite, helpers, signing, keygen, service, frost, secmem, signer, storage, and others
- **Interfaces Defined**: 15+ interfaces
- **Error Types**: 20+ typed errors with context wrapping

## Architecture Layers

### Layer 1: Group Abstraction (`pkg/frost/group/`)

**Purpose**: Abstract prime-order group operations

**Key Components**:
- `Element` interface: Group element operations (add, negate, equality)
- `Scalar` interface: Scalar field operations (add, sub, mul, inv)
- `Group` interface: Group operations (scalar mult, serialization, random generation)

**Design Decisions**:
- Interface-based design allows multiple group implementations (Ed25519, ristretto255, P-256, etc.)
- Minimal audited unsafe usage (secmem package only)
- Immutable value semantics for thread safety
- Fixed-length serialization for each group

### Layer 2: Ciphersuite Abstraction (`pkg/frost/ciphersuite/`)

**Purpose**: Combine group + hash functions for complete FROST instantiation

**Key Components**:
- `Ciphersuite` interface: Combines group with domain-separated hash functions
- Five standard ciphersuite IDs (Ed25519, ristretto255, Ed448, P-256, secp256k1)
- `Registry` interface: Ciphersuite discovery and registration

**Design Decisions**:
- H1-H5 domain-separated hash functions as RFC 9591 requires
- Pluggable architecture for adding new ciphersuites
- HashToCurve support for advanced operations

### Layer 3: Helpers (`pkg/frost/helpers/`)

**Purpose**: Protocol helper functions

**Key Components**:
- `NonceGenerator`: Secure nonce generation with RNG hedging
- `PolynomialHelper`: Polynomial operations (evaluate, interpolate)
- `BindingFactorComputer`: Compute binding factors per RFC 9591
- `GroupCommitmentComputer`: Aggregate participant commitments
- `ChallengeComputer`: Compute signature challenge
- `CommitmentListEncoder`: Encode/validate commitment lists

**Design Decisions**:
- Each helper has dedicated interface for testability
- No global state, all operations are pure functions
- Clear separation of concerns

### Layer 4: Key Generation (`pkg/frost/keygen/`)

**Purpose**: Trusted dealer key generation with VSS

**Key Components**:
- `Dealer` interface: Generate and distribute shares
- `VSS` interface: Verifiable Secret Sharing operations
- Share verification and secret recovery

**Design Decisions**:
- Implements RFC 9591 Appendix C (Trusted Dealer)
- VSS for share verification
- Polynomial-based secret sharing (Shamir)
- Future extension point for DKG (Distributed Key Generation)

### Layer 5: Signing Protocol (`pkg/frost/signing/`)

**Purpose**: Two-round FROST signing protocol

**Key Components**:
- `Participant` interface: Individual signer (round 1, round 2, verification)
- `Aggregator` interface: Signature share aggregation
- `Coordinator` interface: Optional protocol orchestration

**Design Decisions**:
- Clean separation: Participant = local operations, Coordinator = orchestration
- Coordinator is optional (supports fully distributed signing)
- Identifiable abort capability via share verification
- Stateless participant operations

### Layer 6: Service Layer (`pkg/frost/service/`)

**Purpose**: Public API with business logic separation

**Key Components**:
- `FrostService` interface: High-level API (keygen, sign, verify)
- `SigningSession` interface: Stateful signing session management
- `SessionManager` interface: Multi-session coordination

**Design Decisions**:
- **Clean abstraction**: Applications NEVER directly call signing/keygen layers
- Service layer enforces business rules and validates inputs
- Session management for async/distributed signing scenarios
- Single entry point for all FROST operations

## Core Type Definitions (`pkg/frost/types.go`)

**Key Types**:
- `Identifier`: Participant identifier (NonZeroScalar)
- `SigningCommitments`: Round 1 commitments (hiding + binding)
- `SigningNonces`: Secret nonces from round 1
- `SignatureShare`: Participant's signature contribution
- `Signature`: Complete FROST signature (R, z)
- `KeyPackage`: Participant's key material
- `Polynomial`: Secret sharing polynomial
- `Configuration`: FROST parameters (min/max signers, group)

**Design Philosophy**:
- Strongly typed (no generic interfaces or any types)
- Self-documenting with clear naming
- Immutable where possible
- Zero dependencies on external libraries

## Error Handling (`pkg/frost/errors.go`)

**Base Errors** (20+ typed errors):
- `ErrInvalidParameters`, `ErrInvalidParticipant`
- `ErrInvalidCommitment`, `ErrInvalidSignatureShare`
- `ErrInvalidThreshold`, `ErrInsufficientParticipants`
- `ErrDeserializationFailed`, `ErrIdentityElement`
- And more...

**Wrapped Errors**:
- `ParameterError`: Contextual parameter validation errors
- `ParticipantError`: Participant-specific errors with ID
- `VerificationError`: Verification failure context

**Design Philosophy**:
- NO `fmt.Errorf` usage (all errors are typed)
- Error wrapping with `Unwrap()` support
- Rich context for debugging
- Testable error conditions

## Build System (Makefile)

**Targets**:
- `make test`: Run all unit tests
- `make test`: Run integration tests
- `make coverage`: Generate coverage reports
- `make coverage-<package>`: Per-package coverage
- `make bench`: Run benchmarks
- `make bench-<package>`: Per-package benchmarks
- `make lint`: Run golangci-lint
- `make fmt`: Format code
- `make docker-build/test/run`: Docker operations

**Philosophy**:
- Package-specific targets for development velocity
- No skip guards or -short flags (explicit test separation)
- Coverage targets for each package
- Docker integration for E2E testing

## Design Principles Applied

### Clean Architecture
- Service layer never exposes implementation details
- Each layer has well-defined interfaces
- Dependencies flow inward (service -> signing -> helpers -> group)

### SOLID Principles
- Single Responsibility: Each package has one clear purpose
- Open/Closed: Interfaces allow extension without modification
- Liskov Substitution: All implementations satisfy interface contracts
- Interface Segregation: Focused interfaces (not monolithic)
- Dependency Inversion: Depend on abstractions (interfaces), not concretions

### Go Best Practices
- Google Go Style Guide compliance
- Clear, simple, concise code
- Meaningful package names
- Comprehensive godoc comments

### Performance
- Lock-free algorithm design
- Immutable data structures
- Efficient scalar/element operations
- Pre-allocated buffers where appropriate
- Benchmark suite for critical paths

### Security
- Constant-time operations (where feasible)
- Secure random number generation
- Audited unsafe usage limited to secmem package for secure memory zeroing
- Nonce reuse protection
- Input validation at all layers

## RFC 9591 Compliance

The architecture implements all required components:

- Prime-order group operations (Section 3.1)
- Cryptographic hash functions (Section 3.2)
- Helper functions (Section 4): nonce generation (4.1), polynomials (4.2), list operations (4.3), binding factors (4.4), group commitment (4.5), signature challenge (4.6)
- Two-round signing protocol (Section 5)
- Ciphersuite abstraction (Section 6)
- Trusted dealer key generation (Appendix C)
- VSS (Appendix C.2)

## Testing Strategy

### Unit Tests
- Fast, in-memory tests
- 90%+ coverage target
- No host system modifications
- Mock external dependencies

### Integration Tests
- Docker-based E2E tests
- Real server resources
- Complete protocol flows
- Mock external APIs only

### Benchmarks
- Performance regression detection
- Critical path optimization
- Per-package benchmark targets

All implementation phases (group interfaces, ciphersuites, helpers, key generation, signing protocol, service layer, and tests) are complete. DKG, key refresh, and repairable threshold have also been implemented.

## File Structure

```
go-frost/
├── pkg/frost/               # Core FROST library
│   ├── types.go
│   ├── errors.go
│   ├── group/              # Group abstraction + implementations
│   │   ├── ed25519/
│   │   ├── ed448/
│   │   ├── p256/
│   │   ├── ristretto255/
│   │   └── secp256k1/
│   ├── ciphersuite/        # Ciphersuite abstraction + implementations
│   │   ├── ed25519_sha512/
│   │   ├── ed448_shake256/
│   │   ├── p256_sha256/
│   │   ├── ristretto255_sha512/
│   │   └── secp256k1_sha256/
│   ├── helpers/            # Protocol helpers
│   ├── signing/            # Signing protocol
│   ├── keygen/             # Key generation (dealer, DKG, refresh, repairable)
│   │   ├── dkg/
│   │   ├── refresh/
│   │   └── repairable/
│   ├── keystore/           # Key storage abstraction
│   ├── security/           # Security utilities
│   ├── serialization/      # Serialization support
│   └── service/            # Service layer
├── pkg/secmem/             # Secure memory (audited unsafe usage)
├── pkg/signer/             # Signer abstraction
├── pkg/storage/            # Storage backends
├── docs/                   # Documentation
├── Makefile
├── go.mod
└── README.md
```

