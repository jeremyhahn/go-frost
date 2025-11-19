# FROST Architecture Overview

## Design Philosophy

The go-frost implementation follows these core principles:

1. **Clean Architecture**: Clear separation between layers with well-defined interfaces
2. **Type Safety**: No unsafe operations, strongly typed interfaces
3. **Performance**: Lock-free algorithms, efficient data structures
4. **Testability**: Comprehensive test coverage with TDD approach
5. **RFC Compliance**: Strict adherence to RFC 9591 specification

## Layer Architecture

### 1. Group Layer (`pkg/frost/group/`)

Defines the abstract prime-order group interface that all cryptographic operations depend on. This layer provides:

- Element and Scalar abstractions
- Group operations (addition, scalar multiplication)
- Serialization/deserialization
- Random scalar generation

**Key Interfaces**: `Group`, `Element`, `Scalar`

### 2. Ciphersuite Layer (`pkg/frost/ciphersuite/`)

Implements the ciphersuite abstraction, which combines:

- A specific prime-order group implementation
- Domain-separated hash functions (H1-H5)
- Ciphersuite-specific parameters

**Key Interfaces**: `Ciphersuite`, `Registry`

**Supported Ciphersuites**:
- Ed25519/SHA-512
- ristretto255/SHA-512
- Ed448/SHAKE256
- P-256/SHA-256
- secp256k1/SHA-256

### 3. Helper Layer (`pkg/frost/helpers/`)

Provides utility functions used throughout the protocol:

- **Nonce Generation**: Secure nonce generation with RNG hedging
- **Polynomial Operations**: Polynomial evaluation and interpolation
- **Binding Factors**: Computation of participant binding factors
- **Group Commitments**: Aggregation of participant commitments
- **Challenge Computation**: Signature challenge calculation
- **Encoding**: Commitment list encoding and validation

### 4. Key Generation Layer (`pkg/frost/keygen/`)

Implements trusted dealer key generation using Verifiable Secret Sharing (VSS):

- **Dealer**: Generates and distributes secret shares
- **VSS**: Creates and verifies polynomial commitments
- **Share Verification**: Validates participant key shares

### 5. Signing Layer (`pkg/frost/signing/`)

Implements the two-round FROST signing protocol:

- **Participant**: Individual signer operations (rounds 1 and 2)
- **Aggregator**: Combines signature shares into final signature
- **Coordinator**: Optional orchestrator for multi-party signing

**Protocol Flow**:
1. Round 1: Each participant generates nonces and commitments
2. Round 2: Each participant generates signature share
3. Aggregation: Coordinator combines shares into final signature

### 6. Service Layer (`pkg/frost/service/`)

Provides the high-level public API:

- **FrostService**: Main service interface for applications
- **SigningSession**: State management for async signing
- **SessionManager**: Multi-session coordination

This layer enforces business rules and orchestrates operations across lower layers.

## Data Flow

```
Application
    ↓
Service Layer (frost.go)
    ↓
Signing/KeyGen Layer (participant.go, dealer.go)
    ↓
Helper Layer (polynomial.go, binding.go, etc.)
    ↓
Ciphersuite Layer (interface.go)
    ↓
Group Layer (interface.go)
```

## Error Handling

All errors are strongly typed (no `fmt.Errorf`):

- Base errors in `errors.go` (e.g., `ErrInvalidParameters`)
- Wrapped errors with context (`ParameterError`, `ParticipantError`, `VerificationError`)
- Errors propagate up through layers with additional context

## Testing Strategy

1. **Unit Tests**: Each package has comprehensive unit tests
2. **Integration Tests**: End-to-end tests in Docker containers
3. **Benchmarks**: Performance tests for critical operations
4. **Coverage**: Target 90%+ for all packages

## Thread Safety

The implementation uses lock-free algorithms where possible:

- Immutable data structures for concurrent access
- Atomic operations for state management
- No shared mutable state in hot paths

## Future Extensions

The architecture supports future enhancements:

- Distributed key generation (DKG)
- Proactive secret sharing
- Additional ciphersuites
- Hardware security module (HSM) integration
- Identifiable abort mechanisms
