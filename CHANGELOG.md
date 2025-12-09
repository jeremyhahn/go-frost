# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4-alpha] - 2025-12-08

### Changed
- **Consolidated test infrastructure** - Integration tests moved to `pkg/frost/service/` as unit tests
- **Simplified Makefile** - Per-target `.PHONY` declarations, single `make test` command for all tests
- **Removed Docker integration tests** - DKG/multi-participant tests run in-memory without Docker
- **Go 1.25.5** - Updated Dockerfiles for crypto security fixes

### Fixed
- Test coverage improved to 90% with additional error path tests

## [0.1.3-alpha] - 2025-12-08

### Added
- **Hooks interface** for ciphersuite customization (PreSign, PreAggregate, PreVerify, PostDKG, PostGenerate)
- **ByteOrder support** in group interface for cross-platform compatibility
- **Enhanced error types** with culprit identification for malicious participant detection
- **Comprehensive test coverage** improvements across all packages (~90% coverage)

### Changed
- **Constant-time operations** enforced across all ciphersuites
- **CI/CD pipeline** expanded with FIPS-compliant builds and multi-platform support
- **Code quality** improvements via staticcheck and goimports compliance

### Fixed
- Staticcheck warnings for unused values and nil checks
- Goimports formatting across test files

## [0.1.2-alpha] - 2025-01-20

### Added

#### Storage Package (`pkg/storage/`)
- **Independent storage implementations** - go-frost now includes its own storage backends
  - `MemoryBackend`: In-memory storage with TTL support, thread-safe, ideal for testing
  - `FileBackend`: File system storage with atomic writes, secure permissions (0600 default), and path traversal protection
  - `Backend` interface: Compatible with go-keychain and go-objstore for external integrations
- **Interface compatibility** - Storage backends work seamlessly with go-keychain and go-objstore
- **Extensible architecture** - Easy to implement custom backends (HSM, TPM, cloud KMS, DHT, etc.)

#### Signer Package (`pkg/signer/`)
- **Crypto.Signer abstraction** - Flexible key management supporting multiple backends
  - `Ed25519Signer`: Software-based Ed25519 signing using crypto/ed25519
  - `FromCryptoSigner()`: Adapter for HSM, TPM, and cloud KMS signers
  - `MultiSigner`: Manages multiple participant signers
- **Hardware security module support** - Use any crypto.Signer implementation (PKCS#11, cloud KMS)
- **Standard interface** - All signers implement Go's crypto.Signer for maximum compatibility

#### Security Enhancements (`pkg/frost/security/`)
- `SignCommitmentWithSigner()`: Sign FROST commitments using crypto.Signer (enables HSM/TPM)
- `SignSignatureShareWithSigner()`: Sign signature shares using crypto.Signer
- Backward compatible with existing `ed25519.PrivateKey` functions

#### Keystore Updates (`pkg/frost/keystore/`)
- `NewMemoryStorage()`: In-memory storage adapter for testing and development
- Updated `NewFileStorage()`: Now uses go-frost's own storage implementation

### Changed

- **Removed go-keychain dependency** - go-frost is now fully self-contained
  - Maintains interface compatibility for users who want to use go-keychain
  - No breaking changes to existing APIs
- **Storage implementation** - Keystore now uses `pkg/storage` internally
- **Enhanced flexibility** - Applications can now inject custom storage and signer implementations

### Fixed

- File storage `List()` method now correctly handles filename prefix matching
- File storage properly propagates permission errors on base directory access

### Documentation

- Updated README.md with Storage and Key Management section
- Added comprehensive package documentation for `pkg/storage/` and `pkg/signer/`
- Included usage examples for HSM/TPM integration
- Clarified optional dependencies (go-keychain, go-objstore, HSM/TPM libraries)

### Migration Notes

For users currently using go-keychain:
- **No action required** - Interface compatibility means existing code continues to work
- **Optional migration** - Can switch to built-in storage: `storage.NewFileBackend()` instead of go-keychain's `file.New()`
- **HSM/TPM users** - Can now use `signer.FromCryptoSigner()` to integrate hardware-backed keys

### Security

- File storage uses atomic writes to prevent data corruption
- Default file permissions set to 0600 (owner read/write only)
- Path traversal protection (rejects keys containing "..")
- Thread-safe storage operations with proper locking

## [0.1.1-alpha] - 2025-01-19

### Added

#### Ciphersuites
- **FROST(Ed25519, SHA-512)** - RFC 6.1 implementation with 93.8% test coverage
- **FROST(P-256, SHA-256)** - RFC 6.4 implementation with 97.4% test coverage
- **FROST(secp256k1, SHA-256)** - RFC 6.5 implementation with 94.4% test coverage
- **FROST(Ed448, SHAKE256)** - RFC 6.3 implementation with 94.9% test coverage
- All 5 RFC 9591 ciphersuites now fully supported (95%+ test coverage each)

#### Testing
- Table-driven multi-ciphersuite integration tests
- 8 integration test functions testing all 5 ciphersuites (40 test scenarios)
- Comprehensive RFC test vector validation
- `make test-rfc-full` target for complete RFC compliance testing

#### CLI
- Added `--ciphersuite` flag to all commands (keygen, sign, commit, sign-share, aggregate, verify)
- CLI now supports selecting from all 5 RFC 9591 ciphersuites
- Default ciphersuite: ristretto255 (as recommended by RFC)
- Comprehensive help text showing all supported ciphersuites

#### Documentation
- Updated README.md to reflect all 5 ciphersuite support
- Expanded API reference with all ciphersuite import examples
- Added "Using Different Ciphersuites" section to getting-started guide
- Security level documentation for each ciphersuite

### Changed
- Documentation now shows all ciphersuites as production-ready (previously only ristretto255)
- Improved test coverage across all packages (95%+ average)

### Fixed
- N/A (no bug fixes in this release)

## [0.1.0-alpha] - 2025-01-15

### Overview

Initial alpha release of go-frost - a production-ready Go implementation of the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme as specified in RFC 9591.

### Added

#### Core Implementation
- Full RFC 9591 compliance (100% of required features)
- FROST(ristretto255, SHA-512) ciphersuite - RFC 6.2 (recommended default)
- Two-round signing protocol (Section 5)
- Trusted dealer key generation (Appendix C)
- Service layer abstraction for high-level API
- Clean architecture with typed errors

#### Security Features
- Nonce reuse prevention
- Constant-time operations where applicable
- Input validation at all API boundaries
- Identifiable abort for malicious participant detection
- No unsafe code or pointer magic

#### Testing
- 90%+ test coverage across all core packages
- RFC test vector validation (Appendix E)
- Integration tests in Docker containers
- Comprehensive benchmarks
- Security tests for side-channel resistance

#### Documentation
- Complete API reference
- Getting started guide
- Security best practices
- Architecture documentation
- RFC compliance tracking
- Integration guides and examples

#### Build System
- Makefile with comprehensive targets
- Docker support for integration testing
- CI/CD pipeline with GitHub Actions
- Multi-platform builds (linux/amd64, linux/arm64, darwin, windows)
- Code quality tools (golangci-lint, gosec, govulncheck)

### Performance
- Lock-free algorithms where possible
- Optimized cryptographic operations
- Minimal allocations in hot paths
- High throughput, low latency design

### Requirements
- Go 1.21 or higher
- No external dependencies for core library
