# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Protected-memory keystore boundary** (`pkg/frost/keystore`) - the secret
  share is now held only in protected memory
  - `StoredKeyPackage.SecretShare []byte` is removed; the share lives solely in
    `SecretShareProtected`
  - **BREAKING: a `StoredKeyPackage` can no longer be serialized with
    `encoding/json`.** Its `MarshalJSON`/`UnmarshalJSON` now return
    `ErrPlaintextSerialization`. A serialized key package carries the share, so
    the document is secret too, and `encoding/json` cannot produce or consume
    one without leaving plaintext on the ordinary heap: `Marshal` assembles its
    result in a buffer drawn from a package-level `sync.Pool` and returns that
    buffer to the pool with the plaintext still in it, out of reach of any
    zeroization. Use `StoredKeyPackage.Seal` and `OpenStoredKeyPackage`
  - `Seal` assembles the document inside a mlock'd buffer, base64-encoding the
    share straight out of its enclave and splicing the public members - which
    `encoding/json` still serializes - in around it. `OpenStoredKeyPackage`
    decodes from inside the enclave and base64-decodes the share straight into
    a protected buffer. Neither the share nor the document is ever an ordinary
    heap allocation. **The on-disk format is unchanged**, byte for byte
  - A document carrying no share is rejected with `ErrMissingSecretShare`, and
    one this package cannot decode without routing the share through the heap -
    a duplicated share member, or one carrying a JSON escape - is rejected
    rather than decoded
  - `StoredKeyPackage.Zeroize()` destroys the protected share
  - `ToKeyPackage` no longer falls back to a plaintext share and returns
    `ErrMissingSecretShare` when none is present; `FromKeyPackage` rejects a
    key package without a share with `ErrInvalidKeyPackage`
- **BREAKING: `StorageBackend` widened** with `PutSecret`/`GetSecret`, which
  move serialized key packages through `secmem.SecretBytes` instead of plain
  `[]byte`. `Put`/`Get` are unchanged and still carry public material.
  Custom backends must implement the two new methods
  - `MemoryStorage` keeps protected payloads in enclaves rather than in the
    plain map of the underlying backend, with the same TTL semantics. A key
    moves between the plain and protected keyspaces atomically, so concurrent
    `Put`/`PutSecret` calls cannot interleave into losing the value. An entry
    whose TTL has elapsed is destroyed and removed by the next operation that
    passes it rather than merely hidden, so a payload never stays resident
    past the lifetime its TTL set
  - `MemoryStorage.GetSecret` **promotes** a value written through the plain
    `Put` path instead of copying it out: the backend hands its entry over
    rather than copying it, the one remaining slice is zeroized as it is
    sealed, and the key moves into the protected keyspace carrying whatever
    was left of its TTL. Reading a key package written by an older revision
    therefore leaves no plaintext behind; previously the backend kept its own
    plain `[]byte` for the rest of the process's life, however many times the
    key was read through the protected API
  - `FileStorage` writes payloads to disk straight out of the enclave and
    seals what it reads back before returning it

- **`storage.MemoryBackend` zeroizes an entry's data whenever it drops it.**
  Deleting the map reference leaves the bytes in the backing array until the
  allocator happens to reuse them, and callers store secret material here - a
  serialized key package among other things. Every drop now goes through one
  path, so a route added later cannot quietly reintroduce the residue:
  - `Delete`, and so `MemoryStorage.PutSecret`, which clears whatever plain
    value the key held before installing the protected one
  - `Put` over an existing key, which zeroizes the entry it replaces (the
    incoming data is copied first, so a caller passing back a slice it got
    from the backend still stores what it meant to)
  - `Close`, which must not leave payloads readable in the heap it releases
  - an entry whose TTL has elapsed, reaped and zeroized by whichever of `Get`,
    `Exists`, `List`, `Take` or `cleanExpired` next passes it rather than
    reported absent while its data stays resident
  - `Take` is the one path that does not zeroize, because it hands the data to
    its caller rather than dropping it
  - `Get`, `Exists` and `List` take the exclusive lock they now need to reap,
    so the mutex is no longer an `RWMutex`

- **`secmem.SecretBytes` open/reseal cycle made atomic** - `WithSecret` and
  `Clone` now hold the secret's mutex for the whole open/use/reseal cycle, so a
  concurrent `Destroy` either prevents the cycle from starting (`ErrDestroyed`)
  or takes effect after it finishes; previously the reseal could install a
  fresh enclave over a destroyed one and resurrect the secret
  - `Reseal` on a destroyed secret now discards the plaintext instead of
    sealing it back: destruction is final even for a buffer that was opened
    before the `Destroy` landed
  - `Size` reads under the mutex, since `Destroy` writes it

### Added
- `secmem.Clone` - copies a `SecretBytes` between mlock'd buffers, so a
  payload can be handed to another owner without a plaintext heap copy
- `secmem.NewSecret(size, fill)` - builds a secret in place inside a mlock'd,
  guard-paged buffer, for material that has to be assembled or decoded rather
  than simply copied. Unlike `NewSecretBytes`, which can only seal what is
  already on the heap, nothing fill writes ever exists as a heap allocation
- `StoredKeyPackage.Seal` and `OpenStoredKeyPackage` - the protected-memory
  serialization boundary for key packages
- `storage.MemoryBackend.Take` - removes an entry and hands its data to the
  caller rather than copying it, reporting the entry's expiration so the value
  can be moved elsewhere with its remaining lifetime intact. `Get` cannot serve
  a caller holding secret material, because it returns a copy and leaves the
  original in the map with nobody to zeroize it
- Keystore errors `ErrMissingSecretShare`, `ErrProtectedMemory` and
  `ErrPlaintextSerialization`

## [0.1.5-alpha] - 2025-12-27

### Changed
- **CI/CD pipeline** - Updated to golangci-lint v2 for improved linting
- **Makefile** - Now installs and uses same tool versions as CI (golangci-lint v2, staticcheck, gosec, govulncheck)
- **Test infrastructure** - Increased mock group order from 97 to 104729 to prevent probabilistic test failures

### Fixed
- **Linter compliance** - Fixed all revive warnings across codebase:
  - Unused parameter warnings (renamed to `_` where appropriate)
  - Package naming exclusions for RFC 9591 ciphersuite names (ed25519_sha512, ristretto255_sha512, etc.)
  - Variable shadowing of builtins (`max` renamed to `maxVal`)
- **Test coverage** - Added comprehensive tests for mock ciphersuite and mock group implementations
- **VSS test** - Updated modular reduction test case for new mock group order

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
  - `Backend` interface: Compatible with go-xkms and go-objstore for external integrations
- **Interface compatibility** - Storage backends work seamlessly with go-xkms and go-objstore
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

- **Removed go-xkms dependency** - go-frost is now fully self-contained
  - Maintains interface compatibility for users who want to use go-xkms
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
- Clarified optional dependencies (go-xkms, go-objstore, HSM/TPM libraries)

### Migration Notes

For users currently using go-xkms:
- **No action required** - Interface compatibility means existing code continues to work
- **Optional migration** - Can switch to built-in storage: `storage.NewFileBackend()` instead of go-xkms's `file.New()`
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
