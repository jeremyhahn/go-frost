> **Status: DRAFT** · Scope: go-frost · Last verified: 2026-11-12

# go-frost specification

## Purpose

go-frost is a Go implementation of the FROST threshold Schnorr signature scheme specified in RFC 9591, covering all five RFC ciphersuites.
It is a library layer: it owns the cryptographic protocol (key generation, two-round signing, aggregation, verification) and the key-share handling around it.
Go applications consume it through `pkg/frost/service` and the protocol packages; operators use the `frost` CLI; C and other FFI callers use `libfrost`.

## Boundaries

- Owns: the RFC 9591 protocol, its five ciphersuites and prime-order groups, and the RFC test vectors.
- Owns: trusted-dealer key generation, VSS, key refresh, share repair and the in-repository DKG rounds.
- Owns: key-share storage interfaces with memory and file backends, and a `crypto.Signer` abstraction for message authentication.
- Owns: nonce-reuse prevention, participant authentication, misbehavior tracking, error sanitization and secure memory for secrets.
- Never: provides a network transport or a long-running service; callers carry protocol messages between participants.
- Never: claims FIPS compliance; FIPS mode is a ciphersuite selection policy only.
- Never: substitutes a ciphersuite silently; an unknown name or enum is an error.
- Never: uses `unsafe` outside the C bindings in `cmd/libfrost`.

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| rfc9591-ciphersuites | shipped | Implements FROST(Ed25519, SHA-512), FROST(ristretto255, SHA-512), FROST(Ed448, SHAKE256), FROST(P-256, SHA-256) and FROST(secp256k1, SHA-256) in `pkg/frost/ciphersuite` over the groups in `pkg/frost/group`. Every official RFC 9591 test vector passes in `test/testvectors` and `test/rfc`. | [docs/rfc-compliance/](rfc-compliance/README.md) |
| ciphersuite-selection | shipped | `pkg/frost/ciphersuite/suites` resolves a suite by identifier, short name, long name or RFC context string, case-insensitively. An unknown name returns `ErrUnknownCiphersuite`. ristretto255 is the default outside FIPS mode. | none |
| fips-selection-policy | shipped | Under `GODEBUG=fips140=on` or `fips140=only` the default suite is P-256. Under `fips140=only` a non-selectable suite returns `ErrNotFIPSSelectable`. The policy claims nothing beyond selection. | none |
| trusted-dealer-keygen | shipped | `pkg/frost/keygen` generates key packages and the group public key for a MinSigners-of-MaxSigners configuration. Shares carry VSS commitments that participants can verify. Secret reconstruction is available for recovery. | [docs/guides/implementation.md](guides/implementation.md) |
| distributed-keygen | shipped | `pkg/frost/keygen/dkg` runs three DKG rounds with a proof of knowledge in round 1. Round 2 verifies each received share against the sender's VSS commitment. Round 3 derives the group public key and verifying shares. | none |
| key-refresh | shipped | `pkg/frost/keygen/refresh` refreshes the shares of an existing group. `ComputeRefreshingShares` produces refresh shares and `ApplyRefreshShare` applies one to a key share. | none |
| share-repair | shipped | `pkg/frost/keygen/repairable` implements the repairable threshold scheme. Helper participants restore a lost participant's share. | none |
| two-round-signing | shipped | `pkg/frost/signing` provides the participant, coordinator and aggregator roles of the RFC two-round protocol. Signature shares are verified before aggregation. Signatures verify against the group public key. | [docs/architecture/](architecture/README.md) |
| identifiable-abort | shipped | Aggregation strategies in `pkg/frost/signing` identify the participants who sent invalid shares. The caller can stop at the first cheater or collect all of them. | [docs/guides/abort-protocol.md](guides/abort-protocol.md) |
| nonce-preprocessing | shipped | `signing.Preprocess` generates batches of nonces and commitments ahead of signing. | none |
| rerandomized-signing | shipped | `pkg/frost/signing` implements rerandomized FROST for unlinkable signatures. | none |
| batch-verification | shipped | `signing.NewBatchVerifier` verifies many signatures for one ciphersuite together. | none |
| pre-hashing | shipped | Large or streamed messages can be hashed before signing. The guide states which input hashing is safe under RFC 9591 §7.6. | [docs/guides/pre-hashing.md](guides/pre-hashing.md) |
| service-api | shipped | `pkg/frost/service` wraps key generation, signing and verification behind one service per ciphersuite. A session manager tracks signing sessions. Errors are typed. | [docs/api/reference.md](api/reference.md) |
| versioned-serialization | shipped | `pkg/frost/serialization` encodes FROST data structures with a versioned header. Decoding rejects a version mismatch with `ErrVersionMismatch`. | none |
| keystore | shipped | `pkg/frost/keystore` stores key packages in memory, on file or through any `storage.Backend`. `pkg/storage` provides memory and file backends with atomic writes and configurable permissions. | [docs/guides/keystore.md](guides/keystore.md) |
| crypto-signer | shipped | `pkg/signer` exposes software Ed25519 keys and any `crypto.Signer`, including HSM and TPM backed ones, through one interface. | none |
| nonce-reuse-prevention | shipped | `pkg/frost/security` tracks nonces and commitments so that none is used twice. A reused nonce is refused before a share is produced. | [docs/security/](security/README.md) |
| participant-authentication | shipped | `pkg/frost/security` authenticates protocol messages and signs commitments with a `crypto.Signer`. | [docs/security/channel-security.md](security/channel-security.md) |
| misbehavior-tracking | shipped | A reputation tracker records participants who misbehave. An in-memory tracker is the default. | [docs/security/misbehavior-tracking.md](security/misbehavior-tracking.md) |
| error-sanitization | shipped | An error sanitizer strips detail from errors returned to remote parties. It prevents signing-oracle leaks. | [docs/security/error-sanitization.md](security/error-sanitization.md) |
| secure-memory | shipped | `pkg/secmem` holds secrets in mlock'd memory with guard pages and an encrypted enclave. Secrets are owned byte slices scrubbed with `secmem.ZeroBytes`. | [docs/security/side-channel-protection.md](security/side-channel-protection.md) |
| frost-cli | shipped | `cmd/frost` provides keygen, sign, commit, collect-commitments, sign-share, collect-shares, aggregate and verify. Secret shares and nonces in its JSON files are held as owned buffers and scrubbed. An unknown `--ciphersuite` exits 1. | [docs/getting-started/](getting-started/README.md) |
| c-library | shipped | `cmd/libfrost` builds a shared and a static library exporting key generation, signing and verification. An unknown ciphersuite enum returns `FROST_ERR_INVALID_PARAMS`. A suite excluded by FIPS enforcement returns `FROST_ERR_CIPHERSUITE_NOT_ALLOWED`. | none |
| fips-builds | shipped | `make build-fips` and `make build-lib-fips` build the CLI and libraries with FIPS 140 mode enabled. | none |
| distributed-transport-tests | shipped | `test/transport` runs a coordinator and nodes over the network in Docker through `make test-transport`. | none |
| release-alpha | shipped | `make release-alpha VERSION=vX.Y.Z-alpha` cuts a signed, annotated tag from an explicit version. It refuses without a matching CHANGELOG section or while a `changelog.d/` fragment remains. `make changelog-assemble` folds fragments into the release section. | none |
| fips140-only-operation | future | Whether the library should run under `GODEBUG=fips140=only` at all is an open owner question (issue #14). | none |

## Interfaces

- SDK: Go module `github.com/jeremyhahn/go-frost`; entry points `pkg/frost/service`, `pkg/frost/signing`, `pkg/frost/keygen`, `pkg/frost/ciphersuite/suites`.
- CLI: `frost` (`cmd/frost`), file-based distributed signing with JSON key, commitment, share and signature files.
- API: C ABI `libfrost` (`cmd/libfrost`): `frost_version`, `frost_generate_keys`, `frost_sign`, `frost_verify`, `frost_free_string`, `frost_free_bytes`.

## Release criteria

- `make ci` passes: lint, security, static analysis, unit tests and build.
- `make test-rfc` passes every RFC 9591 test vector on all five ciphersuites.
- The `fips` CI job passes the RFC 9591 Appendix E.4 check and a P-256 keygen, sign and verify through the selection API.
- `make integration-test` and `make test-transport` pass.
- `CHANGELOG.md` carries the release section and no `changelog.d/` fragment remains.
