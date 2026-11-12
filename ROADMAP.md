> **Status: DRAFT** · Scope: go-frost · Last verified: 2026-11-12

# go-frost roadmap

The feature set below is the one in the [specification](docs/SPEC.md) feature table; each feature sits in the section its status maps to.

## Shipped

- rfc9591-ciphersuites: all five RFC 9591 ciphersuites with the official test vectors.
- ciphersuite-selection: `pkg/frost/ciphersuite/suites` resolves a suite by identifier or name.
- fips-selection-policy: P-256 is the default and only selectable suite under FIPS enforcement.
- trusted-dealer-keygen: `pkg/frost/keygen` with VSS commitments.
- distributed-keygen: three-round DKG in `pkg/frost/keygen/dkg`.
- key-refresh: `pkg/frost/keygen/refresh`.
- share-repair: `pkg/frost/keygen/repairable`.
- two-round-signing: participant, coordinator and aggregator in `pkg/frost/signing`.
- identifiable-abort: aggregation strategies that name cheating participants.
- nonce-preprocessing: `signing.Preprocess`.
- rerandomized-signing: rerandomized FROST in `pkg/frost/signing`.
- batch-verification: `signing.NewBatchVerifier`.
- pre-hashing: message pre-hashing per RFC 9591 §7.6.
- service-api: `pkg/frost/service` with a session manager.
- versioned-serialization: `pkg/frost/serialization`.
- keystore: `pkg/frost/keystore` over `pkg/storage` backends.
- crypto-signer: `pkg/signer`.
- nonce-reuse-prevention: nonce and commitment trackers in `pkg/frost/security`.
- participant-authentication: message authentication in `pkg/frost/security`.
- misbehavior-tracking: reputation tracker in `pkg/frost/security`.
- error-sanitization: error sanitizer in `pkg/frost/security`.
- secure-memory: `pkg/secmem`.
- frost-cli: `cmd/frost`.
- c-library: `cmd/libfrost`.
- fips-builds: `make build-fips`, `make build-lib-fips`.
- distributed-transport-tests: `test/transport`, `make test-transport`.
- release-alpha: `make release-alpha` and `make changelog-assemble`.

## In progress

- None.

## Planned

- None.

## Future

- fips140-only-operation: whether the library should run under `GODEBUG=fips140=only` at all; open owner question, issue #14.

## Milestones and issues

- Issue #14: FIPS `fips140=only` operation (future, above).
- Issue #70: this specification and roadmap.
- Open milestones: not listed here; the lane that wrote this draft had no issue-tracker access, so the owner adds them on review.
