# RFC 9591 Compliance Tests

This directory contains tests organized by RFC 9591 sections to verify complete compliance with the FROST threshold signature specification.

## Purpose

These tests are organized to mirror the structure of RFC 9591, making it easy to:

1. Verify compliance with specific RFC sections
2. Identify which RFC requirements are tested
3. Run tests for specific protocol components
4. Track coverage of RFC requirements

## Test Organization

### Section-Based Tests

- **section3_test.go** - Section 3: Cryptographic Dependencies
  - Section 3.1: Prime-Order Group operations
  - Section 3.2: Cryptographic Hash Functions (H1-H5)

- **section4_test.go** - Section 4: Helper Functions
  - Section 4.1: Nonce Generation
  - Section 4.2: Polynomials
  - Section 4.3: List Operations
  - Section 4.4: Binding Factors Computation
  - Section 4.5: Group Commitment Computation
  - Section 4.6: Signature Challenge Computation

- **section5_test.go** - Section 5: Two-Round FROST Signing Protocol
  - Section 5.1: Round One - Commitment
  - Section 5.2: Round Two - Signature Share Generation
  - Section 5.3: Signature Share Aggregation
  - Section 5.4: Identifiable Abort

- **section6_test.go** - Section 6: Ciphersuites
  - Ciphersuite requirements
  - FROST(ristretto255, SHA-512) validation
  - Signature verification

### Appendix Tests

- **appendixc_test.go** - Appendix C: Trusted Dealer Key Generation
  - Appendix C.1: Shamir Secret Sharing
  - Appendix C.2: Verifiable Secret Sharing

- **appendixd_test.go** - Appendix D: Random Scalar Generation
  - Appendix D.1: Rejection Sampling
  - Appendix D.2: Wide Reduction

- **appendixe_test.go** - Appendix E: Test Vectors
  - Test vector structure validation
  - Appendix E.3: FROST(ristretto255, SHA-512) test vectors

## Running Tests

### Run All RFC Tests

```bash
go test ./test/rfc -v
```

### Run Specific Section Tests

```bash
# Section 3: Cryptographic Dependencies
go test ./test/rfc -v -run Section3

# Section 4: Helper Functions
go test ./test/rfc -v -run Section4

# Section 5: Two-Round Signing Protocol
go test ./test/rfc -v -run Section5

# Section 6: Ciphersuites
go test ./test/rfc -v -run Section6

# Appendix C: Key Generation
go test ./test/rfc -v -run AppendixC

# Appendix D: Random Scalar Generation
go test ./test/rfc -v -run AppendixD

# Appendix E: Test Vectors
go test ./test/rfc -v -run AppendixE
```

### Run Specific Subsection Tests

```bash
# Section 3.1: Prime-Order Group
go test ./test/rfc -v -run Section3_1

# Section 3.2: Hash Functions
go test ./test/rfc -v -run Section3_2

# Section 4.1: Nonce Generation
go test ./test/rfc -v -run Section4_1

# Section 4.4: Binding Factors
go test ./test/rfc -v -run Section4_4

# Section 5.1: Round One
go test ./test/rfc -v -run Section5_1

# Section 5.3: Aggregation
go test ./test/rfc -v -run Section5_3
```

## Test Coverage

Each test file includes:

1. **RFC Section References** - Comments indicating which RFC section is tested
2. **RFC Quotes** - Direct quotes from the RFC describing requirements
3. **Requirement Validation** - Tests that verify specific RFC requirements
4. **Error Conditions** - Tests for required error handling

See [docs/rfc-test-coverage.md](../../docs/rfc-test-coverage.md) for a detailed coverage matrix.

## Test Naming Convention

Tests follow this naming pattern:

```
TestSection<X>_<Y>_<Description>
TestAppendix<X>_<Y>_<Description>
```

Where:
- `<X>` is the section/appendix number
- `<Y>` is the subsection number (optional)
- `<Description>` is a brief description of what's tested

Examples:
- `TestSection3_1_PrimeOrderGroup`
- `TestSection4_4_BindingFactors`
- `TestSection5_1_RoundOne`
- `TestAppendixC_TrustedDealerKeyGeneration`

## Relationship to Other Tests

These RFC compliance tests complement the existing test structure:

- **Unit tests** (`pkg/frost/*/`) - Test individual components
- **Integration tests** (`test/integration/`) - Test component interactions
- **Test vectors** (`test/testvectors/`) - Validate against RFC test vectors
- **RFC tests** (`test/rfc/`) - Verify RFC compliance by section

The RFC tests focus on verifying that the implementation meets each specific requirement stated in RFC 9591, while the other tests focus on correctness, integration, and real-world usage.

## References

- [RFC 9591: The FROST Protocol](../../docs/rfc9591.txt)
- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](../../docs/2020-852.pdf)
- [FROST Coverage Matrix](../../docs/rfc-test-coverage.md)
- [Test Vectors](../testvectors/)
