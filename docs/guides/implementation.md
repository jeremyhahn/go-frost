# FROST Implementation Guide

This guide outlines the recommended implementation order and key considerations for completing the go-frost implementation.

## Implementation Order

### Phase 1: Foundation (Group Interface)

Start with one group implementation to validate the interface design.

**Recommended: Start with ristretto255**
- Well-documented
- Good library support (filippo.io/edwards25519)
- Used in production systems

**Tasks**:
1. Create `pkg/frost/group/ristretto255/` package
2. Implement `Element` interface
3. Implement `Scalar` interface
4. Implement `Group` interface
5. Write unit tests (target: 95%+ coverage)
6. Write benchmarks for critical operations

**Key Considerations**:
- Use constant-time operations from the library
- Validate all deserializations
- Handle identity element properly (reject where required)
- Test edge cases (zero scalars, identity elements)

### Phase 2: Ciphersuite (ristretto255-SHA512)

**Tasks**:
1. Create `pkg/frost/ciphersuite/ristretto255sha512/` package
2. Implement domain-separated hash functions (H1-H5)
3. Implement ciphersuite interface
4. Create ciphersuite registry
5. Write unit tests
6. Validate against RFC test vectors (Appendix E.3)

**Key Considerations**:
- Domain separation strings must match RFC exactly
- H1, H2, H3 must output scalars in field
- H4, H5 are byte string outputs
- Use crypto/sha512 for hash function

### Phase 3: Helper Functions

Implement in this order (dependencies flow):

**3.1 Nonce Generation** (`helpers/nonce.go`)
- Use crypto/rand for 32 random bytes
- Implement H3 integration
- Test randomness properties
- Verify no nonce reuse

**3.2 Polynomial Operations** (`helpers/polynomial.go`)
- Implement polynomial evaluation (Horner's method)
- Implement Lagrange interpolation
- Test with known values
- Verify edge cases (degree 0, 1, large degrees)

**3.3 Encoding** (`helpers/encoding.go`)
- Implement commitment list encoding
- Implement sorting validation
- Test with various list sizes

**3.4 Binding Factors** (`helpers/binding.go`)
- Use encoding and H1/H4/H5
- Test against RFC test vectors
- Verify deterministic output

**3.5 Group Commitment** (`helpers/commitment.go`)
- Aggregate commitments with binding factors
- Test with various participant counts
- Verify against test vectors

**3.6 Challenge** (`helpers/challenge.go`)
- Implement H2 integration
- Test against RFC test vectors
- Verify deterministic output

### Phase 4: Key Generation

**4.1 VSS** (`keygen/vss.go`)
- Implement commitment creation
- Implement share verification
- Test share validation
- Test commitment properties

**4.2 Dealer** (`keygen/dealer.go`)
- Implement share generation
- Use VSS for commitments
- Implement parameter validation
- Test with various threshold configurations
- Test against RFC test vectors (Appendix C)

**Key Considerations**:
- Validate: minSigners >= 2
- Validate: minSigners <= maxSigners
- Validate: no duplicate participant IDs
- Validate: no zero participant IDs
- Securely clear secret polynomial after use

### Phase 5: Signing Protocol

**5.1 Participant** (`signing/participant.go`)
- Implement Round 1 (nonce generation)
- Implement Round 2 (signature share)
- Implement share verification (identifiable abort)
- Test with various scenarios
- Test against RFC test vectors (Appendix E)

**5.2 Aggregator** (`signing/aggregator.go`)
- Implement signature aggregation
- Implement signature verification
- Test with threshold and above-threshold signers
- Test against RFC test vectors

**5.3 Coordinator** (`signing/coordinator.go`)
- Implement commitment collection
- Implement share collection
- Implement full signing flow
- Test distributed scenarios

**Key Considerations**:
- Commitment list MUST be sorted
- Verify all shares before aggregation (optional but recommended)
- Clear nonces after use
- Detect and handle malicious participants

### Phase 6: Service Layer

**6.1 FrostService** (`service/frost.go`)
- Wire up keygen → dealer
- Wire up signing → participant/aggregator/coordinator
- Implement verification
- Add input validation
- Add comprehensive error handling

**6.2 Session Management**
- Implement session state machine
- Add timeout handling
- Add cancellation support
- Test concurrent sessions

### Phase 7: Additional Ciphersuites

Implement in order of priority:

1. **Ed25519-SHA512** (high priority - EdDSA compatibility)
2. **P-256-SHA256** (high priority - NIST standard)
3. **secp256k1-SHA256** (medium priority - Bitcoin/Ethereum)
4. **Ed448-SHAKE256** (lower priority)

For each:
- Implement group operations
- Implement ciphersuite
- Run RFC test vectors
- Add benchmarks

### Phase 8: Testing & Validation

**8.1 Unit Tests**
- Achieve 90%+ coverage for all packages
- Test all error conditions
- Test boundary cases
- Test with fuzz testing where appropriate

**8.2 Integration Tests**
- Implement Docker-based E2E tests
- Test complete signing flows
- Test with various threshold configurations
- Test failure scenarios

**8.3 RFC Test Vectors**
- Implement test vector validation for all ciphersuites
- Ensure bit-exact compatibility with RFC

**8.4 Benchmarks**
- Benchmark key generation
- Benchmark signing (round 1, round 2, aggregation)
- Benchmark verification
- Compare with other implementations

### Phase 9: Security & Hardening

**9.1 Security Review**
- Constant-time review for critical operations
- Nonce generation review
- Secret clearing review
- Input validation review

**9.2 Fuzzing**
- Fuzz deserialization functions
- Fuzz signature verification
- Fuzz key generation

**9.3 Side-Channel Analysis**
- Timing analysis of critical operations
- Memory access pattern analysis

### Phase 10: Documentation & Examples

**10.1 API Documentation**
- Complete godoc for all public APIs
- Add usage examples to godoc

**10.2 Usage Examples**
- Basic key generation example
- Basic signing example
- Coordinator-based signing
- Distributed signing (no coordinator)
- Identifiable abort example

**10.3 Security Documentation**
- Security considerations
- Best practices
- Common pitfalls
- Threat model

## Development Workflow

### Test-Driven Development (TDD)

For each component:

1. **Write tests first**
   - Define expected behavior
   - Include edge cases
   - Include error cases

2. **Implement minimal code**
   - Make tests pass
   - Keep it simple

3. **Refactor**
   - Improve code quality
   - Maintain test coverage

4. **Validate**
   - Run linters
   - Check coverage
   - Run benchmarks

### Code Review Checklist

Before considering a component complete:

- [ ] All tests pass
- [ ] Coverage >= 90%
- [ ] Linter passes (golangci-lint)
- [ ] Benchmarks added
- [ ] Godoc comments complete
- [ ] Error handling comprehensive
- [ ] No unaudited unsafe operations (note: `secmem` uses audited `unsafe` for secure memory handling)
- [ ] Constants extracted (no magic numbers)
- [ ] Edge cases tested
- [ ] RFC test vectors pass (if applicable)

## Key Implementation Notes

### Random Number Generation

Always use `crypto/rand`:
```go
import "crypto/rand"

randomBytes := make([]byte, 32)
if _, err := rand.Read(randomBytes); err != nil {
    return err
}
```

### Constant-Time Operations

For sensitive comparisons, use `crypto/subtle`:
```go
import "crypto/subtle"

if subtle.ConstantTimeCompare(a, b) == 1 {
    // Equal
}
```

### Secret Clearing

The project provides `secmem.ZeroBytes()` and `secmem.ZeroString()` for constant-time zeroing of sensitive data, and `secmem.SecretBytes` for encrypted-at-rest storage via memguard. Prefer these over manual loops:

```go
for i := range secretBytes {
    secretBytes[i] = 0
}
```

Use `secmem.SecretBytes` when key material must persist in memory, and call `secmem.ZeroBytes()` or `secmem.ZeroString()` for cleanup of temporary buffers.

### Error Handling

Always use typed errors:
```go
// Good
if identifier == 0 {
    return frost.ErrInvalidParticipant
}

// Bad - NEVER do this
if identifier == 0 {
    return fmt.Errorf("invalid participant")
}
```

### Polynomial Evaluation

Use Horner's method for efficiency:
```go
// result = c[n]*x^n + ... + c[1]*x + c[0]
// Horner: result = (...((c[n]*x + c[n-1])*x + c[n-2])*x ... + c[0])
result := coefficients[degree]
for i := degree - 1; i >= 0; i-- {
    result = result.Mul(x).Add(coefficients[i])
}
```

### Commitment List Sorting

Commitment lists MUST be sorted:
```go
sort.Slice(commitments, func(i, j int) bool {
    return commitments[i].Identifier < commitments[j].Identifier
})
```

## Testing Strategy

### Unit Test Structure

```go
func TestComponent_Operation(t *testing.T) {
    // Setup
    suite := setupTestCiphersuite(t)

    // Execute
    result, err := component.Operation(input)

    // Assert
    require.NoError(t, err)
    assert.NotNil(t, result)
    assert.Equal(t, expected, result)
}

func TestComponent_Operation_Error(t *testing.T) {
    // Test error conditions
    _, err := component.Operation(invalidInput)
    assert.Error(t, err)
    assert.ErrorIs(t, err, frost.ErrInvalidParameters)
}
```

### Benchmark Structure

```go
func BenchmarkComponent_Operation(b *testing.B) {
    // Setup
    suite := setupTestCiphersuite(b)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = component.Operation(input)
    }
}
```

## Performance Targets

Rough performance targets (will vary by hardware):

- **Key Generation**: < 10ms for 3-of-5 setup
- **Round 1 (per participant)**: < 1ms
- **Round 2 (per participant)**: < 2ms
- **Aggregation**: < 5ms for 5 shares
- **Verification**: < 5ms

## Common Pitfalls to Avoid

1. **Nonce Reuse**: Never reuse nonces across signatures
2. **Identity Elements**: Reject identity elements in commitments
3. **Zero Scalars**: Validate identifiers are non-zero
4. **Unsorted Lists**: Always sort commitment lists
5. **Missing Validation**: Validate all inputs at service layer
6. **Error Wrapping**: Provide context in errors
7. **Secret Leakage**: Clear secrets after use
8. **Timing Attacks**: Use constant-time comparisons

## Resources

- RFC 9591: https://www.rfc-editor.org/rfc/rfc9591.html
- FROST Paper: https://eprint.iacr.org/2020/852
- ristretto255: https://ristretto.group/
- edwards25519: https://pkg.go.dev/filippo.io/edwards25519
- Google Go Style: https://google.github.io/styleguide/go/

## Getting Help

When stuck:
1. Review RFC 9591 specification
2. Check test vectors (Appendix E)
3. Review existing implementations
4. Consult with cryptography experts

## Completion Checklist

- [ ] All 5 ciphersuites implemented
- [ ] All RFC test vectors pass
- [ ] 90%+ code coverage achieved
- [ ] All benchmarks written
- [ ] Documentation complete
- [ ] Security review completed
- [ ] Integration tests pass
- [ ] Production ready
