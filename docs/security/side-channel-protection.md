# Side-Channel Security in go-frost

> **Status: REFERENCE** · Scope: go-frost constant-time requirements · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

Scope of verification: this guide describes the ristretto255-SHA512 suite
(`pkg/frost/group/ristretto255`). Constant-time properties of the underlying
arithmetic are inherited from `github.com/gtank/ristretto255` (see `go.mod` for the
version) and are **not re-verified here**; where this guide describes upstream
algorithms (Montgomery ladder, Fermat inversion, table use) that is background, not a
statement checked against this repository. Source locations are given by symbol name
because line numbers drift. The other suites (P-256, secp256k1, Ed25519, Ed448) are
not analysed here.

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What Are Side-Channel Attacks?](#what-are-side-channel-attacks)
3. [Threat Model](#threat-model)
4. [Constant-Time Operations](#constant-time-operations)
5. [Non-Constant-Time Operations](#non-constant-time-operations)
6. [Library Guarantees](#library-guarantees)
7. [Timing Attack Mitigations](#timing-attack-mitigations)
8. [Testing Methodology](#testing-methodology)
9. [Deployment Best Practices](#deployment-best-practices)
10. [Platform-Specific Considerations](#platform-specific-considerations)
11. [References](#references)

---

## Executive Summary

Side-channel attacks exploit information leaked through the physical implementation of cryptographic operations rather than weaknesses in the algorithms themselves. The go-frost implementation mitigates timing-based side-channel attacks using constant-time primitives from the ristretto255 library, avoidance of secret-dependent branching and memory access patterns, and multiple layered mitigation strategies.

### Quick Security Assessment

| Attack Vector | Protection Level | Notes |
|--------------|------------------|-------|
| Timing attacks on scalar operations | **HIGH** | ristretto255 constant-time primitives |
| Timing attacks on point operations | **HIGH** | ristretto255 constant-time primitives |
| Timing attacks on comparisons | **MEDIUM** | Some operations use big.Int (non-constant) |
| Cache timing attacks | **MEDIUM** | Depends on underlying library and platform |
| Power analysis | **OUT OF SCOPE** | Requires physical access |
| Electromagnetic analysis | **OUT OF SCOPE** | Requires physical access |

### Key Takeaways

1. **Core cryptographic operations are constant-time** - All scalar arithmetic and elliptic curve operations use constant-time implementations
2. **Some utility operations are NOT constant-time** - Scalar ordering comparisons use variable-time big.Int operations
3. **Deployment matters** - Virtual machines, containers, and shared hosting reduce side-channel resistance
4. **Testing is ongoing** - Statistical timing analysis should be part of CI/CD pipelines

**Recommendation**: go-frost provides strong protection against remote timing attacks. For high-security applications requiring protection against local attackers or sophisticated adversaries, deploy on dedicated hardware with additional hardening.

---

## What Are Side-Channel Attacks?

### Definition

Side-channel attacks extract secret information by observing physical characteristics of a cryptographic implementation rather than analyzing the mathematical algorithm. These attacks exploit the fact that real-world computers leak information through:

- **Timing**: How long operations take
- **Power consumption**: How much electricity is used
- **Electromagnetic radiation**: Radio frequency emissions
- **Cache behavior**: Which memory locations are accessed
- **Acoustic emissions**: Sound produced by components

### Relevance to FROST

In threshold signature schemes like FROST, side-channel attacks are particularly dangerous because:

1. **Secret Key Shares**: Each participant holds a secret share that must never be disclosed
2. **Nonce Generation**: Secret nonces must be unpredictable and never reused
3. **Distributed Protocol**: Multiple participants increase attack surface
4. **Remote Adversaries**: Network-based timing attacks are feasible

### Types of Side-Channel Attacks

#### 1. Timing Attacks

**Description**: Measuring how long cryptographic operations take to infer secret values.

**Example**:
```
Time to compute: secret_key * point

If secret_key bit is 0: Fast (point addition)
If secret_key bit is 1: Slow (point doubling + addition)

Attacker measures many operations → recovers secret_key bit-by-bit
```

**FROST Impact**: Could reveal participant secret shares or nonces.

#### 2. Cache Timing Attacks

**Description**: Observing CPU cache behavior to infer which memory locations were accessed.

**Example**:
```
Lookup table indexed by secret value:
table[secret_byte] → Loads table[secret_byte] into cache
Attacker measures cache state → determines secret_byte
```

**FROST Impact**: Could reveal scalar values during multiplication if implementation uses lookup tables.

#### 3. Power Analysis

**Description**: Measuring power consumption during cryptographic operations.

**Attack Variants**:
- **Simple Power Analysis (SPA)**: Direct observation of power traces
- **Differential Power Analysis (DPA)**: Statistical analysis of many power traces

**FROST Impact**: Requires physical access to participant devices. Out of scope for most deployments but relevant for hardware security modules (HSMs).

#### 4. Fault Injection

**Description**: Inducing errors during computation to reveal secrets.

**Example**: Corrupting one bit during scalar multiplication to produce an invalid signature that leaks the secret key.

**FROST Impact**: Could compromise participant secret shares. Mitigated by signature verification before output.

---

## Threat Model

### In-Scope Threats

The following side-channel attacks are considered in scope for go-frost:

#### Remote Timing Attacks (PRIMARY THREAT)

**Adversary Capabilities**:
- Network access to FROST participant or coordinator
- Ability to send signing requests
- Ability to measure response times with millisecond precision
- Knowledge of FROST protocol internals

**Attack Scenario**:
1. Adversary sends crafted messages for signing
2. Measures time to generate signature shares
3. Uses statistical analysis to infer secret share bits
4. Recovers secret share after many samples

**Mitigation Priority**: **CRITICAL**

#### Local Timing Attacks

**Adversary Capabilities**:
- Local process on same machine (shared hosting, containers)
- High-resolution timing measurements (nanosecond precision)
- Ability to observe cache state

**Attack Scenario**:
1. Adversary runs malicious process on same CPU
2. Uses performance counters to measure cache hits/misses
3. Observes FROST signing operations
4. Infers secret values from cache patterns

**Mitigation Priority**: **HIGH**

### Out-of-Scope Threats

The following attacks require physical access and are out of scope:

- **Power Analysis**: Requires power measurement equipment attached to device
- **Electromagnetic Analysis**: Requires antennas near device
- **Acoustic Cryptanalysis**: Requires microphones near device
- **Fault Injection**: Requires hardware access (voltage glitching, laser fault injection)

**Note**: Deployments requiring protection against physical attacks should use certified HSMs.

### Trust Assumptions

Side-channel protection assumes:

1. **Operating System is Trusted**: Kernel has not been compromised
2. **Hardware is Trusted**: CPU, memory, and peripherals are not backdoored
3. **Dependencies are Trusted**: Go runtime and crypto libraries are not malicious
4. **Compiler is Trusted**: Go compiler generates correct constant-time code

**Violation of Assumptions**: If any of these assumptions are violated, side-channel protections may be ineffective.

---

## Constant-Time Operations

The following operations are implemented using constant-time algorithms that do not leak secret information through timing or cache behavior.

### Scalar Arithmetic

All scalar field operations execute in constant time regardless of input values.

#### Addition and Subtraction

**Operations**:
- `Scalar.Add(other)` - Scalar addition modulo group order
- `Scalar.Sub(other)` - Scalar subtraction modulo group order

**Implementation**: `Scalar.Add` / `Scalar.Sub` in `pkg/frost/group/ristretto255/ristretto255.go`

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Scalar.Add()` and `ristretto255.Scalar.Subtract()`
- Operations are modular arithmetic in constant time
- No branches based on scalar values
- No table lookups indexed by scalar values

**Example**:
```go
// Safe to use with secret values
secretShare1 := participant1.GetShare()  // secret
secretShare2 := participant2.GetShare()  // secret
sum := secretShare1.Add(secretShare2)    // CONSTANT TIME ✅
```

#### Multiplication

**Operation**: `Scalar.Mul(other)` - Scalar multiplication modulo group order

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Scalar.Mul`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Scalar.Multiply()`
- Montgomery multiplication in constant time
- No early exit based on zero/one optimizations
- No conditional branches on input values

**Example**:
```go
// Safe to use with secret values
lambda := computeLagrangeCoefficient(participants)  // public
secretShare := participant.GetShare()                // secret
product := lambda.Mul(secretShare)                   // CONSTANT TIME ✅
```

#### Inversion

**Operation**: `Scalar.Inv()` - Multiplicative inverse modulo group order

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Scalar.Inv`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Scalar.Invert()`
- Fermat's Little Theorem: `a^-1 = a^(p-2) mod p`
- Exponentiation by squaring in constant time
- Returns error for zero scalar (constant time check)

**Example**:
```go
// Safe to use with secret values (but typically used with public values)
denominator := computeDenominator(xCoords)  // typically public
inverse, err := denominator.Inv()           // CONSTANT TIME ✅
```

#### Negation

**Operation**: `Scalar.Negate()` - Additive inverse modulo group order

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Scalar.Negate`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Scalar.Negate()`
- Computes `p - scalar` in constant time
- No conditional logic

### Point Operations

All elliptic curve point operations execute in constant time.

#### Scalar Multiplication

**Operation**: `Group.ScalarMult(element, scalar)` - Point multiplication

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.ScalarMult`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Element.ScalarMult()`
- Montgomery ladder or similar constant-time algorithm
- Processes all bits of scalar regardless of value
- No conditional point additions

**Example**:
```go
// Safe to use with secret scalar
publicKey := group.Generator()        // public
secretShare := participant.GetShare() // secret
partialPublicKey := group.ScalarMult(publicKey, secretShare)  // CONSTANT TIME ✅
```

#### Scalar Base Multiplication

**Operation**: `Group.ScalarBaseMult(scalar)` - Multiplication by generator

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.ScalarBaseMult`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Element.ScalarBaseMult()`
- Optimized constant-time base point multiplication
- May use precomputed tables in constant-time manner
- No branches on scalar value

**Example**:
```go
// Safe to use with secret nonce
hidingNonce := generateNonce()  // secret
commitment := group.ScalarBaseMult(hidingNonce)  // CONSTANT TIME ✅
```

#### Point Addition

**Operation**: `Element.Add(other)` - Elliptic curve point addition

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Element.Add`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Element.Add()`
- Unified addition formulas (no special cases)
- Same execution path for all inputs
- No timing variation

**Example**:
```go
// Safe to use with any points
commitment1 := participant1.GetCommitment()  // public
commitment2 := participant2.GetCommitment()  // public
groupCommitment := commitment1.Add(commitment2)  // CONSTANT TIME ✅
```

### Comparison Operations

#### Equality Checks

**Operations**:
- `Scalar.Equal(other)` - Scalar equality
- `Element.Equal(other)` - Point equality

**Implementation**:
- Scalar: `pkg/frost/group/ristretto255/ristretto255.go` (`Scalar.Equal`)
- Element: `pkg/frost/group/ristretto255/ristretto255.go` (`Element.Equal`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255` equality functions which use constant-time comparison
- Returns 1 for equal, 0 for not equal (no early exit)
- Compares all bytes regardless of first difference

**Example**:
```go
// Safe to use with secret values
if nonce.Equal(zeroScalar) {  // CONSTANT TIME ✅
    return errors.New("nonce must be non-zero")
}
```

### Serialization and Deserialization

#### Scalar Serialization

**Operation**: `Group.SerializeScalar(scalar)` - Encode scalar to bytes

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.SerializeScalar`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Scalar.Bytes()`
- Canonical little-endian encoding
- No branches based on scalar value
- Processes all bytes

**Example**:
```go
// Safe to use with secret values
secretShare := participant.GetShare()
bytes := group.SerializeScalar(secretShare)  // CONSTANT TIME ✅
```

#### Scalar Deserialization

**Operation**: `Group.DeserializeScalar(data)` - Decode bytes to scalar

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.DeserializeScalar`)

**Constant-Time Guarantee**: ✅ **YES** (with caveats)

**Details**:
- Checks the length is 32 bytes, then uses `ristretto255.Scalar.SetCanonicalBytes()`
- Rejects non-canonical encodings (value >= group order)
- Validation is constant-time
- **Caveat**: Error path may differ in timing (acceptable for deserialization)

**Example**:
```go
// Safe to deserialize from network
shareBytes := receiveFromNetwork()
share, err := group.DeserializeScalar(shareBytes)  // CONSTANT TIME ✅
if err != nil {
    return err  // Timing of error path is acceptable
}
```

#### Element Serialization

**Operation**: `Group.SerializeElement(element)` - Encode point to bytes

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.SerializeElement`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Uses `ristretto255.Element.Bytes()`
- Canonical encoding of Ristretto point
- Checks for identity element (`IsIdentity` uses the constant-time `Equal`)
- Returns `ErrIdentityElement` if identity (timing of that early return is acceptable)

#### Element Deserialization

**Operation**: `Group.DeserializeElement(data)` - Decode bytes to point

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.DeserializeElement`)

**Constant-Time Guarantee**: ✅ **YES** (with caveats)

**Details**:
- Checks the length is 32 bytes, then uses `ristretto255.Element.SetCanonicalBytes()`
- Rejects invalid Ristretto encodings and the identity element (`ErrIdentityElement`)
- Validation inside the upstream decoder is constant-time per upstream documentation
- **Caveat**: Error path may differ in timing (acceptable for deserialization)

### Random Number Generation

#### Random Scalar Generation

**Operation**: `Group.RandomScalar()` - Generate cryptographically secure random scalar

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Group.RandomScalar`)

**Constant-Time Guarantee**: ✅ **YES**

**Details**:
- Reads 64 bytes from `crypto/rand` (constant time)
- Uses `ristretto255.Scalar.SetUniformBytes()` (wide reduction, constant time)
- No rejection sampling loops
- No timing variation based on output

**Example**:
```go
// Generates secret nonce in constant time
nonce, err := group.RandomScalar()  // CONSTANT TIME ✅
```

**Note on Randomness**: While the operation is constant-time, the quality of randomness depends on the operating system's CSPRNG. On Linux, this uses `/dev/urandom`. Ensure sufficient entropy, especially in embedded systems or VMs.

### Hash Functions

All hash functions in FROST use SHA-512, which is designed to be constant-time with respect to input data.

**Operations**:
- `H1(msg)` - Hash to scalar (binding factors)
- `H2(msg)` - Hash to scalar (challenge)
- `H3(msg)` - Hash to scalar (nonce generation)
- `H4(msg)` - Hash to bytes (misc)
- `H5(msg)` - Hash to bytes (misc)

**Implementation**: `pkg/frost/ciphersuite/ristretto255_sha512/ciphersuite.go`

**Constant-Time Guarantee**: ⚠️ **PARTIAL**

**Details**:
- SHA-512 compression function is constant-time
- Input length is processed in constant time
- **Caveat**: Message length may leak through padding (standard behavior)
- **Caveat**: Memory allocation timing may vary with message size

**Security Note**: Hash function timing variations are generally acceptable because:
1. Messages are typically public or low-sensitivity
2. Length hiding can be achieved through padding at application layer
3. Timing differences are small compared to network jitter

---

## Non-Constant-Time Operations

The following operations are NOT constant-time and should NOT be used with secret values.

### Scalar Ordering Comparison

**Operation**: `Scalar.Compare(other)` - Lexicographic comparison returning -1, 0, or 1

**Implementation**: `pkg/frost/group/ristretto255/ristretto255.go` (`Scalar.Compare`)

**Constant-Time Guarantee**: ❌ **NO**

**Code** (abridged):
```go
func (s *Scalar) Compare(other group.Scalar) int {
    // bytes are little-endian, so they are reversed before big.Int
    sBig := new(big.Int).SetBytes(reverseBytes(s.Bytes()))
    oBig := new(big.Int).SetBytes(reverseBytes(other.(*Scalar).Bytes()))
    return sBig.Cmp(oBig)  // ⚠️ NOT CONSTANT TIME
}
```

**Issue**: `big.Int.Cmp()` is not guaranteed constant-time. It may exit early when finding the first differing byte.

**Current Usage Analysis**: a search of the non-test code under `pkg/` finds no
call to `.Compare(` (the method exists to satisfy the `group.Scalar` interface).

**Status**: ✅ **SAFE** - Not used with secret values in current implementation

**Warning**: If this method is used in the future, it MUST NOT be used to compare secret scalars.

**Acceptable Uses**:
- Sorting participant identifiers (public values)
- Comparing public keys
- Ordering commitments

**Prohibited Uses**:
- Comparing secret key shares
- Comparing nonces
- Any operation where result reveals secret information

The method's doc comment already carries this warning: it is NOT constant-time for
ordering, must not be used on secret scalars, and `Equal()` is the call for secret equality.

### Big Integer Operations

**Context**: `Scalar.Compare` (above) is the one place the ristretto255 group uses
`big.Int`. Polynomial and Lagrange code in `pkg/frost/helpers/polynomial.go` builds
the constant scalar 1 with `scalarOne`, which deserializes a fixed byte string in the
group's byte order:

```go
oneBytes := make([]byte, grp.ScalarLength())
if grp.ByteOrder() == group.BigEndian { oneBytes[len(oneBytes)-1] = 1 } else { oneBytes[0] = 1 }
one, _ := grp.DeserializeScalar(oneBytes)
```

**Constant-Time Status**: the constant involves no secret data, so its timing is not a
concern. Other suites (P-256, secp256k1, Ed448) may use `big.Int` internally; they are
outside this guide.

### Message Length Checks

**Context**: Input validation may check message length.

**Example**:
```go
if len(msg) > MaxMessageSize {
    return errors.New("message too large")
}
```

**Constant-Time Status**: ❌ **NO** - Length comparison is variable-time

**Security Impact**: ✅ **ACCEPTABLE**

**Rationale**:
- Message content is typically public or semi-public
- Message length is not sensitive in FROST protocol
- Early rejection of oversized messages prevents DoS

**Note**: If message content must remain confidential, application should pad messages to fixed length before passing to FROST.

### Error Handling Paths

**Context**: Different error conditions may have different execution times.

**Examples**:
- Deserialization errors (malformed input detected at different stages)
- Validation failures (different checks may fail at different times)
- Network errors

**Constant-Time Status**: ❌ **NO** - Error paths vary in timing

**Security Impact**: ✅ **ACCEPTABLE**

**Rationale**:
1. **Input Validation**: Validating untrusted input can take variable time (standard practice)
2. **Fail-Stop Behavior**: FROST aborts on error, preventing oracle attacks
3. **Public Inputs**: Most validated data is public (commitments, participant IDs)

**Note**: the coordinator's errors for a bad share identify the participant (`frost.NewParticipantError`), because identifiable abort is the point of share verification. That identity is protocol-public, not secret.

### Memory Allocation

**Context**: Dynamic memory allocation timing varies with allocation size.

**Examples**:
- Creating slices for commitments
- Allocating buffers for serialization

**Constant-Time Status**: ❌ **NO** - Memory allocator is variable-time

**Security Impact**: ✅ **ACCEPTABLE**

**Rationale**:
- Allocation sizes are determined by public parameters (number of participants, message size)
- Go's garbage collector introduces timing variability regardless
- Secret data sizes are fixed (32 bytes for scalars, 32 bytes for elements)

**Mitigation**: Pre-allocate buffers where possible to reduce timing variability.

---

## Library Guarantees

### ristretto255 Library

**Package**: `github.com/gtank/ristretto255`

**Version**: see `go.mod` (v0.2.0 at the time of verification)

**Security Guarantees**:

1. **Constant-Time Scalar Operations**
   - All field operations (add, sub, mul, inv) execute in constant time
   - No conditional branches based on secret values
   - No table lookups indexed by secret values

2. **Constant-Time Point Operations**
   - Point addition using unified formulas
   - Scalar multiplication using Montgomery ladder or similar
   - No special-case handling based on point coordinates

3. **Canonical Encoding**
   - Serialization is deterministic and canonical
   - Deserialization rejects non-canonical encodings
   - No malleable representations

4. **Side-Channel Hardening**
   - Designed to resist timing attacks
   - Designed to resist cache-timing attacks (constant memory access patterns)
   - Based on rigorous cryptographic engineering principles

**Upstream Source**: Based on `filippo.io/edwards25519` and Ristretto specification

**Audits**: not verified here; check the upstream project for its own audit statements.

**Limitations**:
- Does not protect against power analysis (requires physical access)
- Does not protect against fault injection (requires physical access)
- Assumes trusted CPU and operating system
- May be vulnerable to speculative execution attacks (Spectre/Meltdown) depending on CPU and mitigations

### Go crypto/rand

**Package**: `crypto/rand`

**Security Guarantees**:

1. **Cryptographically Secure**
   - Uses operating system CSPRNG
   - Linux: `/dev/urandom`
   - Sufficient entropy for cryptographic operations

2. **Constant-Time Read**
   - `rand.Read()` executes in time proportional to number of bytes requested
   - No secret-dependent timing variations

**Limitations**:
- Entropy quality depends on operating system
- May block on systems with insufficient entropy (Linux `/dev/random`, but we use `/dev/urandom`)
- Virtualized environments may have weak entropy sources

**Best Practice**: Ensure operating system has sufficient entropy, especially:
- Embedded systems (add hardware RNG)
- Virtual machines (use virtio-rng)
- Containers (share host entropy)

### Go crypto/sha512

**Package**: `crypto/sha512`

**Security Guarantees**:

1. **Collision Resistance**
   - 256-bit security against collision attacks
   - No known practical attacks

2. **Preimage Resistance**
   - 512-bit security against preimage attacks
   - Suitable for hash-to-scalar operations

3. **Constant-Time Compression**
   - SHA-512 compression function is constant-time
   - Message length processed in constant time

**Limitations**:
- Message length may leak through timing (standard behavior)
- Memory allocation timing may vary (standard behavior)

---

## Timing Attack Mitigations

### 1. Network Jitter

**Mechanism**: Network latency variations mask sub-millisecond timing differences.

**Effectiveness** (general reasoning, not measured by this repository):
- **Remote Attacks**: network jitter can mask small timing differences
- **Local Attacks**: low - local processes bypass the network

**Deployment Recommendation**:
- Rely on network jitter for basic protection
- Add artificial delays for sensitive operations
- Do NOT rely solely on network jitter for high-security applications

**Example**:
```go
// Optional: Add random delay to mask timing variations
import (
    "crypto/rand"
    "math/big"
    "time"
)

func addRandomDelay() {
    // Random delay 0-50ms
    maxDelay := big.NewInt(50)
    delay, _ := rand.Int(rand.Reader, maxDelay)
    time.Sleep(time.Duration(delay.Int64()) * time.Millisecond)
}
```

### 2. Constant-Time Primitives

**Mechanism**: Use algorithms that execute in time independent of input values.

**Implementation**:
- ✅ All scalar arithmetic uses constant-time ristretto255
- ✅ All point operations use constant-time ristretto255
- ✅ `Equal` on ristretto255 scalars and elements is constant-time
- ⚠️ `Scalar.Compare` (ordering) uses `big.Int.Cmp` and is not constant-time; the
  ed25519 and ed448 groups have the same pattern, and the P-256 `Element.Equal`
  compares coordinates with `big.Int.Cmp`

**Verification**: search the non-test code under `pkg/` for `big.Int` `Cmp`,
`bytes.Compare` and `subtle.ConstantTimeCompare`, and confirm each hit is not
applied to secret values.

### 3. Unified Code Paths

**Mechanism**: Ensure all execution paths take the same time regardless of inputs.

**Example - Good**:
```go
// ✅ GOOD: Both paths execute same operations
func processShare(share Scalar, valid bool) error {
    result := computeHash(share)  // Always compute
    if !valid {
        return errors.New("invalid share")
    }
    storeResult(result)  // Conditional, but timing already leaked by validation
    return nil
}
```

**Example - Bad**:
```go
// ❌ BAD: Early exit leaks timing
func validateShare(share Scalar) error {
    if share.IsZero() {
        return errors.New("zero share")  // Early exit! ⚠️
    }
    // Expensive validation...
    if !expensiveCheck(share) {
        return errors.New("invalid")
    }
    return nil
}
```

**Current Status**: not established by a systematic audit; treat as a review guideline.

### 4. Blinding Techniques

**Mechanism**: Add random values to secret data, perform operation, then remove randomness.

**Example**:
```go
// Blinded scalar multiplication (not currently used)
func blindedScalarMult(secret Scalar, point Element) Element {
    r, _ := group.RandomScalar()          // Random blinding factor
    blinded := secret.Add(r)              // secret + r
    temp := group.ScalarMult(point, blinded)  // (secret + r) * P
    cancel := group.ScalarMult(point, r)      // r * P
    result := temp.Add(cancel.Negate())       // (secret + r) * P - r * P = secret * P
    return result
}
```

**Status**: ❌ Not implemented (constant-time primitives sufficient)

**Future Consideration**: May be useful for additional defense-in-depth

### 5. Input Validation

**Mechanism**: Reject invalid inputs early to prevent oracle attacks.

**Implementation**:
- ✅ Scalar deserialization rejects non-canonical values (`SetCanonicalBytes`)
- ✅ Element deserialization rejects invalid Ristretto encodings
- ✅ Identity element rejected on element deserialization (`ErrIdentityElement`)

**Security Note**: Validation timing may vary, but this is acceptable for untrusted inputs.

### 6. Signature Share Verification

**Mechanism**: Verify all signature shares before aggregation to prevent timing oracles.

**Implementation**: `participant.VerifySignatureShare` in `pkg/frost/signing/participant.go`
and `aggregator.AggregateWithVerification` in `pkg/frost/signing/aggregator.go`.

**Current Status**: opt-in. `Aggregate` does not verify individual shares;
`AggregateWithVerification` takes the participants' verification shares and checks
each signature share before combining them (identifiable abort).

**Recommendation**: use `AggregateWithVerification` where a bad share must be
attributed to a participant.

**Note**: failures identify the offending participant. That is the purpose of
identifiable abort, and the identifier is public protocol data, not a secret.

---

## Testing Methodology

### Unit Tests

#### Behavioral Side-Channel Test

**Location**: `test/rfc/appendixd_test.go`, subtest `SideChannelResistance`

**Purpose**: behavioral check only. It generates a scalar, multiplies the base point
and checks the result is non-nil. It does not measure timing.

#### Nonce Uniqueness Tests

**Location**: `TestSection4_1_NonceGeneration` in `test/rfc/section4_test.go`

**Purpose**: check generated nonces are unique. This is a randomness sanity check,
not a timing test.

### Statistical Timing Tests

**Location**: `test/rfc/section7_1_sidechannel_test.go`

**Methodology**: each test times an operation on two classes of input, applies
Welch's t-test and fails when |t| exceeds `tTestThreshold` (5.0).

**Tests**:
- `TestScalarMultiplicationTiming`
- `TestScalarBaseMultiplicationTiming`
- `TestNonceGenerationTiming`
- `TestSignatureShareVerificationTiming`
- `TestHashOperationTiming`
- `TestScalarEqualityTiming`
- `TestElementEqualityTiming`

**Running**: `make test-rfc` runs the suite with `-short`; `make test-rfc-full` runs
it without. Timing tests are statistical and sensitive to machine load, so run
them on a quiet machine.

**Limits**: these tests time in-process Go calls. They do not cover cache or
microarchitectural channels, network-level timing, or other suites' internals.

### Benchmarks

The same file defines `BenchmarkScalarMultiplication`, `BenchmarkScalarBaseMult`,
`BenchmarkNonceGeneration`, `BenchmarkSignatureVerification` and
`BenchmarkHashOperation`; each group package also has its own `BenchmarkScalarMult`
and `BenchmarkScalarBaseMult`. `make bench` runs the benchmark target. Timings depend
on the machine, so this guide gives no reference numbers.

### Integration and Network Timing

No network-level timing analysis exists in this repository. Applications deploying
participants over a network need to assess that themselves.

---

## Deployment Best Practices

### Hardware Recommendations

#### Dedicated Hardware (BEST)

**Configuration**:
- Bare-metal server
- No virtualization
- Dedicated CPU cores for FROST processes
- ECC memory
- Disabled hyperthreading

**Security Level**: ✅ **HIGHEST**

**Protection Against**:
- ✅ Remote timing attacks
- ✅ Local timing attacks
- ✅ Cache timing attacks
- ⚠️ Physical attacks (requires additional hardening)

**Use Cases**:
- High-value key custody
- Financial infrastructure
- Critical signing operations

#### Virtual Private Server (VPS) (ACCEPTABLE)

**Configuration**:
- Dedicated CPU cores (not shared)
- Isolated from other tenants
- Hypervisor-level protections
- Memory isolation

**Security Level**: ⚠️ **MEDIUM**

**Protection Against**:
- ✅ Remote timing attacks
- ⚠️ Local timing attacks (depends on hypervisor)
- ❌ Cache timing attacks (shared CPU cache)

**Use Cases**:
- Development and testing
- Low to medium value operations
- Non-critical infrastructure

#### Shared Hosting / Containers (NOT RECOMMENDED)

**Configuration**:
- Containers (Docker, Kubernetes)
- Shared hosting environments
- Multi-tenant virtualization

**Security Level**: ❌ **LOW**

**Protection Against**:
- ⚠️ Remote timing attacks (partially)
- ❌ Local timing attacks
- ❌ Cache timing attacks

**Use Cases**:
- Development only
- Testing only
- NOT for production

**Risks**:
- Other containers/processes can observe timing
- Shared CPU cache enables cache timing attacks
- Resource contention causes timing variations

### Operating System Hardening

#### Disable Hyperthreading

**Rationale**: Hyperthreading shares CPU resources between threads, enabling timing attacks.

**Linux**:
```bash
# Check if hyperthreading is enabled
lscpu | grep "Thread(s) per core"

# Disable hyperthreading (add to kernel cmdline)
echo "nosmt" | sudo tee -a /boot/cmdline.txt

# Reboot
sudo reboot
```

**Verification**:
```bash
lscpu | grep "Thread(s) per core"
# Should output: Thread(s) per core: 1
```

**Impact**: reduces CPU throughput; the size depends on the workload.

#### CPU Isolation

**Rationale**: Isolate FROST processes to dedicated CPU cores.

**Linux**:
```bash
# Isolate cores 4-7 for FROST processes
echo "isolcpus=4-7" | sudo tee -a /boot/cmdline.txt

# Reboot
sudo reboot

# Run FROST process on isolated cores
taskset -c 4-7 ./frost-participant
```

**Verification**:
```bash
ps aux | grep frost-participant
# Check CPU affinity
taskset -p <PID>
```

#### Disable Turbo Boost / Dynamic Frequency Scaling

**Rationale**: CPU frequency changes cause timing variations.

**Linux**:
```bash
# Disable turbo boost
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Set CPU governor to performance (constant frequency)
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Verification**:
```bash
cat /sys/devices/system/cpu/intel_pstate/no_turbo
# Should output: 1

cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# Should output: performance
```

#### Enable Address Space Layout Randomization (ASLR)

**Rationale**: Randomize memory addresses to mitigate cache-timing attacks.

**Linux**:
```bash
# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 2 = full randomization (recommended)

# Enable full ASLR
echo "2" | sudo tee /proc/sys/kernel/randomize_va_space

# Make permanent
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
```

#### Spectre/Meltdown Mitigations

**Rationale**: CPU vulnerabilities can leak secrets across security boundaries.

**Linux**:
```bash
# Check mitigations status
grep . /sys/devices/system/cpu/vulnerabilities/*

# Enable all mitigations (add to kernel cmdline)
# Note: mitigations can have a significant performance impact
echo "spec_store_bypass_disable=on spectre_v2=on l1tf=full,force mds=full,nosmt" | sudo tee -a /boot/cmdline.txt

# Reboot
sudo reboot
```

**Trade-off**: Performance degradation vs. security. Evaluate based on threat model.

### Network Hardening

#### Use TLS 1.3+

**Rationale**: Protect FROST messages from network attackers.

**Configuration**:
```go
import (
    "crypto/tls"
)

// Configure TLS for FROST communication
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{
        tls.X25519,
    },
}
```

#### Authenticated Channels

**Rationale**: Prevent man-in-the-middle attacks and participant impersonation.

**Recommendation**: Implement mutual TLS (mTLS) for participant authentication.

**Example**:
```go
// Server-side: Require client certificates
tlsConfig := &tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  loadTrustedCAs(),
}

// Client-side: Present certificate
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadClientCert()},
}
```

### Application Hardening

#### Message Size Limits

**Rationale**: Prevent DoS via large messages.

**Configuration**:
```go
const MaxMessageSize = 1 * 1024 * 1024  // 1 MB

func validateMessage(msg []byte) error {
    if len(msg) > MaxMessageSize {
        return errors.New("message too large")
    }
    return nil
}
```

#### Rate Limiting

**Rationale**: Prevent timing attack via statistical sampling.

**Configuration**:
```go
import "golang.org/x/time/rate"

// Limit signing requests to 10 per second per participant
limiter := rate.NewLimiter(10, 1)

func handleSigningRequest(req SigningRequest) error {
    if !limiter.Allow() {
        return errors.New("rate limit exceeded")
    }
    // Process request...
}
```

#### Audit Logging

**Rationale**: Detect timing attack attempts.

**Configuration**:
```go
import "log"

func logSecurityEvent(event string, details map[string]interface{}) {
    log.Printf("SECURITY: %s %v", event, details)
}

// Log signing requests with timing
start := time.Now()
signature, err := frost.Sign(msg)
duration := time.Since(start)

logSecurityEvent("signing_request", map[string]interface{}{
    "participant_id": participantID,
    "message_hash":   sha256.Sum256(msg),
    "duration_ms":    duration.Milliseconds(),
    "success":        err == nil,
})
```

**Analysis**: Monitor logs for:
- Unusual timing patterns
- High request rates from single participant
- Repeated failures

---

## Platform-Specific Considerations

### Linux

**Recommended Distribution**: Ubuntu 22.04 LTS or Debian 12 (stable, long-term support)

**Kernel Configuration**:
```bash
# Recommended kernel parameters
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
echo "kernel.kptr_restrict = 2" | sudo tee -a /etc/sysctl.conf
echo "kernel.yama.ptrace_scope = 1" | sudo tee -a /etc/sysctl.conf
```

**Entropy**: Linux provides good entropy via `/dev/urandom`. No additional configuration needed.

**Considerations**:
- ✅ Mature crypto/rand implementation
- ✅ Well-tested ristretto255 library
- ✅ Good performance
- ⚠️ Check Spectre/Meltdown mitigations

### macOS

**Recommended Version**: macOS 12 (Monterey) or later

**Entropy**: Uses Fortuna CSPRNG. Good quality randomness.

**Considerations**:
- ✅ Good crypto/rand implementation
- ⚠️ Difficult to disable hyperthreading
- ⚠️ Limited control over CPU frequency scaling
- ❌ Not recommended for high-security deployments (use Linux)

### Windows

**Recommended Version**: Windows Server 2022 or Windows 11

**Entropy**: Uses CryptGenRandom. Good quality randomness.

**Considerations**:
- ✅ Good crypto/rand implementation
- ⚠️ Limited hardening options vs. Linux
- ⚠️ Difficult to control CPU features
- ❌ Not recommended for high-security deployments (use Linux)

### Docker / Containers

**Recommendation**: ❌ **NOT RECOMMENDED** for production

**Issues**:
- Shared kernel with host
- Shared CPU cache with other containers
- Limited isolation from other processes
- Resource contention causes timing variations

**If Docker is Required**:
```yaml
# docker-compose.yml
services:
  frost-participant:
    image: frost:latest
    cpus: "2.0"              # Dedicated CPU quota
    mem_limit: "4g"           # Memory limit
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

**Better Alternative**: Use systemd-nspawn or LXC with dedicated CPU cores.

### Cloud Environments

#### AWS

**Recommended**: EC2 c6i instances (dedicated cores)

**Configuration**:
```bash
# Use dedicated instances (not shared)
# c6i.2xlarge: 8 vCPUs, 16 GB RAM

# Enable EBS encryption
# Use AWS Nitro Enclaves for additional isolation
```

**Considerations**:
- ✅ Good performance
- ✅ Nitro Enclaves provide hardware isolation
- ⚠️ Still virtualized (hypervisor attack surface)

#### Google Cloud Platform (GCP)

**Recommended**: Compute Engine n2-standard instances

**Configuration**:
```bash
# Use sole-tenant nodes for maximum isolation
gcloud compute sole-tenancy node-templates create frost-template \
    --node-type=n2-node-96-624

# Create instance on sole-tenant node
gcloud compute instances create frost-participant \
    --node=frost-node \
    --machine-type=n2-standard-8
```

**Considerations**:
- ✅ Sole-tenant nodes provide excellent isolation
- ⚠️ Higher cost vs. shared instances

#### Azure

**Recommended**: Azure Dedicated Host

**Considerations**:
- ✅ Full physical server isolation
- ⚠️ Higher cost vs. VMs

### Hardware Security Modules (HSMs)

**Use Case**: Maximum security for high-value keys

**Recommendations**:
- Yubico YubiHSM 2
- Thales nShield
- AWS CloudHSM

**Benefits**:
- ✅ Physical tamper resistance
- ✅ Side-channel hardened hardware
- ✅ Secure key storage

**Integration**: go-frost would need HSM adapter for key operations.

---

## References

### Academic Papers

1. **[FROST20]** Chelsea Komlo and Ian Goldberg. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." In SAC 2020.
   https://eprint.iacr.org/2020/852

2. **[StrongerSec22]** Bellare et al. "Better than Advertised Security for Non-interactive Threshold Signatures." 2022.
   https://eprint.iacr.org/2022/833

3. **[Timing96]** Paul C. Kocher. "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems." CRYPTO 1996.
   https://www.paulkocher.com/doc/TimingAttacks.pdf

4. **[Cache05]** Daniel J. Bernstein. "Cache-timing attacks on AES." 2005.
   https://cr.yp.to/antiforgery/cachetiming-20050414.pdf

5. **[BearSSL]** Thomas Pornin. "Why Constant-Time Crypto?" BearSSL Documentation.
   https://bearssl.org/ctmul.html

6. **[Pornin22]** Thomas Pornin. "Optimizing Curve25519 Verification." 2022.
   Referenced in RFC 9591 for efficient identity element checks.

### Specifications

7. **[RFC9591]** IETF RFC 9591: "The FROST Protocol for Two-Round Schnorr Signatures." June 2024.
   https://www.rfc-editor.org/rfc/rfc9591.html
   **Section 7.1**: Side-Channel Mitigations

8. **[RFC8032]** IETF RFC 8032: "Edwards-Curve Digital Signature Algorithm (EdDSA)." January 2017.
   https://www.rfc-editor.org/rfc/rfc8032.html

9. **[RFC7748]** IETF RFC 7748: "Elliptic Curves for Security." January 2016.
   https://www.rfc-editor.org/rfc/rfc7748.html

10. **[Ristretto]** Ristretto Group Specification.
    https://ristretto.group/

### Implementation References

11. **[ristretto255]** Go ristretto255 library by George Tankersley.
    https://github.com/gtank/ristretto255

12. **[edwards25519]** Filippo Valsorda's edwards25519 implementation.
    https://filippo.io/edwards25519

13. **[dudect]** Oscar Reparaz. "dudect: Constant-time verification tool."
    https://github.com/oreparaz/dudect

### Security Guidance

14. **[NIST]** NIST Special Publication 800-133: "Recommendation for Cryptographic Key Generation." 2019.
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf

15. **[Google Go Style]** Google Go Style Guide - Security.
    https://google.github.io/styleguide/go/

16. **[OWASP]** OWASP Cryptographic Storage Cheat Sheet.
    https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

### Related Documentation

17. **[go-frost Testing]** Security testing notes: `docs/security/testing.md`.

---

## Appendix A: Side-Channel Attack Timeline

Understanding historical attacks helps appreciate the importance of constant-time implementations.

| Year | Attack | Target | Impact |
|------|--------|--------|--------|
| 1996 | Kocher Timing Attack | RSA, DH, DSS | First practical timing attack |
| 2005 | Bernstein Cache Attack | AES | Demonstrated cache-timing on AES |
| 2013 | Lucky Thirteen | TLS | Padding oracle via timing |
| 2014 | FLUSH+RELOAD | Various | Cross-VM cache attacks |
| 2018 | Spectre/Meltdown | CPUs | Speculative execution leaks |
| 2020 | TPM-FAIL | TPM 2.0 | Timing attack on ECDSA nonces |

**Lesson**: Side-channel attacks are real, practical, and constantly evolving. Constant-time implementation is essential.

---

## Appendix B: Constant-Time Code Review Checklist

Use this checklist when reviewing code for side-channel vulnerabilities:

### Scalar Operations
- [ ] No conditional branches based on scalar values
- [ ] No early exit based on scalar properties (zero, one, etc.)
- [ ] No table lookups indexed by scalar values
- [ ] Use constant-time equality checks (`Equal()`, not `Compare()`)

### Point Operations
- [ ] No special-case handling for identity element in hot path
- [ ] No conditional point doubling vs. addition
- [ ] No early exit based on point coordinates

### Memory Access
- [ ] No array indexing by secret values
- [ ] No variable-length loops based on secret values
- [ ] Constant memory access patterns

### Comparisons
- [ ] Use `subtle.ConstantTimeCompare()` for byte arrays
- [ ] Use `Scalar.Equal()` for scalar equality
- [ ] No `bytes.Equal()` or `bytes.Compare()` with secrets

### Error Handling
- [ ] Error paths don't leak information via timing
- [ ] Generic error messages (no detailed failure info)
- [ ] Validation failures take similar time

### Randomness
- [ ] Use `crypto/rand` for all random generation
- [ ] No rejection sampling loops (use wide reduction)
- [ ] Check for sufficient entropy

---

## Appendix C: Example Attack Scenario

This appendix illustrates a concrete timing attack scenario against a hypothetical flawed implementation.

### Vulnerable Code (Hypothetical)

```go
// ⚠️ VULNERABLE IMPLEMENTATION - DO NOT USE
func vulnerableScalarMult(scalar Scalar, point Element) Element {
    result := Identity()

    // Process scalar bits from high to low
    for i := 255; i >= 0; i-- {
        result = result.Double()

        // ⚠️ TIMING LEAK: Conditional branch based on secret bit
        if scalar.Bit(i) == 1 {
            result = result.Add(point)  // Takes ~10 microseconds
        }
        // If bit is 0, skips addition → faster by ~10 microseconds
    }

    return result
}
```

### Attack Methodology

**Attacker Goal**: Recover participant's secret share `s`

**Step 1: Information Gathering**
- Attacker sends signing requests with different messages
- Measures response time from network perspective
- Collects 10,000 timing samples

**Step 2: Statistical Analysis**
```python
import numpy as np

# Group timing samples by hypothetical bit value
samples_if_bit_is_0 = []
samples_if_bit_is_1 = []

for i in range(256):  # For each bit position
    # Hypothesis: bit i is 0
    times_h0 = [t for t in timings if hypothetical_bit(t, i) == 0]
    samples_if_bit_is_0.append(np.mean(times_h0))

    # Hypothesis: bit i is 1
    times_h1 = [t for t in timings if hypothetical_bit(t, i) == 1]
    samples_if_bit_is_1.append(np.mean(times_h1))

# Detect timing difference
for i in range(256):
    diff = samples_if_bit_is_1[i] - samples_if_bit_is_0[i]
    if abs(diff) > threshold:
        print(f"Bit {i} is likely 1 (timing diff: {diff} us)")
    else:
        print(f"Bit {i} is likely 0")
```

**Step 3: Key Recovery**
- After analyzing all 256 bits, attacker reconstructs secret share
- Can now forge signatures without other participants

### Mitigated Code (go-frost)

```go
// ✅ SECURE IMPLEMENTATION - Used in go-frost
func secureScalarMult(scalar Scalar, point Element) Element {
    // Uses ristretto255.Element.ScalarMult()
    // Implements Montgomery ladder (constant-time)
    result := ristretto255.NewElement()
    result.ScalarMult(scalar.scalar, point.elem)
    return &Element{elem: result}
}
```

**Montgomery Ladder** (constant-time algorithm):
```
Input: scalar s, point P
Output: s * P

R0 = Identity
R1 = P

For each bit b of s from high to low:
    # Both branches execute SAME operations
    if b == 0:
        R1 = R0 + R1
        R0 = 2 * R0
    else:
        R0 = R0 + R1
        R1 = 2 * R1

Return R0
```

**Key Property**: Both branches perform one addition and one doubling → constant time.

