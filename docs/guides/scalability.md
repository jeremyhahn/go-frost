# FROST Scalability Analysis

> **Status: REFERENCE** · Last verified: 2026-10-09
> Scalability considerations for go-frost deployments.

## Overview

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is designed for **threshold signature schemes** with small-to-medium participant groups. While cryptographically sound at any scale, practical considerations limit the number of participants. The complexity and size figures below are derived from the protocol and the ristretto255 encoding; go-frost publishes no measured timings, so no latency figures are given (run `make bench` for your hardware).

## Computational Complexity

### Per-Signature Operations

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Nonce Generation | O(1) per participant | Constant time |
| Commitment Broadcasting | O(n) | Linear in participants |
| Binding Factor Computation | O(n) | Hash all commitments |
| Lagrange Coefficients | O(t²) | Quadratic in threshold |
| Signature Share Generation | O(1) per participant | Constant time |
| Signature Aggregation | O(n) | Linear in signers |

**Total Coordinator Overhead**: O(n + t²)
**Total Participant Overhead**: O(n) (mostly communication)

## Communication Overhead

### Bandwidth Requirements (per signature)

**Ristretto255 encoding sizes** (other ciphersuites differ, e.g. P-256 compressed points are 33 bytes):
- Group element: 32 bytes
- Scalar: 32 bytes

**Two-round protocol:**

#### Round 1: Commitment Phase
Each participant broadcasts:
- Hiding nonce commitment (D): 32 bytes
- Binding nonce commitment (E): 32 bytes
- **Total per participant**: 64 bytes
- **Total for n participants**: 64n bytes

#### Round 2: Signing Phase
Each participant broadcasts:
- Signature share (z): 32 bytes
- **Total per participant**: 32 bytes
- **Total for n participants**: 32n bytes

#### Final Signature
Coordinator outputs:
- Group commitment (R): 32 bytes
- Combined scalar (z): 32 bytes
- **Total**: 64 bytes (constant)

### Bandwidth Examples

| Participants (n) | Round 1 | Round 2 | Total |
|------------------|---------|---------|-------|
| 3 | 192 bytes | 96 bytes | 288 bytes |
| 10 | 640 bytes | 320 bytes | 960 bytes |
| 50 | 3.1 KB | 1.6 KB | 4.7 KB |
| 100 | 6.3 KB | 3.2 KB | 9.5 KB |
| 500 | 31 KB | 16 KB | 47 KB |
| 1000 | 63 KB | 32 KB | 95 KB |

**Note**: These are protocol minimums. Real deployments add overhead for:
- Network framing (TCP/TLS headers)
- Authentication proofs
- Participant identifiers
- Metadata and timestamps

## Memory Requirements

These are lower bounds on the serialized data a session holds, not measurements of Go heap usage.

### Coordinator State (per active session)

| Component | Size | Formula |
|-----------|------|---------|
| Participant list | 4n bytes | n × `uint32` identifiers (`frost.Identifier`) |
| Commitments | 64n bytes | n × 2 group elements |
| Signature shares | 32n bytes | n × scalar |
| Verification shares (if enabled) | 32n bytes | n × group element |
| Binding factors | 32n bytes | n × scalar |
| Lagrange coefficients | 32t bytes | t × scalar |

**Total per session**: ~164n + 32t bytes

**Examples:**
- 10 participants (t=7): ~1.9 KB per session
- 100 participants (t=67): ~18.5 KB per session
- 1000 participants (t=667): ~185 KB per session

### Participant State (per session)

- Nonces (hiding + binding): 64 bytes
- Commitments from others: 64n bytes
- Binding factors: 32 bytes
- Own signature share: 32 bytes

**Total**: ~64n + 128 bytes

## Practical Limits

### Deployment Size Guidance

These are design recommendations, not measured limits.

#### Small Groups (3-20 participants)
- **Use case**: Multisig wallets, small teams
- **Latency**: Network-bound
- **Recommendation**: ✅ **Optimal range**

#### Medium Groups (20-100 participants)
- **Use case**: Enterprise governance, DAOs
- **Latency**: Coordination-bound
- **Recommendation**: ✅ **Well-supported**

#### Large Groups (100-500 participants)
- **Use case**: Large organizations, federated systems
- **Latency**: Significant coordination overhead
- **Recommendation**: ⚠️ **Possible but requires tuning and your own load testing**

#### Very Large Groups (500-1000+ participants)
- **Latency**: Coordination becomes primary bottleneck
- **Recommendation**: ❌ **Not practical**

### Why Not Thousands?

1. **Coordination Complexity**: Gathering commitments from thousands of participants is slow
2. **Network Bandwidth**: ~100KB per signature at 1000 participants
3. **Failure Probability**: More participants = higher chance someone is offline/malicious
4. **Diminished Returns**: High thresholds (t=667 for n=1000) provide little additional security over smaller groups

### Alternative Approaches for Large-Scale

If you need thousands of participants:

1. **Hierarchical Threshold Signatures**
   - Top-level FROST among group leaders (10-20)
   - Each leader runs FROST within their group (10-50)
   - Reduces coordination to O(log n)

2. **BLS Signature Aggregation**
   - Different scheme optimized for many signers
   - O(1) signature size regardless of signers
   - Trade-off: Requires trusted setup or pairing-friendly curves

3. **Proof-of-Stake Consensus**
   - Select rotating subset of signers
   - Only active subset participates in FROST
   - Reduces n while maintaining security

## SecurityConfig Limits

`security.SecurityConfig.MaxSignersPerSession` (`uint32`) is set to 1000 by `DefaultProductionConfig()` and `DefaultDevelopmentConfig()`, and to 0 (no limit) by `InsecureConfig()`. `SecurityConfig.Validate()` rejects values above 10000.

**Not enforced by the library:** no signing or service code reads this field today. Applications that want the cap must check the participant count themselves against `MaxSignersPerSession`.

### Current Defaults

```go
MaxSignersPerSession: 1000  // DoS protection ceiling
```

### Suggested Values

**For typical deployments:**
```go
MaxSignersPerSession: 100   // Conservative limit
```

**For high-security/low-latency:**
```go
MaxSignersPerSession: 50    // Optimal performance
```

**For large organizations:**
```go
MaxSignersPerSession: 200   // Maximum practical limit
```

**DoS protection only:**
```go
MaxSignersPerSession: 1000  // Default (generous ceiling)
```

## Benchmark Data

No benchmark results are published. Run `make bench` to measure on your hardware.

## Recommendations

### For Application Developers

1. **Design for 10-50 participants** as the primary use case
2. **Set MaxSignersPerSession based on your actual needs**, not theoretical maximums
3. **Implement timeout handling** - larger groups have higher failure probability
4. **Consider threshold carefully** - t=2n/3 is common, t=1000 is excessive

### For Production Deployments

1. **Start conservative**: Begin with MaxSignersPerSession: 50
2. **Monitor and tune**: Increase only if genuinely needed
3. **Test at scale**: Load test with your actual participant count
4. **Plan for failures**: Larger groups → more likely someone is offline

### For High-Scale Requirements

If you truly need >100 participants:

1. **Evaluate alternatives** (hierarchical, BLS, etc.)
2. **Benchmark first** - measure actual performance
3. **Implement retry logic** - failures are more likely
4. **Consider async coordination** - don't block on slow participants

## Conclusion

FROST works well for 3-100 participants. Hundreds are possible but increasingly impractical. Thousands are not viable with the current protocol.

The default `MaxSignersPerSession: 1000` is a configured ceiling meant to limit DoS exposure, not a performance target. Real-world deployments should use much smaller values based on actual requirements.
