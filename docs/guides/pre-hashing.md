# Pre-Hashing Guidance for FROST

## Overview

This document provides comprehensive guidance on when and how to use pre-hashing with the FROST threshold signature scheme. Pre-hashing is the practice of hashing a message before passing it to the signing protocol, rather than signing the message directly.

### What is Pre-Hashing?

Pre-hashing is the process of applying a cryptographic hash function to a message before it is signed:

```
Without Pre-hashing: Sign(message) → signature
With Pre-hashing:    Sign(Hash(message)) → signature
```

By default, **FROST signatures do not pre-hash message inputs**. This means the entire message must be known in advance and passed directly to the signing protocol. However, RFC 9591 Section 7.6 explicitly allows applications to apply pre-hashing in specific scenarios where it provides practical benefits.

### Key Principle

> **Important**: Pre-hashing changes the security properties of the signature scheme. When you sign `Hash(message)` instead of `message`, you're relying on the collision resistance of the hash function for security.

---

## Table of Contents

- [When to Use Pre-Hashing](#when-to-use-pre-hashing)
- [When NOT to Use Pre-Hashing](#when-not-to-use-pre-hashing)
- [Security Considerations](#security-considerations)
- [Implementation Guide](#implementation-guide)
- [Hash Function Recommendations](#hash-function-recommendations)
- [Performance Implications](#performance-implications)
- [RFC 9591 Compliance](#rfc-9591-compliance)
- [Code Examples](#code-examples)
- [Common Pitfalls](#common-pitfalls)

---

## When to Use Pre-Hashing

Pre-hashing is beneficial and recommended in the following scenarios:

### 1. Large Messages

When signing messages that are too large to efficiently transmit or store in memory.

**Use Case Example**: Signing large files (videos, disk images, database dumps)

```go
// Instead of loading entire 10GB file into memory:
// signature := Sign(largeFile)  // ❌ Impractical

// Use pre-hashing:
hash := SHA256(largeFile)       // ✅ Can stream file
signature := Sign(hash)
```

**Why it helps**:
- Reduces memory footprint (hash is fixed-size, e.g., 32 bytes for SHA-256)
- Enables streaming processing of large data
- Reduces network bandwidth when message is transmitted to signers

**Threshold**: Consider pre-hashing for messages > 1MB

### 2. Streaming Data

When the message is generated or received incrementally and cannot be buffered entirely.

**Use Case Examples**:
- Network stream processing
- Real-time sensor data aggregation
- Log file signing
- Blockchain block signing

```go
hasher := sha256.New()
for chunk := range streamingData {
    hasher.Write(chunk)  // Incremental hashing
}
hash := hasher.Sum(nil)
signature := Sign(hash)
```

**Why it helps**:
- Process data as it arrives without buffering
- Constant memory usage regardless of total data size
- Enables real-time signing of unbounded streams

### 3. Storage-Constrained Environments

When participants have limited storage capacity for message retention.

**Use Case Examples**:
- IoT devices with limited memory
- Embedded systems
- Mobile applications
- Hardware security modules (HSMs)

**Why it helps**:
- Store fixed-size hash instead of arbitrary-length message
- Reduces storage requirements from O(message_size) to O(1)

### 4. Multiple Signature Schemes

When the same message needs to be signed by different signature schemes with different message size requirements.

**Use Case Example**: Hybrid signing systems

```go
// Some schemes have message size limits
hash := SHA256(message)
frostSig := FROST.Sign(hash)
ecdsaSig := ECDSA.Sign(hash)
rsaSig := RSA.Sign(hash)
```

**Why it helps**:
- Normalizes message format across different schemes
- Ensures compatibility with schemes that have size restrictions

### 5. Bandwidth-Constrained Networks

When transmitting messages to distributed signers over low-bandwidth channels.

**Use Case Examples**:
- Satellite communications
- Low-bandwidth radio networks
- Multi-region distributed signing (reducing cross-region traffic)

**Why it helps**:
- Transmit 32-byte hash instead of multi-megabyte message
- Reduces network costs in cloud environments
- Faster round-trip times for signing operations

---

## When NOT to Use Pre-Hashing

Pre-hashing is **NOT recommended** and may be harmful in these scenarios:

### 1. Short Messages

Messages that are already small (< 1KB).

**Why avoid pre-hashing**:
- Hash output (32-64 bytes) is similar size to original message
- Additional hash computation adds latency with no benefit
- Unnecessary complexity
- Reduces security to collision resistance

```go
// For short messages, sign directly
message := []byte("Transfer $100 to Alice")
signature := frostService.Sign(keyPackages, message)  // ✅ Correct
```

### 2. When Collision Resistance is Questionable

If you cannot use a hash function with strong collision resistance guarantees.

**Why avoid pre-hashing**:
- Security depends entirely on collision resistance
- Broken hash function = broken signature scheme
- Direct signing provides stronger security properties

### 3. Multiple Signatures of Same Message

When the same message will be signed multiple times by different participant sets.

**Why avoid pre-hashing**:
- Pre-hashing doesn't prevent replay attacks
- Coordinator can reuse hash across signing sessions
- Each signing session should ideally have unique context

**Better approach**: Include session-specific context in message

```go
// Instead of just signing Hash(message) multiple times
// Include unique session context
sessionMessage := append(message, sessionID...)
signature := Sign(sessionMessage)
```

### 4. When Message Validation is Required

When signing participants need to validate message content before signing.

**Example**: Transaction validation in cryptocurrency

```go
// Participants must see and validate the actual transaction
transaction := ParseTransaction(message)
if !ValidateTransaction(transaction) {
    return ErrInvalidTransaction
}
// Must sign the full message, not just a hash
signature := Sign(message)
```

**Why avoid pre-hashing**:
- Participants need to verify message structure and semantics
- Pre-hash hides message content from validation
- Could enable signing of invalid or malicious content

### 5. High-Security Applications

When your threat model requires the strongest possible security properties.

**Why avoid pre-hashing**:
- Direct message signing provides stronger security guarantees
- No dependency on hash function collision resistance
- Eliminates hash function as potential attack vector
- Reduces cryptographic assumptions

---

## Security Considerations

### Collision Resistance is Critical

When you pre-hash, signature security depends on collision resistance of the hash function.

**Attack Scenario**: If attacker finds `Hash(m1) = Hash(m2)`:
- Valid signature on `m1` is also valid signature on `m2`
- This breaks signature scheme's security

**Mitigation**:
- **REQUIRED**: Use collision-resistant hash with security level ≥ signature scheme
- Recommended: SHA-256 minimum, SHA-512 preferred
- Avoid: MD5, SHA-1, or any deprecated hash functions

### Security Level Matching

Hash function security must match or exceed the ciphersuite security level:

| Ciphersuite | Group Security Bits | Minimum Hash |
|------------|---------------------|--------------|
| FROST(Ed25519, SHA-512) | 126 bits | SHA-256 (128 bits) |
| FROST(ristretto255, SHA-512) | 126 bits | SHA-256 (128 bits) |
| FROST(Ed448, SHAKE256) | 223 bits | SHA-512 (256 bits) |
| FROST(P-256, SHA-256) | 128 bits | SHA-256 (128 bits) |
| FROST(secp256k1, SHA-256) | 128 bits | SHA-256 (128 bits) |

**Rule**: `Hash_Security_Bits ≥ Group_Security_Bits`

### Domain Separation

Pre-hashing MUST use domain separation to prevent cross-protocol attacks.

**From RFC 9591 Section 7.6**:
> "In particular, a different prefix SHOULD be used to differentiate this pre-hash from H4."

**Implementation**:
```go
// ❌ WRONG - No domain separation
preHash := SHA256(message)

// ✅ CORRECT - With domain separation
contextString := "FROST-v1-ristretto255-SHA-512"
prefix := "pre-hash"
preHash := SHA256(contextString || prefix || message)
```

**Why it matters**:
- Prevents hash collisions with protocol's internal hashing (H1, H2, H3, H4)
- Prevents cross-protocol attacks if hash is reused elsewhere
- Provides cryptographic separation between application and protocol

### Length Extension Attacks

Be aware of length extension attacks when using Merkle-Damgård hash functions.

**Vulnerable**: SHA-256, SHA-512
**Safe**: SHA-3, BLAKE2, BLAKE3

**Mitigation**:
- Use HMAC for additional protection if needed
- Or use SHA-3 family which is not vulnerable

```go
// If using SHA-256/512 and concerned about length extension
key := DeriveKey(contextString)
preHash := HMAC-SHA256(key, message)
```

### Nonce Reuse Still Catastrophic

Pre-hashing does **NOT** protect against nonce reuse attacks.

**Critical**: Each signing session must use fresh nonces regardless of pre-hashing.

```go
// ❌ WRONG - Reusing nonces is still catastrophic
hash := SHA256(message)
nonces1 := GenerateNonces()
sig1 := Sign(hash, nonces1)
sig2 := Sign(hash, nonces1)  // 💀 CRITICAL VULNERABILITY

// ✅ CORRECT - Always fresh nonces
hash := SHA256(message)
nonces1 := GenerateNonces()
sig1 := Sign(hash, nonces1)
nonces2 := GenerateNonces()
sig2 := Sign(hash, nonces2)
```

### Message Commitment

Consider committing to the original message in the signature context.

```go
// Include message digest in context for auditability
messageDigest := SHA256(message)
signingContext := append(contextString, messageDigest...)
preHash := SHA256(signingContext || message)
```

**Benefits**:
- Cryptographically binds signature to original message
- Enables verification that correct message was hashed
- Provides audit trail

---

## Implementation Guide

### Recommended Pre-Hashing Pattern

```go
package prehash

import (
    "crypto/sha256"
    "crypto/sha512"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// PreHashMessage applies pre-hashing with proper domain separation
func PreHashMessage(suite string, message []byte) []byte {
    // 1. Build domain separation string
    contextString := "FROST-v1-" + suite
    prefix := "pre-hash"

    // 2. Concatenate: contextString || prefix || message
    data := make([]byte, 0, len(contextString)+len(prefix)+len(message))
    data = append(data, []byte(contextString)...)
    data = append(data, []byte(prefix)...)
    data = append(data, message...)

    // 3. Hash based on suite
    switch suite {
    case "ristretto255-SHA-512", "Ed25519-SHA-512", "Ed448-SHAKE256":
        hash := sha512.Sum512(data)
        return hash[:]
    case "P-256-SHA-256", "secp256k1-SHA-256":
        hash := sha256.Sum256(data)
        return hash[:]
    default:
        // Default to SHA-512 for maximum security
        hash := sha512.Sum512(data)
        return hash[:]
    }
}

// SignWithPreHash signs a message after applying pre-hashing
func SignWithPreHash(
    frostService service.FrostService,
    keyPackages []frost.KeyPackage,
    message []byte,
) (frost.Signature, error) {
    // 1. Get ciphersuite name
    suite := frostService.GetCiphersuite().Name()

    // 2. Pre-hash the message
    messageHash := PreHashMessage(suite, message)

    // 3. Sign the hash
    return frostService.Sign(keyPackages, messageHash)
}

// VerifyWithPreHash verifies a signature created with pre-hashing
func VerifyWithPreHash(
    frostService service.FrostService,
    message []byte,
    signature frost.Signature,
    publicKey group.Element,
) error {
    // 1. Get ciphersuite name
    suite := frostService.GetCiphersuite().Name()

    // 2. Pre-hash the message (same as signing)
    messageHash := PreHashMessage(suite, message)

    // 3. Verify signature on hash
    return frostService.Verify(messageHash, signature, publicKey)
}
```

### Streaming Pre-Hash Pattern

For large files or streaming data:

```go
package prehash

import (
    "crypto/sha256"
    "hash"
    "io"
)

// StreamingPreHash computes pre-hash for large data streams
type StreamingPreHash struct {
    hasher hash.Hash
    suite  string
}

// NewStreamingPreHash creates a new streaming pre-hasher
func NewStreamingPreHash(suite string) *StreamingPreHash {
    h := &StreamingPreHash{
        suite: suite,
    }

    // Initialize hasher with domain separation
    h.hasher = sha256.New()

    contextString := "FROST-v1-" + suite
    prefix := "pre-hash"
    h.hasher.Write([]byte(contextString))
    h.hasher.Write([]byte(prefix))

    return h
}

// Write implements io.Writer for streaming data
func (h *StreamingPreHash) Write(data []byte) (int, error) {
    return h.hasher.Write(data)
}

// Finalize returns the computed pre-hash
func (h *StreamingPreHash) Finalize() []byte {
    return h.hasher.Sum(nil)
}

// Example usage for large files
func SignLargeFile(
    frostService service.FrostService,
    keyPackages []frost.KeyPackage,
    reader io.Reader,
) (frost.Signature, error) {
    // 1. Create streaming hasher
    suite := frostService.GetCiphersuite().Name()
    hasher := NewStreamingPreHash(suite)

    // 2. Stream file through hasher
    _, err := io.Copy(hasher, reader)
    if err != nil {
        return frost.Signature{}, err
    }

    // 3. Get final hash
    messageHash := hasher.Finalize()

    // 4. Sign the hash
    return frostService.Sign(keyPackages, messageHash)
}
```

---

## Hash Function Recommendations

### Primary Recommendations

Listed in order of preference:

#### 1. SHA-512 (Preferred for Most Use Cases)

**Pros**:
- 256-bit collision resistance
- Well-studied and standardized
- Faster than SHA-256 on 64-bit platforms
- Compatible with most FROST ciphersuites

**Cons**:
- Larger output (64 bytes vs 32 bytes)
- Vulnerable to length extension (use HMAC if concerned)

**Use for**:
- FROST(Ed25519, SHA-512)
- FROST(ristretto255, SHA-512)
- FROST(Ed448, SHAKE256)
- General purpose applications

```go
import "crypto/sha512"

hash := sha512.Sum512(data)
```

#### 2. SHA-256 (Acceptable)

**Pros**:
- 128-bit collision resistance (sufficient for most use cases)
- Smaller output (32 bytes)
- Ubiquitous support
- Well-studied

**Cons**:
- Lower security margin than SHA-512
- Vulnerable to length extension

**Use for**:
- FROST(P-256, SHA-256)
- FROST(secp256k1, SHA-256)
- Bandwidth-constrained environments

```go
import "crypto/sha256"

hash := sha256.Sum256(data)
```

#### 3. BLAKE3 (Best for Performance)

**Pros**:
- Fastest cryptographic hash function
- Not vulnerable to length extension
- 128-bit collision resistance
- Supports parallel hashing
- Tree-mode for large files

**Cons**:
- Newer, less widely adopted
- Not in Go standard library

**Use for**:
- High-performance requirements
- Very large files
- Streaming applications

```go
import "github.com/zeebo/blake3"

hash := blake3.Sum256(data)
```

#### 4. SHA3-256 (Most Conservative)

**Pros**:
- Different construction than SHA-2 (Keccak vs Merkle-Damgård)
- Not vulnerable to length extension
- NIST standard
- 128-bit collision resistance

**Cons**:
- Slower than SHA-256
- Larger implementation

**Use for**:
- Maximum security paranoia
- Defense in depth (different from ciphersuite hash)

```go
import "golang.org/x/crypto/sha3"

hash := sha3.Sum256(data)
```

### Hash Functions to AVOID

| Hash Function | Status | Reason |
|--------------|--------|---------|
| MD5 | ❌ NEVER USE | Broken - practical collision attacks |
| SHA-1 | ❌ NEVER USE | Broken - collision attacks demonstrated |
| SHA-224 | ⚠️ AVOID | Truncated SHA-256, no advantages |
| RIPEMD-160 | ⚠️ AVOID | Insufficient collision resistance (80 bits) |

---

## Performance Implications

### Computational Cost

Pre-hashing adds one additional hash computation to the signing and verification process.

**Typical Hash Performance** (64-bit platform, 1MB message):

| Hash Function | Throughput | Time for 1MB |
|--------------|------------|--------------|
| BLAKE3 | ~3 GB/s | 0.3 ms |
| SHA-256 | ~500 MB/s | 2 ms |
| SHA-512 | ~800 MB/s | 1.3 ms |
| SHA3-256 | ~200 MB/s | 5 ms |

**Signing Time Breakdown**:
```
Without pre-hash: FROST signing time only (~10-50ms)
With pre-hash:    Hash time + FROST signing time

For small messages (<1KB): Adds ~0.01ms overhead
For medium messages (1MB): Adds ~1-5ms overhead
For large messages (1GB):  Saves overall time (streaming)
```

### Memory Usage

Pre-hashing can significantly reduce memory usage for large messages:

```
Direct signing:   O(message_size) memory
Pre-hash signing: O(hash_output) memory

For 1GB message:
  Direct: 1GB RAM needed
  Pre-hash: 64 bytes RAM needed

Savings: 99.99%+ reduction
```

### Network Bandwidth

When signers are distributed across network:

```
Direct signing:   Transmit full message to each signer
Pre-hash signing: Transmit only hash to each signer

For 1GB message with 5 signers:
  Direct: 5GB network transfer
  Pre-hash: 320 bytes transfer
```

### Recommendation

Use pre-hashing when:
- Message size > 1MB (memory/network benefits outweigh overhead)
- Streaming data (enables processing without buffering)
- Storage is limited

Don't use pre-hashing when:
- Message size < 1KB (overhead exceeds benefit)
- Maximum performance needed for small messages

---

## RFC 9591 Compliance

### Section 7.6: Input Message Hashing

RFC 9591 explicitly addresses pre-hashing in Section 7.6:

> "FROST signatures do not pre-hash message inputs. This means that the entire message must be known in advance of invoking the signing protocol. Applications can apply pre-hashing in settings where storing the full message is prohibitively expensive."

### Requirements

The RFC imposes specific requirements when pre-hashing is used:

#### 1. Collision Resistance (REQUIRED)

> "Pre-hashing MUST use a collision-resistant hash function with a security level commensurate with the security inherent to the ciphersuite chosen."

**Implementation**: Always use SHA-256 or stronger.

#### 2. Domain Separation (RECOMMENDED)

> "For applications that choose to apply pre-hashing, it is RECOMMENDED that they use the hash function (H) associated with the chosen ciphersuite in a manner similar to how H4 is defined. In particular, a different prefix SHOULD be used to differentiate this pre-hash from H4."

**Implementation**: Include context string and unique prefix.

**Example from RFC**:
```
H(contextString || "Quux-pre-hash" || m)
```

**Our implementation**:
```go
contextString := "FROST-v1-ristretto255-SHA-512"
prefix := "pre-hash"
H(contextString || prefix || message)
```

### Ciphersuite Hash Functions

Use the hash function that matches your ciphersuite for consistency:

| Ciphersuite | Protocol Hash | Pre-Hash Should Use |
|------------|---------------|---------------------|
| FROST(Ed25519, SHA-512) | SHA-512 | SHA-512 |
| FROST(ristretto255, SHA-512) | SHA-512 | SHA-512 |
| FROST(Ed448, SHAKE256) | SHAKE256 | SHAKE256 or SHA-512 |
| FROST(P-256, SHA-256) | SHA-256 | SHA-256 |
| FROST(secp256k1, SHA-256) | SHA-256 | SHA-256 |

### Verification

Both signing and verification must use identical pre-hashing:

```go
// Signing side
preHash := SHA512(contextString || "pre-hash" || message)
signature := Sign(preHash)

// Verification side (MUST use same pre-hash)
preHash := SHA512(contextString || "pre-hash" || message)
valid := Verify(preHash, signature, publicKey)
```

**Critical**: Verifier must know that pre-hashing was used and apply the same function.

---

## Code Examples

### Example 1: Basic Pre-Hashing

```go
package main

import (
    "crypto/sha512"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

func main() {
    // Setup
    suite := ristretto255_sha512.New()
    frostService := service.NewFrostService(suite)

    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }

    keyPackages, groupPublicKey, err := frostService.GenerateKeys(
        config,
        []frost.Identifier{1, 2, 3},
    )
    if err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }

    // Large message
    largeMessage := make([]byte, 10*1024*1024) // 10MB

    // Pre-hash the message
    contextString := "FROST-v1-" + suite.Name()
    prefix := "pre-hash"
    data := append([]byte(contextString), []byte(prefix)...)
    data = append(data, largeMessage...)

    hash := sha512.Sum512(data)
    messageHash := hash[:]

    // Sign the hash instead of the full message
    signature, err := frostService.Sign(
        []frost.KeyPackage{keyPackages[0], keyPackages[1]},
        messageHash,
    )
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    // Verify with same pre-hash
    err = frostService.Verify(messageHash, signature, groupPublicKey)
    if err != nil {
        log.Fatalf("Verification failed: %v", err)
    }

    fmt.Println("Success! Large message signed using pre-hash.")
}
```

### Example 2: Streaming File Signing

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "io"
    "log"
    "os"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

func SignFile(
    frostService service.FrostService,
    keyPackages []frost.KeyPackage,
    filePath string,
) (frost.Signature, error) {
    // Open file
    file, err := os.Open(filePath)
    if err != nil {
        return frost.Signature{}, err
    }
    defer file.Close()

    // Create hasher with domain separation
    hasher := sha256.New()
    suite := frostService.GetCiphersuite().Name()
    contextString := "FROST-v1-" + suite
    prefix := "pre-hash"
    hasher.Write([]byte(contextString))
    hasher.Write([]byte(prefix))

    // Stream file through hasher (constant memory usage)
    _, err = io.Copy(hasher, file)
    if err != nil {
        return frost.Signature{}, err
    }

    // Get hash
    messageHash := hasher.Sum(nil)

    // Sign hash
    return frostService.Sign(keyPackages, messageHash)
}

func main() {
    suite := ristretto255_sha512.New()
    frostService := service.NewFrostService(suite)

    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }

    keyPackages, _, _ := frostService.GenerateKeys(
        config,
        []frost.Identifier{1, 2, 3},
    )

    // Sign large file without loading into memory
    signature, err := SignFile(
        frostService,
        []frost.KeyPackage{keyPackages[0], keyPackages[1]},
        "/path/to/large/file.bin",
    )
    if err != nil {
        log.Fatalf("File signing failed: %v", err)
    }

    fmt.Printf("File signed successfully: %v\n", signature)
}
```

### Example 3: Pre-Hash Helper Library

```go
package prehash

import (
    "crypto/sha256"
    "crypto/sha512"
    "hash"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/group"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// Config holds pre-hashing configuration
type Config struct {
    Suite      string
    HashFunc   func() hash.Hash
    ContextStr string
}

// GetDefaultConfig returns recommended config for a ciphersuite
func GetDefaultConfig(ciphersuiteName string) Config {
    switch ciphersuiteName {
    case "FROST(ristretto255, SHA-512)", "FROST(Ed25519, SHA-512)":
        return Config{
            Suite:      ciphersuiteName,
            HashFunc:   sha512.New,
            ContextStr: "FROST-v1-" + ciphersuiteName,
        }
    case "FROST(P-256, SHA-256)", "FROST(secp256k1, SHA-256)":
        return Config{
            Suite:      ciphersuiteName,
            HashFunc:   sha256.New,
            ContextStr: "FROST-v1-" + ciphersuiteName,
        }
    default:
        // Default to SHA-512 for maximum security
        return Config{
            Suite:      ciphersuiteName,
            HashFunc:   sha512.New,
            ContextStr: "FROST-v1-" + ciphersuiteName,
        }
    }
}

// Hash computes pre-hash with domain separation
func (c Config) Hash(message []byte) []byte {
    hasher := c.HashFunc()
    hasher.Write([]byte(c.ContextStr))
    hasher.Write([]byte("pre-hash"))
    hasher.Write(message)
    return hasher.Sum(nil)
}

// SignWithPreHash is a convenience wrapper
func SignWithPreHash(
    frostService service.FrostService,
    keyPackages []frost.KeyPackage,
    message []byte,
) (frost.Signature, error) {
    config := GetDefaultConfig(frostService.GetCiphersuite().Name())
    hash := config.Hash(message)
    return frostService.Sign(keyPackages, hash)
}

// VerifyWithPreHash is a convenience wrapper
func VerifyWithPreHash(
    frostService service.FrostService,
    message []byte,
    signature frost.Signature,
    publicKey group.Element,
) error {
    config := GetDefaultConfig(frostService.GetCiphersuite().Name())
    hash := config.Hash(message)
    return frostService.Verify(hash, signature, publicKey)
}
```

---

## Common Pitfalls

### Pitfall 1: Forgetting Domain Separation

**Problem**:
```go
// ❌ WRONG - No domain separation
hash := sha256.Sum256(message)
signature := Sign(hash[:])
```

**Solution**:
```go
// ✅ CORRECT - Proper domain separation
contextString := "FROST-v1-" + suite.Name()
data := append([]byte(contextString), []byte("pre-hash")...)
data = append(data, message...)
hash := sha256.Sum256(data)
signature := Sign(hash[:])
```

### Pitfall 2: Using Weak Hash Functions

**Problem**:
```go
// ❌ WRONG - SHA-1 is broken
hash := sha1.Sum(message)
```

**Solution**:
```go
// ✅ CORRECT - Use SHA-256 or better
hash := sha256.Sum256(message)
```

### Pitfall 3: Inconsistent Pre-Hashing

**Problem**:
```go
// Signing side uses pre-hash
hash := SHA256(message)
signature := Sign(hash)

// Verification side forgets pre-hash
valid := Verify(message, signature)  // ❌ Will fail!
```

**Solution**:
```go
// Both sides must use same pre-hash
hash := SHA256(message)
signature := Sign(hash)
valid := Verify(hash, signature)  // ✅ Correct
```

### Pitfall 4: Pre-Hashing Short Messages

**Problem**:
```go
// ❌ Unnecessary for short message
message := []byte("Hello")
hash := SHA512(message)  // 64 bytes hash of 5 byte message!
signature := Sign(hash)
```

**Solution**:
```go
// ✅ Sign short messages directly
message := []byte("Hello")
signature := Sign(message)
```

### Pitfall 5: Ignoring Security Level

**Problem**:
```go
// ❌ WRONG - Hash too weak for ciphersuite
// Ed448 has 223-bit security, SHA-256 only has 128-bit
suite := Ed448()
hash := SHA256(message)  // Insufficient!
```

**Solution**:
```go
// ✅ CORRECT - Hash matches security level
suite := Ed448()
hash := SHA512(message)  // 256-bit collision resistance
```

---

## Summary

### Quick Decision Guide

```
Should I use pre-hashing?

Is message > 1MB?
├─ YES → Use pre-hashing
└─ NO → Is message from streaming source?
    ├─ YES → Use pre-hashing
    └─ NO → Is storage severely constrained?
        ├─ YES → Use pre-hashing
        └─ NO → Don't use pre-hashing (sign directly)
```

### Checklist for Pre-Hashing Implementation

- [ ] Message size justifies pre-hashing (>1MB or streaming)
- [ ] Using collision-resistant hash (SHA-256 minimum)
- [ ] Hash security level ≥ ciphersuite security level
- [ ] Domain separation implemented (context string + prefix)
- [ ] Signing and verification use same pre-hash
- [ ] Fresh nonces generated for each signing session
- [ ] Pre-hash function documented for verifiers

### Key Takeaways

1. **Pre-hashing is optional** - FROST doesn't require it
2. **Use for large messages** - Primary benefit is memory/bandwidth savings
3. **Collision resistance is critical** - Use SHA-256 or better
4. **Domain separation required** - Prevent cross-protocol attacks
5. **Consistency essential** - Sign and verify must use same pre-hash
6. **Don't overuse** - Short messages should be signed directly

---

## References

- **RFC 9591**: The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol
  - Section 7.6: Input Message Hashing
  - https://www.rfc-editor.org/rfc/rfc9591.html

- **NIST SP 800-107**: Recommendation for Applications Using Approved Hash Algorithms
  - https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final

- **NIST FIPS 180-4**: Secure Hash Standard (SHS)
  - https://csrc.nist.gov/publications/detail/fips/180/4/final

- **go-frost Documentation**:
  - API Reference: `/docs/api-reference.md`
  - Examples: `/docs/examples.md`
  - Security Considerations: `/docs/rfc-compliance.md`
