# Getting Started with go-frost

This guide will help you get started with go-frost, a FROST threshold signature implementation in Go.

## Table of Contents

- [Installation](#installation)
- [Basic Concepts](#basic-concepts)
- [Your First FROST Signature](#your-first-frost-signature)
- [Common Patterns](#common-patterns)
- [Error Handling](#error-handling)
- [Next Steps](#next-steps)

## Installation

### Prerequisites

- Go 1.21 or later
- Git

### Install the Package

```bash
go get github.com/jeremyhahn/go-frost
```

### Verify Installation

Create a simple test file:

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

func main() {
    suite := ristretto255_sha512.New()
    fmt.Printf("Ciphersuite: %s\n", suite.Name())
}
```

Run it:

```bash
go run main.go
```

## Basic Concepts

### Threshold Signatures

FROST is a threshold signature scheme where:
- **t-of-n threshold**: `t` participants out of `n` total can create a valid signature
- **MinSigners (t)**: Minimum number of participants needed to sign
- **MaxSigners (n)**: Total number of participants in the group

### Key Components

1. **Ciphersuite**: Defines the cryptographic primitives (group + hash function)
2. **Service**: High-level API for FROST operations
3. **Key Packages**: Contains secret shares for each participant
4. **Configuration**: Threshold parameters and group settings

### Two-Round Signing Protocol

FROST uses a two-round protocol:
1. **Round One**: Participants generate and share nonce commitments
2. **Round Two**: Participants compute signature shares
3. **Aggregation**: Coordinator aggregates shares into final signature

## Your First FROST Signature

Here's a complete example of creating a 2-of-3 threshold signature:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

func main() {
    // Step 1: Create a ciphersuite
    suite := ristretto255_sha512.New()
    fmt.Printf("Using ciphersuite: %s\n", suite.Name())

    // Step 2: Create the FROST service
    frostService := service.NewFrostService(suite)

    // Step 3: Configure a 2-of-3 threshold scheme
    config := frost.Configuration{
        MinSigners: 2, // Need 2 participants to sign
        MaxSigners: 3, // Total of 3 participants
        Group:      suite.Group(),
    }

    // Step 4: Generate key shares for 3 participants
    participantIDs := []frost.Identifier{1, 2, 3}
    keyPackages, groupPublicKey, err := frostService.GenerateKeys(config, participantIDs)
    if err != nil {
        log.Fatalf("Key generation failed: %v", err)
    }
    fmt.Printf("Generated keys for %d participants\n", len(keyPackages))

    // Step 5: Sign a message with 2 participants (participants 1 and 2)
    message := []byte("Hello, FROST!")
    signingParticipants := []frost.KeyPackage{keyPackages[0], keyPackages[1]}

    signature, err := frostService.Sign(signingParticipants, message)
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }
    fmt.Printf("Signature created successfully\n")

    // Step 6: Verify the signature
    err = frostService.Verify(message, signature, groupPublicKey)
    if err != nil {
        log.Fatalf("Signature verification failed: %v", err)
    }
    fmt.Println("Signature verified successfully!")

    // Step 7: Try with different participants (participants 2 and 3)
    signingParticipants2 := []frost.KeyPackage{keyPackages[1], keyPackages[2]}
    signature2, err := frostService.Sign(signingParticipants2, message)
    if err != nil {
        log.Fatalf("Signing with different participants failed: %v", err)
    }

    err = frostService.Verify(message, signature2, groupPublicKey)
    if err != nil {
        log.Fatalf("Verification failed: %v", err)
    }
    fmt.Println("Different participants created valid signature!")
}
```

## Common Patterns

### Pattern 1: Key Package Storage

Key packages contain sensitive material and should be stored securely:

```go
// Each participant should store their own key package
func storeKeyPackage(pkg frost.KeyPackage, participantID frost.Identifier) error {
    // In production, encrypt and store securely
    // This is just an example
    return nil
}

// Retrieve when needed for signing
func loadKeyPackage(participantID frost.Identifier) (frost.KeyPackage, error) {
    var pkg frost.KeyPackage
    // Load from secure storage
    return pkg, nil
}
```

### Pattern 2: Asynchronous Signing with Sessions

For distributed systems where participants don't sign synchronously:

```go
// Create a session manager
sessionManager := service.NewSessionManager(frostService)

// Coordinator creates a signing session
participantIDs := []frost.Identifier{1, 2, 3}
message := []byte("Document to sign")
session, err := sessionManager.CreateSession(participantIDs, message)
if err != nil {
    log.Fatal(err)
}

// Participants join asynchronously and add commitments
commitment1 := frost.SigningCommitments{
    Identifier:             1,
    HidingNonceCommitment:  /* from participant 1 */,
    BindingNonceCommitment: /* from participant 1 */,
}
err = session.AddCommitment(commitment1)

// After enough commitments, proceed to round 2
commitmentList, err := session.GetCommitmentList()

// Participants add signature shares
// ... (similar pattern)

// Get final signature when complete
if session.IsComplete() {
    signature, err := session.GetSignature()
}
```

### Pattern 3: Verifying Key Shares

Participants should verify their key shares after key generation:

```go
for i, pkg := range keyPackages {
    err := frostService.VerifyKeyShare(pkg)
    if err != nil {
        log.Printf("Participant %d key share verification failed: %v", i+1, err)
        continue
    }
    log.Printf("Participant %d key share verified", i+1)
}
```

### Pattern 4: Different Threshold Configurations

```go
// 2-of-2 (multisig)
config := frost.Configuration{
    MinSigners: 2,
    MaxSigners: 2,
    Group:      suite.Group(),
}

// 3-of-5 (typical threshold)
config := frost.Configuration{
    MinSigners: 3,
    MaxSigners: 5,
    Group:      suite.Group(),
}

// 5-of-9 (high security, high availability)
config := frost.Configuration{
    MinSigners: 5,
    MaxSigners: 9,
    Group:      suite.Group(),
}
```

## Error Handling

go-frost uses typed errors for proper error handling:

```go
import "errors"

signature, err := frostService.Sign(keyPackages, message)
if err != nil {
    // Check for specific error types
    var paramErr *frost.ParameterError
    if errors.As(err, &paramErr) {
        log.Printf("Invalid parameter %s: %s", paramErr.Parameter, paramErr.Reason)
        return
    }

    var participantErr *frost.ParticipantError
    if errors.As(err, &participantErr) {
        log.Printf("Participant %d error: %s", participantErr.Identifier, participantErr.Reason)
        return
    }

    // Check for specific error conditions
    if errors.Is(err, frost.ErrInsufficientParticipants) {
        log.Println("Need more participants to sign")
        return
    }

    if errors.Is(err, frost.ErrInvalidSignature) {
        log.Println("Signature verification failed")
        return
    }

    // Generic error
    log.Printf("Error: %v", err)
}
```

### Common Errors

- `ErrInvalidParameters`: Invalid function parameters
- `ErrInvalidThreshold`: Threshold configuration is invalid
- `ErrInsufficientParticipants`: Not enough participants to sign
- `ErrDuplicateParticipant`: Duplicate participant IDs
- `ErrInvalidSignature`: Signature verification failed
- `ErrInvalidKeyShare`: Key share verification failed

## Next Steps

Now that you understand the basics:

1. Read the [Protocol Documentation](protocol.md) to understand how FROST works
2. Explore the [API Reference](api-reference.md) for detailed API documentation
3. Check out more [Examples](examples.md) for advanced use cases
4. Review [RFC Compliance](rfc-compliance.md) for specification details
5. Learn about [Testing](testing.md) your FROST implementation

## Tips and Best Practices

### Security

- **Never reuse nonces**: The service handles this automatically
- **Protect key packages**: Store them encrypted and with proper access controls
- **Verify group public key**: All participants should verify they have the same group public key
- **Use trusted key generation**: This implementation uses a trusted dealer; consider DKG for production

### Performance

- **Batch operations**: Sign multiple messages with the same participants in parallel
- **Session management**: Use sessions for asynchronous/distributed signing
- **Benchmark your use case**: Run benchmarks to understand performance characteristics

### Integration

- **Network transport**: FROST is network-agnostic; design your transport layer separately
- **State management**: Track signing rounds and participant commitments
- **Timeouts**: Implement timeouts for rounds to handle unresponsive participants
- **Retries**: Handle transient failures with appropriate retry logic
