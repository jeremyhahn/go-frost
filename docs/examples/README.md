# FROST Examples

Complete code examples demonstrating how to use go-frost.

## Basic Signing Example

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

func main() {
    // Create FROST service with ristretto255 ciphersuite
    suite := ristretto255_sha512.New()
    frostService := service.NewFrostService(suite)

    // Configure threshold signature scheme
    // 2-of-3: need 2 participants to sign, 3 total participants
    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }

    // Generate keys for 3 participants
    participantIDs := []frost.Identifier{1, 2, 3}
    keyPackages, groupPublicKey, err := frostService.GenerateKeys(config, participantIDs)
    if err != nil {
        panic(err)
    }

    // Sign a message using participants 1 and 2
    message := []byte("Hello, FROST!")
    signingPackages := []frost.KeyPackage{keyPackages[0], keyPackages[1]}
    signature, err := frostService.Sign(signingPackages, message)
    if err != nil {
        panic(err)
    }

    // Verify the signature
    err = frostService.Verify(message, signature, groupPublicKey)
    if err != nil {
        fmt.Println("Signature verification failed:", err)
        return
    }

    fmt.Println("Signature verified successfully!")
}
```

## Distributed Signing Example

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

func main() {
    suite := ristretto255_sha512.New()

    // ... (key generation omitted for brevity)

    message := []byte("Distributed signing example")

    // Round 1: Each participant generates commitments
    participant1 := signing.NewParticipant(keyPackage1, suite)
    participant2 := signing.NewParticipant(keyPackage2, suite)

    commitments1, err := participant1.Commit()
    if err != nil {
        panic(err)
    }

    commitments2, err := participant2.Commit()
    if err != nil {
        panic(err)
    }

    // Collect commitments (in real app, exchange over network)
    allCommitments := []frost.SigningCommitments{commitments1, commitments2}

    // Round 2: Each participant generates signature shares
    share1, err := participant1.Sign(message, allCommitments)
    if err != nil {
        panic(err)
    }

    share2, err := participant2.Sign(message, allCommitments)
    if err != nil {
        panic(err)
    }

    // Aggregate signature shares
    aggregator := signing.NewAggregator(suite, allCommitments)
    signature, err := aggregator.Aggregate(message, []frost.SignatureShare{share1, share2})
    if err != nil {
        panic(err)
    }

    // Verify
    err = suite.Verify(message, signature, groupPublicKey)
    if err != nil {
        fmt.Println("Verification failed:", err)
        return
    }

    fmt.Println("Distributed signature verified!")
}
```

## Advanced Examples

### Custom Ciphersuites
For examples of using different ciphersuites (Ed25519, P-256, secp256k1), see the test files in `pkg/frost/ciphersuite/`.

### Coordinator Pattern
Example of using the optional coordinator for managing signing sessions:

```go
coordinator := signing.NewCoordinator(suite, config)
session, err := coordinator.CreateSession(participantIDs, message)
// ... manage multi-round signing session
```

### Error Handling
Proper error handling with typed errors:

```go
signature, err := frostService.Sign(signingPackages, message)
if err != nil {
    switch {
    case errors.Is(err, frost.ErrInvalidSignature):
        // Handle invalid signature
    case errors.Is(err, frost.ErrNonceReuse):
        // Handle nonce reuse attempt
    case errors.Is(err, frost.ErrInvalidParticipant):
        // Handle invalid participant
    default:
        // Handle other errors
    }
}
```

## Running Examples

Examples can be found in the test files:
- `pkg/frost/service/frost_test.go` - Service layer examples
- `pkg/frost/signing/*_test.go` - Signing protocol examples
- `test/rfc/` - RFC 9591 test vectors

Run examples:
```bash
# Run all tests (includes examples)
make test

# Run specific package tests
go test -v ./pkg/frost/service/...
go test -v ./pkg/frost/signing/...
```

## Next Steps

- Review [API Reference](../api/reference.md) for complete API documentation
- Read [Security Considerations](../security/README.md) before production use
- See [Integration Guide](../guides/integration.md) for application integration
