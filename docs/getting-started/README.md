# Getting Started

Quick start guide for using go-frost in your application.

## Installation

See [installation.md](installation.md) for detailed installation instructions.

## Quick Start Example

```go
import (
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// Create a FROST service
suite := ristretto255_sha512.New()
frostService := service.NewFrostService(suite)

// Generate keys for 3 participants with threshold of 2
config := frost.Configuration{
    MinSigners: 2,
    MaxSigners: 3,
    Group:      suite.Group(),
}
participantIDs := []frost.Identifier{1, 2, 3}
keyPackages, groupPublicKey, err := frostService.GenerateKeys(config, participantIDs)
if err != nil {
    panic(err)
}

// Sign a message with 2 participants
msg := []byte("Hello, FROST!")
signingPackages := []frost.KeyPackage{keyPackages[0], keyPackages[1]}
signature, err := frostService.Sign(signingPackages, msg)
if err != nil {
    panic(err)
}

// Verify the signature
err = frostService.Verify(msg, signature, groupPublicKey)
if err != nil {
    panic(err)
}
```

## Using Different Ciphersuites

All 5 RFC 9591 ciphersuites are supported. Simply import and instantiate the desired ciphersuite:

```go
// FROST(ristretto255, SHA-512) - RFC 6.2 (default, recommended)
import "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
suite := ristretto255_sha512.New()

// FROST(Ed25519, SHA-512) - RFC 6.1
import "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
suite := ed25519_sha512.New()

// FROST(P-256, SHA-256) - RFC 6.4 (NIST standard)
import "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
suite := p256_sha256.New()

// FROST(secp256k1, SHA-256) - RFC 6.5 (Bitcoin curve)
import "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
suite := secp256k1_sha256.New()

// FROST(Ed448, SHAKE256) - RFC 6.3 (highest security, 224-bit)
import "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
suite := ed448_shake256.New()
```

All ciphersuites work identically - just swap the import and instantiation.

## Next Steps

- Read the [installation guide](installation.md) for detailed setup
- See [examples](../examples/README.md) for more comprehensive examples
- Review the [API reference](../api/reference.md) for complete API documentation
- Understand [security considerations](../security/README.md) for production deployments
