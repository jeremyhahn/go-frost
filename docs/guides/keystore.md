# FROST Keystore Integration

> **Status: REFERENCE** · Last verified: 2026-10-09
> Guide to the `pkg/frost/keystore` package.

The `keystore` package stores FROST key material behind a pluggable `StorageBackend`. The package ships a file backend (`NewFileStorage`) and an in-memory backend (`NewMemoryStorage`); applications may supply their own. `go-frost` has no dependency on go-xkms.

## Overview

The keystore layer abstracts key storage operations and provides:

- **Secure Storage**: Key packages are written with 0600 permissions, group public keys with 0644
- **Protected Secret Shares**: Shares are held in protected memory (`secmem.SecretBytes`) and reach the backend through `PutSecret`/`GetSecret`
- **Thread Safety**: Delegated to the storage backend; `KeychainStore` itself holds no lock (see [Thread Safety](#thread-safety))
- **Serialization/Deserialization**: Automatic conversion between FROST types and storage format
- **Metadata Management**: Track key creation time, updates, group membership, and custom tags
- **Group Management**: Store and retrieve group public keys with threshold configuration
- **Pluggable Storage**: Any `StorageBackend` implementation (file, memory, or your own DHT/cloud/HSM-backed store)

## Architecture

### Storage Layout

```
<storage-path>/
├── frost/
│   ├── keypackages/
│   │   ├── participant-1.json    # Key package for participant 1
│   │   ├── participant-2.json    # Key package for participant 2
│   │   └── participant-3.json    # Key package for participant 3
│   └── groups/
│       └── signing-group.json    # Group public key and metadata
```

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                      KeyStore Interface                      │
│  - StoreKeyPackage                                          │
│  - GetKeyPackage                                            │
│  - DeleteKeyPackage                                         │
│  - ListKeyPackages                                          │
│  - StoreGroupPublicKey                                      │
│  - GetGroupPublicKey                                        │
│  - ListGroups, UpdateMetadata, Close, ...                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ implements
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                    KeychainStore                            │
│  - Uses the StorageBackend from Config.Storage             │
│  - Handles serialization/deserialization                   │
│  - Manages metadata and lifecycle                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ uses
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                    StorageBackend                           │
│  - NewFileStorage: files with explicit permissions         │
│  - NewMemoryStorage: protected in-memory store             │
│  - Or an application-supplied implementation               │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Example

```go
package main

import (
	"fmt"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/keystore"
)

func main() {
	// Initialize ciphersuite
	cs := ristretto255_sha512.New()
	group := cs.Group()

	// Create the storage backend
	storage, err := keystore.NewFileStorage("/var/lib/frost/keys")
	if err != nil {
		panic(err)
	}

	// Configure keystore
	config := &keystore.Config{
		Group:   group,
		Storage: storage,
		Tags: map[string]string{
			"environment": "production",
			"application": "signing-service",
		},
	}

	// Create keystore
	ks, err := keystore.NewKeychainStore(config)
	if err != nil {
		panic(err)
	}
	defer ks.Close()

	// Generate keys using trusted dealer
	dealer := keygen.NewDealer(cs)
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		panic(err)
	}

	// Store key packages
	groupID := "signing-group-1"
	for _, kp := range keyPackages {
		keyID := fmt.Sprintf("participant-%d", kp.Identifier)
		err := ks.StoreKeyPackage(keyID, groupID, &kp, 2, 3)
		if err != nil {
			panic(err)
		}
	}

	// Store group public key
	err = ks.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		panic(err)
	}

	// Later: Retrieve key package for signing
	keyPackage, metadata, err := ks.GetKeyPackage("participant-1")
	if err != nil {
		panic(err)
	}
	_, _ = keyPackage, metadata

	// Use key package for signing operations...
}
```

### Integration with FROST Service

```go
// Sign with key packages loaded from the keystore
func sign(ks keystore.KeyStore, ids []frost.Identifier, msg []byte) (frost.Signature, error) {
	var packages []frost.KeyPackage
	for _, id := range ids {
		kp, _, err := ks.GetKeyPackage(fmt.Sprintf("participant-%d", id))
		if err != nil {
			return frost.Signature{}, err
		}
		packages = append(packages, *kp)
	}

	svc := service.NewFrostService(ristretto255_sha512.New())
	return svc.Sign(packages, msg)
}
```

### Listing and Filtering Keys

```go
// List all key packages in a group
metadata, err := ks.ListKeyPackages("signing-group-1")
if err != nil {
	panic(err)
}

for _, meta := range metadata {
	fmt.Printf("Key ID: %s\n", meta.KeyID)
	fmt.Printf("  Group: %s\n", meta.GroupID)
	fmt.Printf("  Threshold: %d of %d\n", meta.MinSigners, meta.MaxSigners)
	fmt.Printf("  Created: %v\n", time.Unix(meta.CreatedAt, 0))
	fmt.Printf("  Tags: %v\n", meta.Tags)
}

// List all groups
groups, err := ks.ListGroups()
if err != nil {
	panic(err)
}

for _, group := range groups {
	fmt.Printf("Group ID: %s\n", group.GroupID)
	fmt.Printf("  Threshold: %d of %d\n", group.MinSigners, group.MaxSigners)
	fmt.Printf("  Created: %v\n", time.Unix(group.CreatedAt, 0))
}
```

### Updating Metadata

```go
// Get current metadata
_, metadata, err := ks.GetKeyPackage("participant-1")
if err != nil {
	panic(err)
}

// Update tags
metadata.Tags["rotated"] = "2025-01-01"
metadata.Tags["status"] = "active"

// Save updated metadata
err = ks.UpdateMetadata("participant-1", metadata)
if err != nil {
	panic(err)
}
```

### Key Deletion

```go
// Delete a key package
err := ks.DeleteKeyPackage("participant-1")
if err != nil {
	panic(err)
}

// Delete a group public key
err = ks.DeleteGroupPublicKey("signing-group-1")
if err != nil {
	panic(err)
}
```

## API Reference

### KeyStore Interface

#### StoreKeyPackage

```go
StoreKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32) error
```

Stores a key package with the given key ID and group ID.

**Parameters:**
- `keyID`: Unique identifier for the key package
- `groupID`: Identifier for the signing group
- `kp`: The key package to store
- `minSigners`: Threshold (minimum signers required)
- `maxSigners`: Total number of participants

**Returns:**
- `ErrAlreadyExists` if a key package with the same key ID already exists
- `ErrInvalidKeyID` if keyID is empty
- `ErrInvalidGroupID` if groupID is empty
- `ErrInvalidKeyPackage` if kp is nil

#### GetKeyPackage

```go
GetKeyPackage(keyID string) (*frost.KeyPackage, *KeyMetadata, error)
```

Retrieves a key package and its metadata by key ID.

**Parameters:**
- `keyID`: Unique identifier for the key package

**Returns:**
- The key package
- Associated metadata
- `ErrNotFound` if the key package does not exist

#### DeleteKeyPackage

```go
DeleteKeyPackage(keyID string) error
```

Removes a key package by key ID.

**Parameters:**
- `keyID`: Unique identifier for the key package

**Returns:**
- `ErrNotFound` if the key package does not exist

#### ListKeyPackages

```go
ListKeyPackages(groupID string) ([]*KeyMetadata, error)
```

Returns metadata for all stored key packages. If groupID is non-empty, only key packages for that group are returned.

**Parameters:**
- `groupID`: Optional group ID filter (empty string for all keys)

**Returns:**
- Slice of key metadata

#### StoreGroupPublicKey

```go
StoreGroupPublicKey(groupID string, publicKey group.Element, minSigners, maxSigners uint32) error
```

Stores the group public key for a signing group.

**Parameters:**
- `groupID`: Identifier for the signing group
- `publicKey`: The group's public key
- `minSigners`: Threshold
- `maxSigners`: Total participants

**Returns:**
- `ErrAlreadyExists` if a group public key already exists for this group ID

#### GetGroupPublicKey

```go
GetGroupPublicKey(groupID string) (group.Element, error)
```

Retrieves the group public key for a signing group.

**Parameters:**
- `groupID`: Identifier for the signing group

**Returns:**
- The group public key
- `ErrNotFound` if the group public key does not exist

### Types

#### StoredKeyPackage

```go
type StoredKeyPackage struct {
	Identifier           frost.Identifier
	SecretShareProtected *secmem.SecretBytes `json:"-"`
	GroupPublicKey       []byte
	VerificationShares   []StoredVerificationShare
	Metadata             KeyMetadata
}
```

Represents a key package in storage format with serialized cryptographic material.

The secret share is held only in protected memory (`secmem.SecretBytes`): the
struct carries no plaintext copy of it. Call `Zeroize()` when finished with a
stored key package to destroy the enclave.

Because the struct carries the share, its serialized form is secret too - the
document holds the share base64-encoded in plain sight. So a `StoredKeyPackage`
**cannot be serialized with `encoding/json`**: `MarshalJSON` and
`UnmarshalJSON` return `ErrPlaintextSerialization`. `encoding/json` assembles
its output in a buffer it draws from a package-level `sync.Pool` and returns to
that pool with the plaintext still in it, where no amount of zeroization by
this package can reach it.

Use `Seal` and `OpenStoredKeyPackage` instead:

```go
payload, err := storedKP.Seal()   // *secmem.SecretBytes, caller destroys
defer payload.Destroy()

restored, err := keystore.OpenStoredKeyPackage(payload)
defer restored.Zeroize()
```

`Seal` assembles the document inside a mlock'd buffer, base64-encoding the
share straight out of its enclave and splicing the public members - which
`encoding/json` still serializes, since they carry nothing secret - in around
it. `OpenStoredKeyPackage` decodes from inside the enclave and base64-decodes
the share straight into a protected buffer of its own. Neither the share nor
the document is ever an ordinary heap allocation, and the wire format is
unchanged - the share is still written under the `SecretShare` key, byte for
byte as `encoding/json` used to write it, member order included: the share
member is spliced in after `Identifier`, where the plaintext field used to be
declared. Existing stores read back unmodified.

A document carrying no share is rejected with `ErrMissingSecretShare`. So is
one this package cannot decode without routing the share through the heap: a
duplicated `SecretShare` member, which `encoding/json` and the share scan would
resolve differently, or a value carrying a JSON escape, which base64 never
produces and unescaping would copy.

#### KeyMetadata

```go
type KeyMetadata struct {
	KeyID      string
	GroupID    string
	MinSigners uint32
	MaxSigners uint32
	CreatedAt  int64
	UpdatedAt  int64
	Tags       map[string]string
}
```

Contains metadata about a stored key package.

#### GroupPublicKeyEntry

```go
type GroupPublicKeyEntry struct {
	GroupID    string
	PublicKey  []byte
	MinSigners uint32
	MaxSigners uint32
	CreatedAt  int64
}
```

Represents a stored group public key with metadata.

## Security Considerations

### File Permissions

`KeychainStore` requests these permissions from the backend; the file backend applies them:
- **Key packages**: 0600 (owner read/write only)
- **Group public keys**: 0644 (owner read/write, others read)
- **Directories** created by the file backend: 0700 (owner access only)

### Thread Safety

`KeychainStore` holds no lock of its own; it relies on the `StorageBackend`, which the `KeyStore` interface requires to be thread-safe. The file backend guards its operations with a `sync.RWMutex` and the memory backend with a `sync.Mutex`. Note that `StoreKeyPackage` and `StoreGroupPublicKey` check existence and then write as two backend calls, so two concurrent stores of the same ID can both pass the check.

### Key Material Handling

- Secret shares live in protected memory (mlock'd, encrypted at rest via
  `secmem.SecretBytes`) for as long as they are in the process; no plaintext
  duplicate is kept beside the protected copy
- Serialized key packages move between the keystore and its storage backend
  through the `PutSecret`/`GetSecret` pair of `StorageBackend`, so a
  serialized secret share is never held or returned as a plain `[]byte`; the
  plain `Put`/`Get` pair carries public material (group public keys)
- Serialization does not route the share through the ordinary heap at all:
  the document is assembled and decoded inside protected memory. Any transient
  plaintext that does reach the heap - the share a `frost.KeyPackage` hands to
  `FromKeyPackage`, for instance - is zeroized in place as soon as it has been
  sealed
- `secmem.NewSecret(size, fill)` builds a secret in place inside a protected
  buffer, for material that has to be assembled or decoded rather than simply
  copied; `secmem.NewSecretBytes` can only seal what is already on the heap
- Reach for `secmem.WithSecret` or `secmem.Clone` rather than pairing
  `Open`/`Reseal` by hand: those two hold the secret's mutex for the whole
  open/use/reseal cycle, so a concurrent `Destroy` cannot be undone by the
  reseal that follows it
- No key material is logged or exposed in error messages
- Key IDs and group IDs are sanitized to prevent path traversal (`/` and `..` become `_`), so IDs that differ only in those characters map to the same storage key

Custom storage backends must implement `PutSecret` and `GetSecret` alongside
the plain operations. `PutSecret` receives the payload in protected memory and
must not retain it as a plain `[]byte`; `GetSecret` returns a `SecretBytes`
that the caller owns and destroys. A backend that keeps the two kinds of
payload in separate stores must move a key between them atomically, so that
concurrent `Put` and `PutSecret` calls on one key cannot interleave into a
state where both report success and the key holds nothing. `NewMemoryStorage`
keeps such payloads in enclaves rather than in its plain map, serializing every
operation on both keyspaces under one lock, and promotes a value written
through the plain `Put` path on the first `GetSecret` that reads it - moving it
into the protected keyspace with its remaining TTL rather than copying it out
and leaving the plaintext behind; `NewFileStorage` writes them to
disk straight out of the enclave (at-rest protection remains the file system's
job, with 0600 permissions).

### Best Practices

1. **Use unique key IDs**: Each participant should have a unique key ID within a group
2. **Secure storage location**: Store keys in a protected directory (e.g., `/var/lib/frost/keys`)
3. **Regular backups**: Back up the keystore directory securely
4. **Key rotation**: Update metadata to track key rotation and lifecycle
5. **Access control**: Restrict file system access to the keystore directory

## Testing

There is no keystore-specific make target. The keystore tests run with the unit suite:

```bash
make test
```

To run only this package: `go test -race ./pkg/frost/keystore/`. `make coverage` and `make bench` cover all packages.

## Storage Backends

`Config.Storage` is required (`NewKeychainStore` fails without it). The `StorageBackend` interface is defined in `pkg/frost/keystore/storage.go`:

- **`NewFileStorage(path)`**: one file per key under `path`, written atomically with the requested permissions
- **`NewMemoryStorage()`**: in-memory store for tests and ephemeral use
- **Your own**: DHT, cloud or HSM-backed stores implement the same interface, including `PutSecret`/`GetSecret`

## Error Handling

All errors are typed using the `KeystoreError` type:

```go
type KeystoreError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}
```

Common errors:
- `ErrNotFound`: Key package or group not found
- `ErrAlreadyExists`: Key package or group already exists
- `ErrInvalidKeyID`: Invalid or empty key ID
- `ErrInvalidGroupID`: Invalid or empty group ID
- `ErrInvalidKeyPackage`: Invalid or nil key package
- `ErrInvalidMetadata`: Nil metadata passed to `UpdateMetadata`
- `ErrMissingSecretShare`: Stored document carries no secret share
- `ErrPlaintextSerialization`: `encoding/json` used on a `StoredKeyPackage`
- `ErrStorageBackend`: Underlying storage operation failed

Check for specific errors:

```go
if keystore.IsNotFoundError(err) {
	// Handle not found
}

if keystore.IsAlreadyExistsError(err) {
	// Handle already exists
}
```

## Examples

See the package tests for complete workflows:
- `pkg/frost/keystore/keychain_store_test.go`

## References

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) - FROST specification
- [go-frost README](../../README.md) - Main project documentation
