# FROST Keystore Integration

The `keystore` package provides secure storage for FROST key material using the [go-keychain](https://github.com/jeremyhahn/go-keychain) library. This integration enables production-ready key management with proper security, access control, and lifecycle management.

## Overview

The keystore layer abstracts key storage operations and provides:

- **Secure Storage**: Key packages stored with proper file permissions (0600 for keys, 0644 for public data)
- **Thread-Safe Operations**: All operations are thread-safe using RWMutex
- **Serialization/Deserialization**: Automatic conversion between FROST types and storage format
- **Metadata Management**: Track key creation time, updates, group membership, and custom tags
- **Group Management**: Store and retrieve group public keys with threshold configuration
- **Flexible Storage**: Built on go-keychain's storage abstraction (file-based, with future support for cloud KMS, HSM, etc.)

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
│  - ...                                                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ implements
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                    KeychainStore                            │
│  - Uses go-keychain for storage backend                    │
│  - Handles serialization/deserialization                   │
│  - Manages metadata and lifecycle                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ uses
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              go-keychain Storage Backend                    │
│  - File-based storage with proper permissions              │
│  - Thread-safe operations                                  │
│  - Future: HSM, Cloud KMS support                          │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Example

```go
package main

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/keystore"
)

func main() {
	// Initialize ciphersuite
	cs := ristretto255_sha512.New()
	group := cs.Group()

	// Configure keystore
	config := &keystore.Config{
		Group:       group,
		StoragePath: "/var/lib/frost/keys",
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

	// Use key package for signing operations...
}
```

### Integration with FROST Service

```go
// Create FROST service using keystore
func createService(ks keystore.KeyStore, participantID frost.Identifier) (*service.FrostService, error) {
	// Retrieve key package from keystore
	keyID := fmt.Sprintf("participant-%d", participantID)
	keyPackage, _, err := ks.GetKeyPackage(keyID)
	if err != nil {
		return nil, err
	}

	// Create ciphersuite
	cs := ristretto255_sha512.New()

	// Create service config
	config := &service.FrostServiceConfig{
		Ciphersuite: cs,
		KeyPackage:  keyPackage,
	}

	return service.NewFrostService(config)
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
	Identifier         frost.Identifier
	SecretShare        []byte
	GroupPublicKey     []byte
	VerificationShares []StoredVerificationShare
	Metadata           KeyMetadata
}
```

Represents a key package in storage format with serialized cryptographic material.

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

The keystore uses strict file permissions:
- **Key packages**: 0600 (owner read/write only)
- **Group public keys**: 0644 (owner read/write, others read)
- **Directories**: 0700 (owner access only)

### Thread Safety

All keystore operations are thread-safe using `sync.RWMutex`:
- Read operations (Get, List, Exists) use `RLock()`
- Write operations (Store, Delete, Update) use `Lock()`

### Key Material Handling

- Secret shares are stored as serialized bytes
- No key material is logged or exposed in error messages
- Keys are sanitized to prevent path traversal attacks

### Best Practices

1. **Use unique key IDs**: Each participant should have a unique key ID within a group
2. **Secure storage location**: Store keys in a protected directory (e.g., `/var/lib/frost/keys`)
3. **Regular backups**: Back up the keystore directory securely
4. **Key rotation**: Update metadata to track key rotation and lifecycle
5. **Access control**: Restrict file system access to the keystore directory

## Testing

### Unit Tests

```bash
make test-keystore
```

### Coverage

```bash
make coverage-keystore
```

Current coverage: **73.0%**

### Benchmarks

```bash
make bench-keystore
```

## Integration with go-keychain

The keystore uses go-keychain's storage backend for:

- **File-based storage**: Production-ready file storage with proper permissions
- **Storage abstraction**: Clean interface for future backend implementations
- **Thread safety**: Built-in concurrency control
- **Error handling**: Consistent error types and handling

### Future Backend Support

The go-keychain library supports multiple backends, allowing future integration with:

- **HSMs**: PKCS#11, TPM2, SmartCard-HSM
- **Cloud KMS**: AWS KMS, GCP KMS, Azure Key Vault
- **Enterprise**: HashiCorp Vault

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

See the integration test for a complete workflow example:
- `/home/jhahn/sources/go-frost/test/integration/keystore_integration_test.go`

This example demonstrates:
1. Key generation with trusted dealer
2. Storing key packages in keychain
3. Retrieving keys for signing operations
4. Performing threshold signatures
5. Verifying signatures with stored group public key
6. Key deletion and lifecycle management

## References

- [go-keychain](https://github.com/jeremyhahn/go-keychain) - Secure key management library
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) - FROST specification
- [go-frost README](../README.md) - Main project documentation
