package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// KeyStore defines the interface for secure storage of FROST key material.
//
// All implementations must be thread-safe and provide secure storage for:
//   - Key packages (participant secret shares and verification keys)
//   - Group public keys
//   - Key metadata
//
// The keystore abstracts the underlying storage mechanism, allowing for
// different implementations (file-based, hardware-backed, cloud KMS, etc.).
type KeyStore interface {
	// StoreKeyPackage stores a key package with the given key ID and group ID.
	// Returns ErrAlreadyExists if a key package with the same key ID already exists.
	StoreKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32) error

	// GetKeyPackage retrieves a key package by key ID.
	// Returns ErrNotFound if the key package does not exist.
	GetKeyPackage(keyID string) (*frost.KeyPackage, *KeyMetadata, error)

	// DeleteKeyPackage removes a key package by key ID.
	// Returns ErrNotFound if the key package does not exist.
	DeleteKeyPackage(keyID string) error

	// ListKeyPackages returns metadata for all stored key packages.
	// If groupID is non-empty, only key packages for that group are returned.
	ListKeyPackages(groupID string) ([]*KeyMetadata, error)

	// KeyPackageExists checks if a key package exists.
	KeyPackageExists(keyID string) (bool, error)

	// StoreGroupPublicKey stores the group public key for a signing group.
	// Returns ErrAlreadyExists if a group public key already exists for this group ID.
	StoreGroupPublicKey(groupID string, publicKey group.Element, minSigners, maxSigners uint32) error

	// GetGroupPublicKey retrieves the group public key for a signing group.
	// Returns ErrNotFound if the group public key does not exist.
	GetGroupPublicKey(groupID string) (group.Element, error)

	// DeleteGroupPublicKey removes the group public key for a signing group.
	// Returns ErrNotFound if the group public key does not exist.
	DeleteGroupPublicKey(groupID string) error

	// ListGroups returns metadata for all stored signing groups.
	ListGroups() ([]*GroupPublicKeyEntry, error)

	// GroupExists checks if a group public key exists.
	GroupExists(groupID string) (bool, error)

	// UpdateMetadata updates the metadata for a key package.
	// Returns ErrNotFound if the key package does not exist.
	UpdateMetadata(keyID string, metadata *KeyMetadata) error

	// Close releases any resources held by the keystore.
	Close() error
}

// Config provides configuration for creating a KeyStore instance.
type Config struct {
	// Group is the prime-order group implementation used for key operations.
	// Required for serialization/deserialization of key material.
	Group group.Group

	// Storage is the storage backend implementation.
	// REQUIRED: Applications must provide their own storage implementation
	// (file-based, DHT, cloud storage, etc.) that implements the StorageBackend interface.
	//
	// For file-based storage, use NewFileStorage().
	// For DHT storage, provide your own DHT-backed implementation.
	// For cloud storage, provide your own cloud-backed implementation.
	Storage StorageBackend

	// Tags are optional key-value pairs for organizing keys.
	Tags map[string]string
}
