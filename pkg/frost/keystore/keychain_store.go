package keystore

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// Storage key prefixes
	keyPackagePrefix = "frost/keypackages/"
	groupKeyPrefix   = "frost/groups/"

	// Storage key suffixes
	keyPackageSuffix = ".json"
	groupKeySuffix   = ".json"
)

// KeychainStore implements KeyStore using a pluggable storage backend.
//
// The storage backend is injected via the Config struct, allowing applications
// to provide their own implementations (file-based, DHT, cloud storage, etc.).
//
// Storage layout:
//
//	frost/keypackages/<keyID>.json       - Key package data
//	frost/groups/<groupID>.json          - Group public key data
type KeychainStore struct {
	storage StorageBackend
	group   group.Group
	config  *Config
}

// NewKeychainStore creates a new KeychainStore instance.
//
// The storage backend must be provided via config.Storage. Applications can use:
//   - NewFileStorage() for file-based storage
//   - Their own DHT implementation for distributed storage
//   - Their own cloud storage implementation
//
// Example (file-based):
//
//	storage, err := keystore.NewFileStorage("/var/lib/frost/keystore")
//	if err != nil {
//	    return nil, err
//	}
//	config := &keystore.Config{
//	    Group:   suite.Group(),
//	    Storage: storage,
//	}
//	store, err := keystore.NewKeychainStore(config)
//
// Example (DHT-based):
//
//	dhtStorage := mydht.NewDHTStorage(dhtNode)
//	config := &keystore.Config{
//	    Group:   suite.Group(),
//	    Storage: dhtStorage,
//	}
//	store, err := keystore.NewKeychainStore(config)
func NewKeychainStore(config *Config) (KeyStore, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if config.Group == nil {
		return nil, fmt.Errorf("group is required")
	}
	if config.Storage == nil {
		return nil, fmt.Errorf("storage backend is required")
	}

	return &KeychainStore{
		storage: config.Storage,
		group:   config.Group,
		config:  config,
	}, nil
}

// StoreKeyPackage stores a key package with the given key ID and group ID.
func (k *KeychainStore) StoreKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if groupID == "" {
		return ErrInvalidGroupID
	}
	if kp == nil {
		return ErrInvalidKeyPackage
	}

	// Check if key package already exists
	storageKey := k.keyPackageStorageKey(keyID)
	exists, err := k.storage.Exists(storageKey)
	if err != nil {
		return ErrStorageBackend.Wrap(err)
	}
	if exists {
		return ErrAlreadyExists
	}

	// Convert to stored format
	createdAt := time.Now().Unix()
	storedKP, err := FromKeyPackage(keyID, groupID, kp, minSigners, maxSigners, createdAt)
	if err != nil {
		return err
	}

	// Apply tags from config
	if k.config.Tags != nil {
		for key, value := range k.config.Tags {
			storedKP.Metadata.Tags[key] = value
		}
	}

	// Marshal to JSON
	data, err := json.Marshal(storedKP)
	if err != nil {
		return ErrMarshalJSON.Wrap(err)
	}

	// Store using the pluggable storage backend
	opts := DefaultPutOptions()
	opts.Permissions = 0600 // Owner read/write only
	if err := k.storage.Put(storageKey, data, opts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// GetKeyPackage retrieves a key package by key ID.
func (k *KeychainStore) GetKeyPackage(keyID string) (*frost.KeyPackage, *KeyMetadata, error) {
	if keyID == "" {
		return nil, nil, ErrInvalidKeyID
	}

	// Retrieve from storage
	storageKey := k.keyPackageStorageKey(keyID)
	data, err := k.storage.Get(storageKey)
	if err != nil {
		if err == ErrNotFound {
			return nil, nil, ErrNotFound
		}
		return nil, nil, ErrStorageBackend.Wrap(err)
	}

	// Unmarshal from JSON
	var storedKP StoredKeyPackage
	if err := json.Unmarshal(data, &storedKP); err != nil {
		return nil, nil, ErrUnmarshalJSON.Wrap(err)
	}

	// Convert back to KeyPackage
	kp, err := storedKP.ToKeyPackage(k.group)
	if err != nil {
		return nil, nil, err
	}

	return kp, &storedKP.Metadata, nil
}

// DeleteKeyPackage removes a key package by key ID.
func (k *KeychainStore) DeleteKeyPackage(keyID string) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}

	storageKey := k.keyPackageStorageKey(keyID)
	if err := k.storage.Delete(storageKey); err != nil {
		if err == ErrNotFound {
			return ErrNotFound
		}
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// ListKeyPackages returns metadata for all stored key packages.
func (k *KeychainStore) ListKeyPackages(groupID string) ([]*KeyMetadata, error) {
	// List all key packages
	keys, err := k.storage.List(keyPackagePrefix)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	metadata := make([]*KeyMetadata, 0, len(keys))
	for _, key := range keys {
		// Get the key package data
		data, err := k.storage.Get(key)
		if err != nil {
			continue // Skip keys that can't be read
		}

		// Unmarshal to get metadata
		var storedKP StoredKeyPackage
		if err := json.Unmarshal(data, &storedKP); err != nil {
			continue // Skip keys that can't be unmarshaled
		}

		// Filter by group ID if specified
		if groupID != "" && storedKP.Metadata.GroupID != groupID {
			continue
		}

		metadata = append(metadata, &storedKP.Metadata)
	}

	return metadata, nil
}

// KeyPackageExists checks if a key package exists.
func (k *KeychainStore) KeyPackageExists(keyID string) (bool, error) {
	if keyID == "" {
		return false, ErrInvalidKeyID
	}

	storageKey := k.keyPackageStorageKey(keyID)
	exists, err := k.storage.Exists(storageKey)
	if err != nil {
		return false, ErrStorageBackend.Wrap(err)
	}

	return exists, nil
}

// StoreGroupPublicKey stores the group public key for a signing group.
func (k *KeychainStore) StoreGroupPublicKey(groupID string, publicKey group.Element, minSigners, maxSigners uint32) error {
	if groupID == "" {
		return ErrInvalidGroupID
	}
	if publicKey == nil {
		return fmt.Errorf("public key is required")
	}

	// Check if group already exists
	storageKey := k.groupKeyStorageKey(groupID)
	exists, err := k.storage.Exists(storageKey)
	if err != nil {
		return ErrStorageBackend.Wrap(err)
	}
	if exists {
		return ErrAlreadyExists
	}

	// Serialize public key
	publicKeyBytes := publicKey.Bytes()

	// Create group entry
	entry := &GroupPublicKeyEntry{
		GroupID:    groupID,
		PublicKey:  publicKeyBytes,
		MinSigners: minSigners,
		MaxSigners: maxSigners,
		CreatedAt:  time.Now().Unix(),
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return ErrMarshalJSON.Wrap(err)
	}

	// Store using the pluggable storage backend
	opts := DefaultPutOptions()
	opts.Permissions = 0644 // Owner read/write, others read
	if err := k.storage.Put(storageKey, data, opts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// GetGroupPublicKey retrieves the group public key for a signing group.
func (k *KeychainStore) GetGroupPublicKey(groupID string) (group.Element, error) {
	if groupID == "" {
		return nil, ErrInvalidGroupID
	}

	// Retrieve from storage
	storageKey := k.groupKeyStorageKey(groupID)
	data, err := k.storage.Get(storageKey)
	if err != nil {
		if err == ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, ErrStorageBackend.Wrap(err)
	}

	// Unmarshal from JSON
	var entry GroupPublicKeyEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, ErrUnmarshalJSON.Wrap(err)
	}

	// Deserialize public key
	publicKey, err := k.group.DeserializeElement(entry.PublicKey)
	if err != nil {
		return nil, ErrDeserializeElement.Wrap(err)
	}

	return publicKey, nil
}

// DeleteGroupPublicKey removes the group public key for a signing group.
func (k *KeychainStore) DeleteGroupPublicKey(groupID string) error {
	if groupID == "" {
		return ErrInvalidGroupID
	}

	storageKey := k.groupKeyStorageKey(groupID)
	if err := k.storage.Delete(storageKey); err != nil {
		if err == ErrNotFound {
			return ErrNotFound
		}
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// ListGroups returns metadata for all stored signing groups.
func (k *KeychainStore) ListGroups() ([]*GroupPublicKeyEntry, error) {
	// List all groups
	keys, err := k.storage.List(groupKeyPrefix)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	entries := make([]*GroupPublicKeyEntry, 0, len(keys))
	for _, key := range keys {
		// Get the group data
		data, err := k.storage.Get(key)
		if err != nil {
			continue // Skip keys that can't be read
		}

		// Unmarshal
		var entry GroupPublicKeyEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue // Skip keys that can't be unmarshaled
		}

		entries = append(entries, &entry)
	}

	return entries, nil
}

// GroupExists checks if a group public key exists.
func (k *KeychainStore) GroupExists(groupID string) (bool, error) {
	if groupID == "" {
		return false, ErrInvalidGroupID
	}

	storageKey := k.groupKeyStorageKey(groupID)
	exists, err := k.storage.Exists(storageKey)
	if err != nil {
		return false, ErrStorageBackend.Wrap(err)
	}

	return exists, nil
}

// UpdateMetadata updates the metadata for a key package.
func (k *KeychainStore) UpdateMetadata(keyID string, metadata *KeyMetadata) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}
	if metadata == nil {
		return ErrInvalidMetadata
	}

	// Retrieve existing key package
	storageKey := k.keyPackageStorageKey(keyID)
	data, err := k.storage.Get(storageKey)
	if err != nil {
		if err == ErrNotFound {
			return ErrNotFound
		}
		return ErrStorageBackend.Wrap(err)
	}

	// Unmarshal
	var storedKP StoredKeyPackage
	if err := json.Unmarshal(data, &storedKP); err != nil {
		return ErrUnmarshalJSON.Wrap(err)
	}

	// Update metadata
	metadata.UpdatedAt = time.Now().Unix()
	storedKP.Metadata = *metadata

	// Marshal back to JSON
	data, err = json.Marshal(storedKP)
	if err != nil {
		return ErrMarshalJSON.Wrap(err)
	}

	// Store updated key package
	opts := DefaultPutOptions()
	opts.Permissions = 0600
	if err := k.storage.Put(storageKey, data, opts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// Close releases any resources held by the keystore.
func (k *KeychainStore) Close() error {
	if k.storage != nil {
		return k.storage.Close()
	}
	return nil
}

// keyPackageStorageKey returns the storage key for a key package.
func (k *KeychainStore) keyPackageStorageKey(keyID string) string {
	// Sanitize keyID to prevent path traversal
	keyID = strings.ReplaceAll(keyID, "/", "_")
	keyID = strings.ReplaceAll(keyID, "..", "_")
	return keyPackagePrefix + keyID + keyPackageSuffix
}

// groupKeyStorageKey returns the storage key for a group public key.
func (k *KeychainStore) groupKeyStorageKey(groupID string) string {
	// Sanitize groupID to prevent path traversal
	groupID = strings.ReplaceAll(groupID, "/", "_")
	groupID = strings.ReplaceAll(groupID, "..", "_")
	return groupKeyPrefix + groupID + groupKeySuffix
}
