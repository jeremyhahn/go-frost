// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package storage provides storage backend implementations compatible with
// go-keychain and go-objstore interfaces.
//
// This package allows go-frost to have its own storage implementations while
// maintaining interface compatibility with external storage providers like
// go-keychain and go-objstore.
package storage

// Backend defines the storage interface compatible with go-keychain and go-objstore.
//
// All implementations MUST be thread-safe.
//
// Interface compatibility:
//   - go-keychain: github.com/jeremyhahn/go-keychain/pkg/storage.Backend
//   - go-objstore: Compatible with Get/Put/Delete operations
//
// This interface can be implemented by:
//   - Memory-based storage (for testing)
//   - File system storage (for local persistence)
//   - Cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
//   - Hardware Security Modules (HSM)
//   - Trusted Platform Modules (TPM)
//   - Distributed Hash Tables (DHT)
type Backend interface {
	// Put stores data at the given key with optional metadata/options.
	// If the key already exists, it should be overwritten.
	//
	// Parameters:
	//   - key: Storage key (e.g., "frost/keypackages/key-123.json")
	//   - data: Binary data to store
	//   - opts: Optional storage options (permissions, metadata, etc.)
	//
	// Returns:
	//   - error: Any error that occurred during storage
	Put(key string, data []byte, opts *Options) error

	// Get retrieves data for the given key.
	//
	// Parameters:
	//   - key: Storage key to retrieve
	//
	// Returns:
	//   - []byte: The stored data
	//   - error: ErrNotFound if key doesn't exist, or other storage errors
	Get(key string) ([]byte, error)

	// Delete removes the data at the given key.
	//
	// Parameters:
	//   - key: Storage key to delete
	//
	// Returns:
	//   - error: ErrNotFound if key doesn't exist, or other storage errors
	Delete(key string) error

	// Exists checks if a key exists in storage.
	//
	// Parameters:
	//   - key: Storage key to check
	//
	// Returns:
	//   - bool: true if the key exists, false otherwise
	//   - error: Any error that occurred during the check
	Exists(key string) (bool, error)

	// List returns all keys matching the given prefix.
	//
	// Parameters:
	//   - prefix: Key prefix to match (e.g., "frost/keypackages/")
	//
	// Returns:
	//   - []string: List of matching keys
	//   - error: Any error that occurred during listing
	List(prefix string) ([]string, error)

	// Close releases any resources held by the storage backend.
	//
	// Returns:
	//   - error: Any error that occurred during cleanup
	Close() error
}

// Options provides options for storage operations.
//
// Compatible with go-keychain's storage.Options.
type Options struct {
	// Permissions specifies the file permissions (for file-based storage).
	// This field may be ignored by non-file-based storage backends.
	// Example: 0600 for owner read/write only
	Permissions uint32

	// Metadata provides optional key-value metadata for the stored object.
	// Support for this field depends on the storage backend implementation.
	Metadata map[string]string

	// TTL specifies the time-to-live for the stored object in seconds.
	// A value of 0 means no expiration.
	// Support for this field depends on the storage backend implementation.
	TTL int64
}

// DefaultOptions returns default storage options.
//
// Compatible with go-keychain's storage.DefaultOptions().
func DefaultOptions() *Options {
	return &Options{
		Permissions: 0600, // Owner read/write only (secure default)
		Metadata:    make(map[string]string),
		TTL:         0, // No expiration
	}
}
