// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// StorageBackend defines the interface for pluggable storage implementations.
//
// The Put/Get pair is compatible with go-objstore's Get/Put/Delete operations
// and carries public material (group public keys). Secret-bearing payloads -
// serialized key packages - go through the PutSecret/GetSecret pair instead,
// so that a serialized secret share is never held or returned as a plain
// []byte. Implementations that wrap a []byte-oriented backend must keep any
// transient plaintext as short-lived as possible and zeroize it before
// returning.
//
// All implementations MUST be thread-safe.
type StorageBackend interface {
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
	Put(key string, data []byte, opts *PutOptions) error

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

	// PutSecret stores secret-bearing data at the given key.
	// If the key already exists, it is overwritten.
	//
	// The payload is supplied in protected memory. Implementations MUST NOT
	// retain it as a plain []byte: any plaintext needed to reach the
	// underlying medium must be zeroized before returning. The caller retains
	// ownership of data, so implementations that keep the payload in memory
	// must store an independent copy (see secmem.Clone).
	//
	// Parameters:
	//   - key: Storage key (e.g., "frost/keypackages/key-123.json")
	//   - data: Secret data held in protected memory
	//   - opts: Optional storage options (permissions, metadata, etc.)
	//
	// Returns:
	//   - error: Any error that occurred during storage
	PutSecret(key string, data *secmem.SecretBytes, opts *PutOptions) error

	// GetSecret retrieves secret-bearing data for the given key, returning it
	// in protected memory.
	//
	// The caller owns the returned SecretBytes and is responsible for
	// destroying it once it is no longer needed.
	//
	// GetSecret is not necessarily a pure read. An implementation that can
	// hold a value either in the clear or in protected memory MAY migrate it
	// on the way out - moving a value written through the plain Put path into
	// protected memory, and leaving no plaintext behind - so that a key
	// package written by an older revision does not stay resident in the
	// clear. NewMemoryStorage does exactly this. Callers must not assume the
	// backend is unchanged by a GetSecret.
	//
	// Parameters:
	//   - key: Storage key to retrieve
	//
	// Returns:
	//   - *secmem.SecretBytes: The stored data, sealed in protected memory
	//   - error: ErrNotFound if key doesn't exist, or other storage errors
	GetSecret(key string) (*secmem.SecretBytes, error)
}

// PutOptions provides options for storage operations.
type PutOptions struct {
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

// DefaultPutOptions returns default storage options.
func DefaultPutOptions() *PutOptions {
	return &PutOptions{
		Permissions: 0600, // Owner read/write only (secure default)
		Metadata:    make(map[string]string),
		TTL:         0, // No expiration
	}
}
