// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// StorageBackend is a thread-safe pluggable store: Put/Get for public material, PutSecret/GetSecret for secrets, which are never held as plain []byte.
type StorageBackend interface {
	// Put stores data at key, overwriting any existing value.
	Put(key string, data []byte, opts *PutOptions) error

	// Get returns the data at key, or ErrNotFound.
	Get(key string) ([]byte, error)

	// Delete removes the data at key, or returns ErrNotFound.
	Delete(key string) error

	// Exists reports whether key exists.
	Exists(key string) (bool, error)

	// List returns the keys with the given prefix.
	List(prefix string) ([]string, error)

	// Close releases the backend's resources.
	Close() error

	// PutSecret stores protected data at key, keeping an independent copy and zeroizing any plaintext before returning.
	PutSecret(key string, data *secmem.SecretBytes, opts *PutOptions) error

	// GetSecret returns key's data in protected memory, which the caller destroys; it may migrate a plain value into protected memory.
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
