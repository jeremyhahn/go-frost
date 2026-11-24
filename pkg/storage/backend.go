// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package storage provides go-frost storage backends compatible with the go-xkms and go-objstore interfaces.
package storage

// Backend is a thread-safe storage interface compatible with go-xkms storage.Backend and go-objstore Get/Put/Delete.
type Backend interface {
	// Put stores data at key, overwriting any existing value.
	Put(key string, data []byte, opts *Options) error

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
}

// Options provides options for storage operations.
//
// Compatible with go-xkms's storage.Options.
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
// Compatible with go-xkms's storage.DefaultOptions().
func DefaultOptions() *Options {
	return &Options{
		Permissions: 0600, // Owner read/write only (secure default)
		Metadata:    make(map[string]string),
		TTL:         0, // No expiration
	}
}
