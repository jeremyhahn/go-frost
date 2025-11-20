// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/storage"
)

// MemoryStorage implements StorageBackend using in-memory storage.
//
// This adapter wraps the go-frost memory storage backend to provide
// a compatible implementation of the StorageBackend interface.
//
// Thread-safe: Yes (provided by underlying storage implementation)
//
// WARNING: All data is lost when the process terminates.
// This implementation is suitable for:
//   - Testing
//   - Development
//   - Temporary storage
//   - Caching layer
type MemoryStorage struct {
	backend storage.Backend
}

// NewMemoryStorage creates a new in-memory storage backend.
//
// Returns:
//   - StorageBackend: Memory storage implementation
//
// Example:
//
//	storage := keystore.NewMemoryStorage()
//	defer storage.Close()
func NewMemoryStorage() StorageBackend {
	backend := storage.NewMemoryBackend()

	return &MemoryStorage{
		backend: backend,
	}
}

// Put stores data at the given key with optional metadata/options.
func (m *MemoryStorage) Put(key string, data []byte, opts *PutOptions) error {
	if opts == nil {
		opts = DefaultPutOptions()
	}

	// Convert our PutOptions to storage.Options
	storageOpts := storage.DefaultOptions()
	storageOpts.Permissions = opts.Permissions
	storageOpts.Metadata = opts.Metadata
	storageOpts.TTL = opts.TTL

	if err := m.backend.Put(key, data, storageOpts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// Get retrieves data for the given key.
func (m *MemoryStorage) Get(key string) ([]byte, error) {
	data, err := m.backend.Get(key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, ErrStorageBackend.Wrap(err)
	}

	return data, nil
}

// Delete removes the data at the given key.
func (m *MemoryStorage) Delete(key string) error {
	if err := m.backend.Delete(key); err != nil {
		if err == storage.ErrNotFound {
			return ErrNotFound
		}
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// Exists checks if a key exists in storage.
func (m *MemoryStorage) Exists(key string) (bool, error) {
	exists, err := m.backend.Exists(key)
	if err != nil {
		return false, ErrStorageBackend.Wrap(err)
	}

	return exists, nil
}

// List returns all keys matching the given prefix.
func (m *MemoryStorage) List(prefix string) ([]string, error) {
	keys, err := m.backend.List(prefix)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	return keys, nil
}

// Close releases any resources held by the storage backend.
func (m *MemoryStorage) Close() error {
	if m.backend != nil {
		return m.backend.Close()
	}
	return nil
}
