// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// FileStorage implements StorageBackend using file-based storage.
//
// This adapter wraps the go-keychain file storage backend to provide
// a compatible implementation of the StorageBackend interface.
//
// Thread-safe: Yes (provided by underlying go-keychain implementation)
type FileStorage struct {
	backend storage.Backend
}

// NewFileStorage creates a new file-based storage backend.
//
// Parameters:
//   - storagePath: Base directory for file storage
//
// Returns:
//   - StorageBackend: File storage implementation
//   - error: Any error that occurred during initialization
//
// Example:
//
//	storage, err := keystore.NewFileStorage("/var/lib/frost/keystore")
//	if err != nil {
//	    return err
//	}
//	defer storage.Close()
func NewFileStorage(storagePath string) (StorageBackend, error) {
	backend, err := file.New(storagePath)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	return &FileStorage{
		backend: backend,
	}, nil
}

// Put stores data at the given key with optional metadata/options.
func (f *FileStorage) Put(key string, data []byte, opts *PutOptions) error {
	if opts == nil {
		opts = DefaultPutOptions()
	}

	// Convert our PutOptions to go-keychain storage.Options
	storageOpts := storage.DefaultOptions()
	storageOpts.Permissions = os.FileMode(opts.Permissions)

	// Note: go-keychain file storage doesn't support Metadata or TTL
	// These fields are silently ignored for file-based storage

	if err := f.backend.Put(key, data, storageOpts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// Get retrieves data for the given key.
func (f *FileStorage) Get(key string) ([]byte, error) {
	data, err := f.backend.Get(key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, ErrStorageBackend.Wrap(err)
	}

	return data, nil
}

// Delete removes the data at the given key.
func (f *FileStorage) Delete(key string) error {
	if err := f.backend.Delete(key); err != nil {
		if err == storage.ErrNotFound {
			return ErrNotFound
		}
		return ErrStorageBackend.Wrap(err)
	}

	return nil
}

// Exists checks if a key exists in storage.
func (f *FileStorage) Exists(key string) (bool, error) {
	exists, err := f.backend.Exists(key)
	if err != nil {
		return false, ErrStorageBackend.Wrap(err)
	}

	return exists, nil
}

// List returns all keys matching the given prefix.
func (f *FileStorage) List(prefix string) ([]string, error) {
	keys, err := f.backend.List(prefix)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	return keys, nil
}

// Close releases any resources held by the storage backend.
func (f *FileStorage) Close() error {
	if f.backend != nil {
		return f.backend.Close()
	}
	return nil
}
