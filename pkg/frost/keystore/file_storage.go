// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/jeremyhahn/go-frost/pkg/storage"
)

// FileStorage implements StorageBackend using file-based storage.
//
// This adapter wraps the go-frost storage backend to provide
// a compatible implementation of the StorageBackend interface.
//
// Thread-safe: Yes (provided by underlying storage implementation)
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
	backend, err := storage.NewFileBackend(storagePath)
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

	// Convert our PutOptions to storage.Options
	storageOpts := storage.DefaultOptions()
	storageOpts.Permissions = opts.Permissions
	storageOpts.Metadata = opts.Metadata
	storageOpts.TTL = opts.TTL

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

// PutSecret stores secret-bearing data at the given key.
//
// The payload is written to disk straight out of the enclave: the plaintext
// only ever exists inside the mlock'd buffer opened for the write, and the
// buffer is resealed before this function returns. Note that the file itself
// holds the payload in the clear - at-rest protection is the responsibility
// of the filesystem (the default 0600 permissions apply).
func (f *FileStorage) PutSecret(key string, data *secmem.SecretBytes, opts *PutOptions) error {
	if data == nil {
		return ErrProtectedMemory.Wrap(secmem.ErrNilSecret)
	}

	if opts == nil {
		opts = DefaultPutOptions()
	}

	// Convert our PutOptions to storage.Options
	storageOpts := storage.DefaultOptions()
	storageOpts.Permissions = opts.Permissions
	storageOpts.Metadata = opts.Metadata
	storageOpts.TTL = opts.TTL

	var putErr error
	if err := secmem.WithSecret(data, func(b []byte) error {
		putErr = f.backend.Put(key, b, storageOpts)
		return nil
	}); err != nil {
		return ErrProtectedMemory.Wrap(err)
	}
	if putErr != nil {
		return ErrStorageBackend.Wrap(putErr)
	}

	return nil
}

// GetSecret retrieves secret-bearing data for the given key, returning it in
// protected memory. The plaintext read from disk is sealed into an enclave
// and zeroized in place immediately.
func (f *FileStorage) GetSecret(key string) (*secmem.SecretBytes, error) {
	data, err := f.backend.Get(key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, ErrStorageBackend.Wrap(err)
	}

	// NewSecretBytes zeroizes data in place as it seals it.
	secret := secmem.NewSecretBytes(data)
	if secret == nil {
		return nil, ErrProtectedMemory.Wrap(errEmptyPayload)
	}

	return secret, nil
}

// Close releases any resources held by the storage backend.
func (f *FileStorage) Close() error {
	if f.backend != nil {
		return f.backend.Close()
	}
	return nil
}
