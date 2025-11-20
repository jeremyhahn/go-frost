// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package storage provides storage backend implementations compatible with
// go-keychain and go-objstore interfaces.
//
// # Overview
//
// This package allows go-frost to have its own storage implementations while
// maintaining interface compatibility with external storage providers like
// go-keychain (github.com/jeremyhahn/go-keychain) and go-objstore.
//
// # Interface Compatibility
//
// The Backend interface is designed to be compatible with:
//   - go-keychain: github.com/jeremyhahn/go-keychain/pkg/storage.Backend
//   - go-objstore: Compatible with Get/Put/Delete operations
//
// This means you can:
//  1. Use go-frost's built-in storage implementations (Memory, File)
//  2. Pass a go-keychain Backend to go-frost
//  3. Pass a go-objstore implementation to go-frost
//  4. Implement your own custom Backend (HSM, TPM, cloud KMS, etc.)
//
// # Provided Implementations
//
// Memory Backend (NewMemoryBackend):
//   - In-memory storage using a synchronized map
//   - Suitable for testing and development
//   - Supports TTL (time-to-live) for automatic expiration
//   - All data is lost when process terminates
//
// File Backend (NewFileBackend):
//   - File system storage with configurable permissions
//   - Suitable for production deployments
//   - Atomic writes via temporary files
//   - Automatic directory structure management
//   - Secure file permissions (default 0600)
//
// # Usage Examples
//
// Using Memory Backend:
//
//	import "github.com/jeremyhahn/go-frost/pkg/storage"
//
//	// Create memory backend for testing
//	backend := storage.NewMemoryBackend()
//	defer backend.Close()
//
//	// Store data
//	opts := storage.DefaultOptions()
//	opts.TTL = 3600 // 1 hour expiration
//	err := backend.Put("frost/keypackages/key1.json", data, opts)
//
// Using File Backend:
//
//	// Create file backend for production
//	backend, err := storage.NewFileBackend("/var/lib/frost/keystore")
//	if err != nil {
//	    return err
//	}
//	defer backend.Close()
//
//	// Store data with custom permissions
//	opts := storage.DefaultOptions()
//	opts.Permissions = 0600 // Owner read/write only
//	err = backend.Put("frost/keypackages/key1.json", data, opts)
//
// Using with go-frost keystore:
//
//	import (
//	    "github.com/jeremyhahn/go-frost/pkg/frost/keystore"
//	    "github.com/jeremyhahn/go-frost/pkg/storage"
//	)
//
//	// Create storage backend
//	backend, err := storage.NewFileBackend("/var/lib/frost")
//	if err != nil {
//	    return err
//	}
//
//	// Create keystore with custom backend
//	store := keystore.NewKeychainStore(backend, groupCfg)
//
// Using external go-keychain backend:
//
//	import (
//	    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
//	    "github.com/jeremyhahn/go-frost/pkg/frost/keystore"
//	)
//
//	// Use go-keychain's file backend
//	backend, err := file.New("/var/lib/frost")
//	if err != nil {
//	    return err
//	}
//
//	// Pass to go-frost (interface compatible)
//	store := keystore.NewKeychainStore(backend, groupCfg)
//
// # Thread Safety
//
// All Backend implementations MUST be thread-safe. The provided Memory and
// File backends use sync.RWMutex for synchronization.
//
// # Security Considerations
//
// File Backend:
//   - Default file permissions are 0600 (owner read/write only)
//   - Parent directories are created with 0700 permissions
//   - Atomic writes prevent partial data corruption
//   - Path traversal attacks are prevented (.. in keys rejected)
//
// Memory Backend:
//   - Data is not encrypted in memory
//   - Suitable for testing but not for production secrets
//   - Consider using encrypted swap for sensitive data
//
// For production use with sensitive key material, consider:
//   - Using encrypted file systems
//   - Hardware Security Modules (HSM)
//   - Trusted Platform Modules (TPM)
//   - Cloud Key Management Systems (KMS)
//
// # Implementing Custom Backends
//
// To implement a custom backend, implement the Backend interface:
//
//	type MyBackend struct {
//	    // your fields
//	}
//
//	func (m *MyBackend) Put(key string, data []byte, opts *storage.Options) error {
//	    // your implementation
//	}
//
//	func (m *MyBackend) Get(key string) ([]byte, error) {
//	    // your implementation
//	}
//
//	// ... implement other methods
//
// Your implementation should:
//   - Be thread-safe
//   - Return storage.ErrNotFound when keys don't exist
//   - Handle Options.Permissions for file-based storage
//   - Support (or ignore) Options.Metadata and Options.TTL as appropriate
//   - Clean up resources in Close()
package storage
