// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileBackend implements Backend using file system storage.
//
// This implementation is thread-safe and suitable for:
//   - Local persistence
//   - Production deployments
//   - Secure key material storage
//
// Files are stored with configurable permissions for security.
// The storage directory structure mirrors the key hierarchy.
//
// Example directory structure:
//
//	/var/lib/frost/
//	  frost/
//	    keypackages/
//	      key-123.json
//	      key-456.json
//	    groups/
//	      group-abc.json
type FileBackend struct {
	mu       sync.RWMutex
	basePath string
	closed   bool
}

// NewFileBackend creates a new file-based storage backend.
//
// Parameters:
//   - basePath: Base directory for file storage
//
// Returns:
//   - Backend: File storage implementation
//   - error: Any error that occurred during initialization
//
// Example:
//
//	storage, err := storage.NewFileBackend("/var/lib/frost/keystore")
//	if err != nil {
//	    return err
//	}
//	defer storage.Close()
func NewFileBackend(basePath string) (Backend, error) {
	if basePath == "" {
		return nil, fmt.Errorf("storage: base path cannot be empty")
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("storage: failed to create base directory: %w", err)
	}

	return &FileBackend{
		basePath: basePath,
	}, nil
}

// Put stores data at the given key with optional metadata/options.
func (f *FileBackend) Put(key string, data []byte, opts *Options) error {
	if key == "" {
		return ErrInvalidKey
	}

	// Validate key doesn't contain path traversal attempts
	if strings.Contains(key, "..") {
		return ErrInvalidKey
	}

	if opts == nil {
		opts = DefaultOptions()
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return ErrStorageClosed
	}

	// Construct full file path
	fullPath := filepath.Join(f.basePath, key)

	// Create parent directories if they don't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("storage: failed to create directory: %w", err)
	}

	// Write data to temporary file first (atomic write)
	tmpPath := fullPath + ".tmp"
	perm := os.FileMode(opts.Permissions)
	if perm == 0 {
		perm = 0600 // Default to secure permissions
	}

	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("storage: failed to write file: %w", err)
	}

	// Atomically rename to final location
	if err := os.Rename(tmpPath, fullPath); err != nil {
		// Clean up temporary file on error
		_ = os.Remove(tmpPath)
		return fmt.Errorf("storage: failed to rename file: %w", err)
	}

	// Note: Metadata and TTL are not supported for file-based storage
	// These fields are silently ignored

	return nil
}

// Get retrieves data for the given key.
func (f *FileBackend) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}

	// Validate key doesn't contain path traversal attempts
	if strings.Contains(key, "..") {
		return nil, ErrInvalidKey
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.closed {
		return nil, ErrStorageClosed
	}

	fullPath := filepath.Join(f.basePath, key)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, fmt.Errorf("storage: failed to read file: %w", err)
	}

	return data, nil
}

// Delete removes the data at the given key.
func (f *FileBackend) Delete(key string) error {
	if key == "" {
		return ErrInvalidKey
	}

	// Validate key doesn't contain path traversal attempts
	if strings.Contains(key, "..") {
		return ErrInvalidKey
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return ErrStorageClosed
	}

	fullPath := filepath.Join(f.basePath, key)

	err := os.Remove(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		if os.IsPermission(err) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("storage: failed to delete file: %w", err)
	}

	// Attempt to clean up empty parent directories (best effort)
	f.cleanEmptyDirs(filepath.Dir(fullPath))

	return nil
}

// Exists checks if a key exists in storage.
func (f *FileBackend) Exists(key string) (bool, error) {
	if key == "" {
		return false, ErrInvalidKey
	}

	// Validate key doesn't contain path traversal attempts
	if strings.Contains(key, "..") {
		return false, ErrInvalidKey
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.closed {
		return false, ErrStorageClosed
	}

	fullPath := filepath.Join(f.basePath, key)

	_, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("storage: failed to stat file: %w", err)
	}

	return true, nil
}

// List returns all keys matching the given prefix.
func (f *FileBackend) List(prefix string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.closed {
		return nil, ErrStorageClosed
	}

	var keys []string

	// Always walk from base path to handle both file and directory prefixes
	// Walk the directory tree
	err := filepath.Walk(f.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// If it's the base path itself that has an error, propagate it
			if path == f.basePath {
				return err
			}
			// Skip subdirectories we can't access
			if os.IsPermission(err) {
				return filepath.SkipDir
			}
			return err
		}

		// Skip directories, only process files
		if info.IsDir() {
			return nil
		}

		// Convert absolute path to relative key
		relPath, err := filepath.Rel(f.basePath, path)
		if err != nil {
			return err
		}

		// Normalize path separators to forward slashes (cross-platform)
		relPath = filepath.ToSlash(relPath)

		// Skip temporary files
		if strings.HasSuffix(relPath, ".tmp") {
			return nil
		}

		// Add to results if it matches prefix
		if prefix == "" || strings.HasPrefix(relPath, prefix) {
			keys = append(keys, relPath)
		}

		return nil
	})

	if err != nil {
		// If the base path doesn't exist, return empty list
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("storage: failed to list keys: %w", err)
	}

	return keys, nil
}

// Close releases any resources held by the storage backend.
//
// For file backend, this just marks it as closed. The files remain on disk.
func (f *FileBackend) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}

	f.closed = true
	return nil
}

// cleanEmptyDirs removes empty parent directories up to the base path.
// This is a best-effort operation and errors are ignored.
func (f *FileBackend) cleanEmptyDirs(dir string) {
	// Don't clean the base directory itself
	if dir == f.basePath {
		return
	}

	// Don't clean directories outside base path
	if !strings.HasPrefix(dir, f.basePath) {
		return
	}

	// Try to remove the directory (will fail if not empty)
	err := os.Remove(dir)
	if err != nil {
		// Stop if directory is not empty or other errors
		return
	}

	// Recursively clean parent directories
	f.cleanEmptyDirs(filepath.Dir(dir))
}
