// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package storage

import (
	"strings"
	"sync"
	"time"
)

// memoryEntry represents a stored item with metadata and expiration.
type memoryEntry struct {
	data       []byte
	metadata   map[string]string
	expiration time.Time // Zero value means no expiration
}

// MemoryBackend implements Backend using an in-memory map.
//
// This implementation is thread-safe and suitable for:
//   - Testing
//   - Development
//   - Temporary storage
//   - Caching layer
//
// Note: All data is lost when the process terminates.
type MemoryBackend struct {
	mu     sync.RWMutex
	data   map[string]*memoryEntry
	closed bool
}

// NewMemoryBackend creates a new in-memory storage backend.
//
// Returns:
//   - Backend: In-memory storage implementation
//
// Example:
//
//	storage := storage.NewMemoryBackend()
//	defer storage.Close()
//
//	err := storage.Put("key1", []byte("value1"), nil)
func NewMemoryBackend() Backend {
	return &MemoryBackend{
		data: make(map[string]*memoryEntry),
	}
}

// Put stores data at the given key with optional metadata/options.
func (m *MemoryBackend) Put(key string, data []byte, opts *Options) error {
	if key == "" {
		return ErrInvalidKey
	}

	if opts == nil {
		opts = DefaultOptions()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	// Calculate expiration time
	var expiration time.Time
	if opts.TTL > 0 {
		expiration = time.Now().Add(time.Duration(opts.TTL) * time.Second)
	}

	// Copy metadata to avoid external modifications
	metadata := make(map[string]string)
	for k, v := range opts.Metadata {
		metadata[k] = v
	}

	// Store a copy of the data to avoid external modifications
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	m.data[key] = &memoryEntry{
		data:       dataCopy,
		metadata:   metadata,
		expiration: expiration,
	}

	return nil
}

// Get retrieves data for the given key.
func (m *MemoryBackend) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	entry, exists := m.data[key]
	if !exists {
		return nil, ErrNotFound
	}

	// Check if entry has expired
	if !entry.expiration.IsZero() && time.Now().After(entry.expiration) {
		return nil, ErrNotFound
	}

	// Return a copy to avoid external modifications
	dataCopy := make([]byte, len(entry.data))
	copy(dataCopy, entry.data)

	return dataCopy, nil
}

// Delete removes the data at the given key.
func (m *MemoryBackend) Delete(key string) error {
	if key == "" {
		return ErrInvalidKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	if _, exists := m.data[key]; !exists {
		return ErrNotFound
	}

	delete(m.data, key)
	return nil
}

// Exists checks if a key exists in storage.
func (m *MemoryBackend) Exists(key string) (bool, error) {
	if key == "" {
		return false, ErrInvalidKey
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, ErrStorageClosed
	}

	entry, exists := m.data[key]
	if !exists {
		return false, nil
	}

	// Check if entry has expired
	if !entry.expiration.IsZero() && time.Now().After(entry.expiration) {
		return false, nil
	}

	return true, nil
}

// List returns all keys matching the given prefix.
func (m *MemoryBackend) List(prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	var keys []string
	now := time.Now()

	for key, entry := range m.data {
		// Skip expired entries
		if !entry.expiration.IsZero() && now.After(entry.expiration) {
			continue
		}

		// Match prefix
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Close releases any resources held by the storage backend.
//
// For memory backend, this clears the internal map and marks it as closed.
func (m *MemoryBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	// Clear all data
	m.data = nil
	m.closed = true

	return nil
}

// cleanExpired removes expired entries from memory.
// This should be called periodically if TTL is used extensively.
//
// Note: This is a utility method for memory management and is not part
// of the Backend interface.
func (m *MemoryBackend) cleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	now := time.Now()
	for key, entry := range m.data {
		if !entry.expiration.IsZero() && now.After(entry.expiration) {
			delete(m.data, key)
		}
	}
}
