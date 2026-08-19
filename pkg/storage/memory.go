// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package storage

import (
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
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
// Callers store secret material here - a serialized FROST key package among
// other things - so an entry's data is zeroized whenever the backend drops it,
// whether that is a delete, an overwrite, a close, or a TTL that has elapsed.
// Dropping the map reference alone would leave the bytes in the backing array
// until the allocator happened to reuse them. Take is the one path that does
// not zeroize, because it hands the data to its caller rather than dropping it.
//
// Note: All data is lost when the process terminates.
type MemoryBackend struct {
	// mu is exclusive rather than an RWMutex because every operation mutates:
	// any of them may reap an entry whose TTL has elapsed.
	mu     sync.Mutex
	data   map[string]*memoryEntry
	closed bool
}

// dropEntry removes the entry for key and zeroizes the data it held. Every
// path that drops an entry without handing its data to someone goes through
// here, so a path added later cannot quietly reintroduce the residue.
//
// The caller must hold m.mu.
func (m *MemoryBackend) dropEntry(key string) {
	entry, ok := m.data[key]
	if !ok {
		return
	}

	delete(m.data, key)
	secmem.ZeroBytes(entry.data)
}

// expired reports whether the entry has passed its expiration time.
func (e *memoryEntry) expired(now time.Time) bool {
	return !e.expiration.IsZero() && now.After(e.expiration)
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

	// Zeroize whatever this key held before. The copy above is taken first, so
	// this is safe even when data aliases the entry being replaced.
	m.dropEntry(key)

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

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	entry, exists := m.data[key]
	if !exists {
		return nil, ErrNotFound
	}

	// An entry past its TTL is reaped rather than merely reported absent: left
	// in the map it would keep its data resident for the rest of the process's
	// life, which is the opposite of what the TTL asked for.
	if entry.expired(time.Now()) {
		m.dropEntry(key)
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

	m.dropEntry(key)
	return nil
}

// Exists checks if a key exists in storage.
func (m *MemoryBackend) Exists(key string) (bool, error) {
	if key == "" {
		return false, ErrInvalidKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return false, ErrStorageClosed
	}

	entry, exists := m.data[key]
	if !exists {
		return false, nil
	}

	if entry.expired(time.Now()) {
		m.dropEntry(key)
		return false, nil
	}

	return true, nil
}

// List returns all keys matching the given prefix.
func (m *MemoryBackend) List(prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	var keys []string
	now := time.Now()

	// Deleting from a map while ranging over it is well defined.
	for key, entry := range m.data {
		// Reap expired entries rather than skipping over them.
		if entry.expired(now) {
			m.dropEntry(key)
			continue
		}

		// Match prefix
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Take removes the entry for key and hands its data to the caller rather than
// copying it: the backend keeps no reference to the returned slice once Take
// returns. A caller holding secret material can therefore seal or zeroize what
// it gets back knowing that no other copy of it survives here - which Get,
// which returns a copy and leaves the original in the map, cannot offer.
//
// It also reports when the entry expires, so a caller moving the value
// somewhere else can carry the remaining lifetime across with it. The zero
// Time means the entry does not expire.
//
// An entry holding no data is left in place and reported as an empty slice.
// Take exists to move a payload out of the backend, and an empty entry has
// none to move; removing it would discard a value on what the caller meant as
// a read.
//
// Returns ErrNotFound if the key does not exist or has already expired. An
// expired entry is removed and its data zeroized on the way past, rather than
// left resident for the rest of the process's life.
func (m *MemoryBackend) Take(key string) ([]byte, time.Time, error) {
	if key == "" {
		return nil, time.Time{}, ErrInvalidKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, time.Time{}, ErrStorageClosed
	}

	entry, exists := m.data[key]
	if !exists {
		return nil, time.Time{}, ErrNotFound
	}

	if entry.expired(time.Now()) {
		m.dropEntry(key)
		return nil, time.Time{}, ErrNotFound
	}

	if len(entry.data) == 0 {
		return nil, entry.expiration, nil
	}

	delete(m.data, key)

	return entry.data, entry.expiration, nil
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

	// Zeroize before dropping the map: closing a backend must not leave the
	// payloads it held readable in the heap it releases.
	for key := range m.data {
		m.dropEntry(key)
	}
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
		if entry.expired(now) {
			m.dropEntry(key)
		}
	}
}
