// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keystore

import (
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/jeremyhahn/go-frost/pkg/storage"
)

// expiringBackend is a backend that can hand an entry over instead of copying it, so a plain value moves into protected memory.
type expiringBackend interface {
	storage.Backend

	Take(key string) ([]byte, time.Time, error)
}

// The memory backend is the only one MemoryStorage ever constructs, and this
// assertion is what makes the conversion in NewMemoryStorage a compile-time
// guarantee rather than a runtime hope.
var _ expiringBackend = (*storage.MemoryBackend)(nil)

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
	backend expiringBackend

	// mu guards secrets (PutSecret payloads in enclaves) and serializes every backend operation, so a key moves between keyspaces atomically.
	mu      sync.Mutex
	secrets map[string]*secretEntry
}

// secretEntry is a protected payload plus its optional expiration, mirroring
// the TTL support the underlying memory backend provides for plain entries.
type secretEntry struct {
	secret     *secmem.SecretBytes
	expiration time.Time // Zero value means no expiration
}

// expired reports whether the entry has passed its expiration time.
func (e *secretEntry) expired(now time.Time) bool {
	return !e.expiration.IsZero() && now.After(e.expiration)
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
		backend: backend.(expiringBackend),
		secrets: make(map[string]*secretEntry),
	}
}

// dropSecret destroys key's secret entry, if any; the caller must hold m.mu for writing.
func (m *MemoryStorage) dropSecret(key string) {
	entry, ok := m.secrets[key]
	if !ok {
		return
	}
	delete(m.secrets, key)
	entry.secret.Destroy()
}

// liveSecret returns key's unexpired secret entry, destroying it if its TTL has elapsed; the caller must hold m.mu.
func (m *MemoryStorage) liveSecret(key string) *secretEntry {
	entry, ok := m.secrets[key]
	if !ok {
		return nil
	}
	if entry.expired(time.Now()) {
		m.dropSecret(key)
		return nil
	}
	return entry
}

// reapExpired removes every entry whose TTL has elapsed, destroying its
// enclave. Deleting from the map while ranging over it is well defined.
// The caller must hold m.mu.
func (m *MemoryStorage) reapExpired() {
	now := time.Now()
	for key, entry := range m.secrets {
		if entry.expired(now) {
			m.dropSecret(key)
		}
	}
}

// readProtected copies the plaintext of a protected entry out of its enclave.
// The caller must hold m.mu for writing: reading an enclave opens and reseals
// it, which mutates the entry.
func (m *MemoryStorage) readProtected(entry *secretEntry) ([]byte, error) {
	var data []byte
	if err := secmem.WithSecret(entry.secret, func(b []byte) error {
		data = make([]byte, len(b))
		copy(data, b)
		return nil
	}); err != nil {
		return nil, ErrProtectedMemory.Wrap(err)
	}

	return data, nil
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

	// The backend write and the removal of any protected value the key held
	// happen in one critical section: a concurrent PutSecret either observes
	// the key as fully plain or fully protected, never half of each.
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.backend.Put(key, data, storageOpts); err != nil {
		return ErrStorageBackend.Wrap(err)
	}

	// The key now holds plain data; drop any protected value it had before so
	// the two keyspaces never disagree about what a key contains.
	m.dropSecret(key)

	return nil
}

// Get retrieves data for the given key.
//
// If the key was written through PutSecret, its plaintext is copied out of
// protected memory into the returned slice: callers holding secret material
// should prefer GetSecret and only reach for Get when plain bytes are what
// they actually need.
func (m *MemoryStorage) Get(key string) ([]byte, error) {
	// Write lock: a protected hit opens and reseals its enclave, and the
	// backend lookup must not race a key changing keyspaces.
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry := m.liveSecret(key); entry != nil {
		return m.readProtected(entry)
	}

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
	m.mu.Lock()
	defer m.mu.Unlock()

	// liveSecret reaps an expired entry, so deleting one reports it as absent
	// rather than as deleted - the same answer Get and Exists give.
	if m.liveSecret(key) != nil {
		m.dropSecret(key)
		return nil
	}

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
	// Both keyspaces are inspected under one lock, so a key being moved
	// between them is never reported as absent from both. The lock is
	// exclusive because an expired entry is reaped rather than skipped.
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.liveSecret(key) != nil {
		return true, nil
	}

	exists, err := m.backend.Exists(key)
	if err != nil {
		return false, ErrStorageBackend.Wrap(err)
	}

	return exists, nil
}

// List returns all keys matching the given prefix, across both plain and
// protected entries.
func (m *MemoryStorage) List(prefix string) ([]string, error) {
	// Exclusive: listing reaps the entries whose TTL has elapsed rather than
	// skipping over them.
	m.mu.Lock()
	defer m.mu.Unlock()

	keys, err := m.backend.List(prefix)
	if err != nil {
		return nil, ErrStorageBackend.Wrap(err)
	}

	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		seen[key] = true
	}

	m.reapExpired()
	for key := range m.secrets {
		if seen[key] {
			continue
		}
		if prefix == "" || strings.HasPrefix(key, prefix) {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// PutSecret stores secret-bearing data at the given key.
//
// The payload is kept in an enclave of its own - an independent copy of the
// caller's - and never enters the plain []byte map of the underlying backend.
func (m *MemoryStorage) PutSecret(key string, data *secmem.SecretBytes, opts *PutOptions) error {
	if key == "" {
		return ErrStorageBackend.Wrap(storage.ErrInvalidKey)
	}
	if data == nil {
		return ErrProtectedMemory.Wrap(secmem.ErrNilSecret)
	}

	if opts == nil {
		opts = DefaultPutOptions()
	}

	clone, err := secmem.Clone(data)
	if err != nil {
		return ErrProtectedMemory.Wrap(err)
	}

	var expiration time.Time
	if opts.TTL > 0 {
		expiration = time.Now().Add(time.Duration(opts.TTL) * time.Second)
	}

	// Clearing the plain value and installing the protected one happen in
	// one critical section, for the same reason as in Put.
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.secrets == nil {
		clone.Destroy()
		return ErrStorageBackend.Wrap(storage.ErrStorageClosed)
	}

	// The key is about to hold protected data; drop any plain value it had
	// before. A failure here leaves the previous state untouched.
	if err := m.backend.Delete(key); err != nil && err != storage.ErrNotFound {
		clone.Destroy()
		return ErrStorageBackend.Wrap(err)
	}

	m.dropSecret(key)
	m.secrets[key] = &secretEntry{secret: clone, expiration: expiration}

	return nil
}

// GetSecret retrieves secret-bearing data for the given key, returning an
// independent copy in protected memory that the caller owns.
//
// A value written through Put is not merely copied out of the plain keyspace
// but moved into the protected one, so that reading a key package written by
// an older revision leaves no plaintext behind: the backend hands its entry
// over rather than copying it, and NewSecretBytes zeroizes that one slice as
// it seals it. Reading a legacy value therefore ends with the value held
// exactly once, in an enclave, with its remaining TTL carried across intact.
// Merely copying it out - as this did before - would have left the serialized
// key package resident as a plain []byte for the rest of the process's life,
// however many times it was read through the protected API.
func (m *MemoryStorage) GetSecret(key string) (*secmem.SecretBytes, error) {
	// Write lock: cloning opens and reseals the stored enclave, and promoting
	// a plain value moves it between the two keyspaces.
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry := m.liveSecret(key); entry != nil {
		clone, err := secmem.Clone(entry.secret)
		if err != nil {
			return nil, ErrProtectedMemory.Wrap(err)
		}
		return clone, nil
	}

	data, expiration, err := m.backend.Take(key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, ErrStorageBackend.Wrap(err)
	}

	// An entry Take could not hand over holds nothing this API can represent -
	// protected memory cannot hold a zero-length secret - and Take left it
	// where it was rather than discarding it on a read.
	if len(data) == 0 {
		return nil, ErrProtectedMemory.Wrap(errEmptyPayload)
	}

	// NewSecretBytes zeroizes data in place as it seals it, and data is the
	// backend's own slice, so this is the last plaintext copy anywhere.
	stored := secmem.NewSecretBytes(data)
	if stored == nil {
		return nil, ErrProtectedMemory.Wrap(errEmptyPayload)
	}

	clone, err := secmem.Clone(stored)
	if err != nil {
		stored.Destroy()
		return nil, ErrProtectedMemory.Wrap(err)
	}

	// The key now lives in the protected keyspace, carrying whatever was left
	// of the lifetime it was stored with.
	m.secrets[key] = &secretEntry{secret: stored, expiration: expiration}

	return clone, nil
}

// Close releases any resources held by the storage backend, destroying every
// protected payload it still holds.
func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key := range m.secrets {
		m.dropSecret(key)
	}
	m.secrets = nil

	if m.backend != nil {
		return m.backend.Close()
	}
	return nil
}
