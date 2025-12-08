package storage

import (
	"testing"
	"time"
)

func TestNewMemoryBackend(t *testing.T) {
	backend := NewMemoryBackend()
	if backend == nil {
		t.Fatal("NewMemoryBackend returned nil")
	}
	defer backend.Close()
}

func TestMemoryBackend_Put(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	err := backend.Put("test/key", []byte("test data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
}

func TestMemoryBackend_Put_EmptyKey(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	err := backend.Put("", []byte("test data"), nil)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestMemoryBackend_Put_WithOptions(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	opts := &Options{
		Permissions: 0600,
		Metadata:    map[string]string{"key": "value"},
		TTL:         3600,
	}

	err := backend.Put("test/key", []byte("test data"), opts)
	if err != nil {
		t.Fatalf("Put with options failed: %v", err)
	}
}

func TestMemoryBackend_Get(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	key := "test/key"
	data := []byte("test data")

	err := backend.Put(key, data, nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	retrieved, err := backend.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("data mismatch: expected %q, got %q", data, retrieved)
	}
}

func TestMemoryBackend_Get_EmptyKey(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	_, err := backend.Get("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestMemoryBackend_Get_NotFound(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	_, err := backend.Get("nonexistent/key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryBackend_Get_Expired(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	opts := &Options{TTL: 1} // 1 second TTL

	err := backend.Put("test/key", []byte("test data"), opts)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	_, err = backend.Get("test/key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for expired entry, got %v", err)
	}
}

func TestMemoryBackend_Delete(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	key := "test/delete"
	err := backend.Put(key, []byte("test data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = backend.Delete(key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	exists, err := backend.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("key should not exist after delete")
	}
}

func TestMemoryBackend_Delete_EmptyKey(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	err := backend.Delete("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestMemoryBackend_Delete_NotFound(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	err := backend.Delete("nonexistent/key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryBackend_Exists(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	key := "test/exists"

	// Should not exist initially
	exists, err := backend.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("key should not exist initially")
	}

	// Put data
	err = backend.Put(key, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Should exist now
	exists, err = backend.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("key should exist after Put")
	}
}

func TestMemoryBackend_Exists_EmptyKey(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	_, err := backend.Exists("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestMemoryBackend_Exists_Expired(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	opts := &Options{TTL: 1} // 1 second TTL

	err := backend.Put("test/key", []byte("test data"), opts)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify it exists
	exists, err := backend.Exists("test/key")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Fatal("key should exist before expiration")
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Should no longer exist
	exists, err = backend.Exists("test/key")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("key should not exist after expiration")
	}
}

func TestMemoryBackend_List(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	// Put several keys
	keys := []string{
		"prefix/one",
		"prefix/two",
		"prefix/three",
		"other/key",
	}

	for _, key := range keys {
		err := backend.Put(key, []byte("data"), nil)
		if err != nil {
			t.Fatalf("Put failed for %s: %v", key, err)
		}
	}

	// List with prefix
	listed, err := backend.List("prefix/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != 3 {
		t.Errorf("expected 3 keys with prefix, got %d", len(listed))
	}

	// List all keys (empty prefix)
	listed, err = backend.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != 4 {
		t.Errorf("expected 4 total keys, got %d", len(listed))
	}
}

func TestMemoryBackend_List_Expired(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	// Put one with TTL and one without
	err := backend.Put("normal/key", []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	opts := &Options{TTL: 1}
	err = backend.Put("expiring/key", []byte("data"), opts)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Both should be listed initially
	listed, err := backend.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("expected 2 keys initially, got %d", len(listed))
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Only non-expired should be listed
	listed, err = backend.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("expected 1 key after expiration, got %d", len(listed))
	}
}

func TestMemoryBackend_Close(t *testing.T) {
	backend := NewMemoryBackend()

	err := backend.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be fine
	err = backend.Close()
	if err != nil {
		t.Errorf("Double close should not error: %v", err)
	}
}

func TestMemoryBackend_OperationsAfterClose(t *testing.T) {
	backend := NewMemoryBackend()
	backend.Close()

	// All operations should return ErrStorageClosed
	err := backend.Put("key", []byte("data"), nil)
	if err != ErrStorageClosed {
		t.Errorf("Put after close: expected ErrStorageClosed, got %v", err)
	}

	_, err = backend.Get("key")
	if err != ErrStorageClosed {
		t.Errorf("Get after close: expected ErrStorageClosed, got %v", err)
	}

	err = backend.Delete("key")
	if err != ErrStorageClosed {
		t.Errorf("Delete after close: expected ErrStorageClosed, got %v", err)
	}

	_, err = backend.Exists("key")
	if err != ErrStorageClosed {
		t.Errorf("Exists after close: expected ErrStorageClosed, got %v", err)
	}

	_, err = backend.List("")
	if err != ErrStorageClosed {
		t.Errorf("List after close: expected ErrStorageClosed, got %v", err)
	}
}

func TestMemoryBackend_DataIsolation(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	// Test that modifications to input don't affect stored data
	data := []byte("original")
	err := backend.Put("key", data, nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Modify original data
	data[0] = 'X'

	// Retrieved data should be unchanged
	retrieved, err := backend.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != "original" {
		t.Errorf("data was modified: expected 'original', got %q", retrieved)
	}

	// Test that modifications to output don't affect stored data
	retrieved[0] = 'Y'

	retrieved2, err := backend.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved2) != "original" {
		t.Errorf("stored data was modified: expected 'original', got %q", retrieved2)
	}
}

func TestMemoryBackend_cleanExpired(t *testing.T) {
	mb := NewMemoryBackend().(*MemoryBackend)
	defer mb.Close()

	// Add an entry with short TTL
	opts := &Options{TTL: 1}
	err := mb.Put("expiring/key", []byte("data"), opts)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Add a non-expiring entry
	err = mb.Put("permanent/key", []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	// Clean expired entries
	mb.cleanExpired()

	// Verify expired entry was removed
	mb.mu.RLock()
	_, expiringExists := mb.data["expiring/key"]
	_, permanentExists := mb.data["permanent/key"]
	mb.mu.RUnlock()

	if expiringExists {
		t.Error("expired entry should have been cleaned")
	}
	if !permanentExists {
		t.Error("permanent entry should still exist")
	}
}

func TestMemoryBackend_cleanExpired_AfterClose(t *testing.T) {
	mb := NewMemoryBackend().(*MemoryBackend)
	mb.Close()

	// Should not panic
	mb.cleanExpired()
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts == nil {
		t.Fatal("DefaultOptions returned nil")
	}

	if opts.Permissions != 0600 {
		t.Errorf("expected Permissions 0600, got %o", opts.Permissions)
	}

	if opts.Metadata == nil {
		t.Error("Metadata should not be nil")
	}

	if opts.TTL != 0 {
		t.Errorf("expected TTL 0, got %d", opts.TTL)
	}
}
