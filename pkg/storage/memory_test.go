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
	mb.mu.Lock()
	_, expiringExists := mb.data["expiring/key"]
	_, permanentExists := mb.data["permanent/key"]
	mb.mu.Unlock()

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

func TestMemoryBackend_Take(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	memory := backend.(*MemoryBackend)

	if err := backend.Put("key", []byte("payload"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, expiration, err := memory.Take("key")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if string(data) != "payload" {
		t.Errorf("Take returned %q, want %q", data, "payload")
	}
	if !expiration.IsZero() {
		t.Errorf("Take reported expiration %v for an entry stored without a TTL", expiration)
	}

	// Taken means removed, not copied.
	if _, err := backend.Get("key"); err != ErrNotFound {
		t.Errorf("the entry survived Take (err = %v)", err)
	}
	if exists, _ := backend.Exists("key"); exists {
		t.Error("Exists still reports the taken entry")
	}
}

// TestMemoryBackend_Take_TransfersOwnership verifies Take hands over the
// backend's own slice rather than a copy of it. That is the whole point of the
// method: a caller sealing secret material can zeroize what it gets back and
// know that no copy is left in the map behind it.
func TestMemoryBackend_Take_TransfersOwnership(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	memory := backend.(*MemoryBackend)

	if err := backend.Put("key", []byte("payload"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	stored := memory.data["key"].data

	data, _, err := memory.Take("key")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if &data[0] != &stored[0] {
		t.Error("Take returned a copy; the backend's own slice is still out there to be zeroized by nobody")
	}
}

func TestMemoryBackend_Take_ReportsExpiration(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	memory := backend.(*MemoryBackend)

	opts := DefaultOptions()
	opts.TTL = 600

	before := time.Now()
	if err := backend.Put("key", []byte("payload"), opts); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	_, expiration, err := memory.Take("key")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if expiration.IsZero() {
		t.Fatal("Take reported no expiration for an entry stored with a TTL")
	}
	if expiration.Before(before.Add(600*time.Second)) || expiration.After(time.Now().Add(600*time.Second)) {
		t.Errorf("Take reported expiration %v, outside the window the TTL implies", expiration)
	}
}

// TestMemoryBackend_Take_ReapsExpiredEntry verifies an entry whose TTL has
// elapsed is removed and its data zeroized rather than left resident for the
// rest of the process's life.
func TestMemoryBackend_Take_ReapsExpiredEntry(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	memory := backend.(*MemoryBackend)

	if err := backend.Put("key", []byte("payload"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Expire it by hand rather than by waiting a second.
	stored := memory.data["key"].data
	memory.data["key"].expiration = time.Now().Add(-time.Second)

	if _, _, err := memory.Take("key"); err != ErrNotFound {
		t.Fatalf("Take on an expired entry returned %v, want ErrNotFound", err)
	}
	if _, ok := memory.data["key"]; ok {
		t.Error("the expired entry is still in the map")
	}
	for i, b := range stored {
		if b != 0 {
			t.Errorf("the expired entry's data survives at byte %d (%q); it was not zeroized", i, stored)
			break
		}
	}
}

// TestMemoryBackend_Take_LeavesEmptyEntryInPlace verifies an entry with no data
// is reported without being removed. Take moves a payload out; an empty entry
// has none, and discarding it would lose a value on what the caller meant as a
// read.
func TestMemoryBackend_Take_LeavesEmptyEntryInPlace(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	memory := backend.(*MemoryBackend)

	if err := backend.Put("key", []byte{}, nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, _, err := memory.Take("key")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("Take returned %d bytes for an empty entry", len(data))
	}
	if _, ok := memory.data["key"]; !ok {
		t.Error("the empty entry was discarded")
	}
}

func TestMemoryBackend_Take_Errors(t *testing.T) {
	backend := NewMemoryBackend()
	memory := backend.(*MemoryBackend)

	if _, _, err := memory.Take(""); err != ErrInvalidKey {
		t.Errorf("Take with an empty key returned %v, want ErrInvalidKey", err)
	}
	if _, _, err := memory.Take("absent"); err != ErrNotFound {
		t.Errorf("Take on a missing key returned %v, want ErrNotFound", err)
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if _, _, err := memory.Take("key"); err != ErrStorageClosed {
		t.Errorf("Take on a closed backend returned %v, want ErrStorageClosed", err)
	}
}

// assertZeroed fails unless every byte of b is zero.
func assertZeroed(t *testing.T, b []byte, what string) {
	t.Helper()

	if len(b) == 0 {
		t.Fatalf("%s: nothing to check; the test did not capture the stored slice", what)
	}
	for i, v := range b {
		if v != 0 {
			t.Errorf("%s: byte %d is %#x, want 0; the data survives in the heap the backend released (%q)",
				what, i, v, b)
			return
		}
	}
}

// storedSlice returns the exact slice the backend holds for key, so a test can
// look at those bytes again after the backend has dropped the entry.
func storedSlice(t *testing.T, m *MemoryBackend, key string) []byte {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.data[key]
	if !ok {
		t.Fatalf("the backend holds no entry for %q", key)
	}
	return entry.data
}

// TestMemoryBackend_DropsZeroizeData covers every path that drops an entry
// without handing its data to anyone. Removing the map reference is not
// enough - the backing array keeps the bytes until the allocator reuses them,
// and callers store secret material here.
func TestMemoryBackend_DropsZeroizeData(t *testing.T) {
	const key = "frost/keypackages/secret.json"

	tests := []struct {
		name string
		drop func(t *testing.T, backend Backend, memory *MemoryBackend)
	}{
		{
			name: "Delete",
			drop: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				if err := backend.Delete(key); err != nil {
					t.Fatalf("Delete failed: %v", err)
				}
			},
		},
		{
			name: "Put over an existing key",
			drop: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				if err := backend.Put(key, []byte("replacement"), nil); err != nil {
					t.Fatalf("Put failed: %v", err)
				}
			},
		},
		{
			name: "Close",
			drop: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				if err := backend.Close(); err != nil {
					t.Fatalf("Close failed: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewMemoryBackend()
			memory := backend.(*MemoryBackend)

			if err := backend.Put(key, []byte("secret payload"), nil); err != nil {
				t.Fatalf("Put failed: %v", err)
			}
			stored := storedSlice(t, memory, key)

			tt.drop(t, backend, memory)

			assertZeroed(t, stored, tt.name)
		})
	}
}

// TestMemoryBackend_Put_ReplacementIsReadable guards the ordering inside Put:
// the incoming data is copied before the replaced entry is zeroized, so a
// caller that passes back a slice it got from the backend still stores the
// bytes it meant to.
func TestMemoryBackend_Put_ReplacementIsReadable(t *testing.T) {
	backend := NewMemoryBackend()
	defer backend.Close()

	if err := backend.Put("key", []byte("first"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := backend.Put("key", []byte("second"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, err := backend.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(data) != "second" {
		t.Errorf("Get returned %q, want %q", data, "second")
	}
}

// TestMemoryBackend_ReapsExpiredOnEveryPath verifies an entry past its TTL is
// removed and zeroized by whichever operation next passes it, rather than
// merely being reported absent while its data stays resident.
func TestMemoryBackend_ReapsExpiredOnEveryPath(t *testing.T) {
	const key = "frost/keypackages/expiring.json"

	tests := []struct {
		name string
		pass func(t *testing.T, backend Backend, memory *MemoryBackend)
	}{
		{
			name: "Get",
			pass: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				if _, err := backend.Get(key); err != ErrNotFound {
					t.Errorf("Get on an expired entry returned %v, want ErrNotFound", err)
				}
			},
		},
		{
			name: "Exists",
			pass: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				exists, err := backend.Exists(key)
				if err != nil {
					t.Fatalf("Exists failed: %v", err)
				}
				if exists {
					t.Error("Exists reports an expired entry as present")
				}
			},
		},
		{
			name: "List",
			pass: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				keys, err := backend.List("")
				if err != nil {
					t.Fatalf("List failed: %v", err)
				}
				if len(keys) != 0 {
					t.Errorf("List returned %v, want no keys", keys)
				}
			},
		},
		{
			name: "Take",
			pass: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				if _, _, err := memory.Take(key); err != ErrNotFound {
					t.Errorf("Take on an expired entry returned %v, want ErrNotFound", err)
				}
			},
		},
		{
			name: "cleanExpired",
			pass: func(t *testing.T, backend Backend, memory *MemoryBackend) {
				memory.cleanExpired()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewMemoryBackend()
			defer backend.Close()
			memory := backend.(*MemoryBackend)

			if err := backend.Put(key, []byte("secret payload"), nil); err != nil {
				t.Fatalf("Put failed: %v", err)
			}
			stored := storedSlice(t, memory, key)

			// Expire it by hand rather than by waiting out a TTL, whose
			// resolution is a whole second.
			memory.mu.Lock()
			memory.data[key].expiration = time.Now().Add(-time.Second)
			memory.mu.Unlock()

			tt.pass(t, backend, memory)

			memory.mu.Lock()
			_, stillThere := memory.data[key]
			memory.mu.Unlock()
			if stillThere {
				t.Errorf("%s left the expired entry in the map", tt.name)
			}

			assertZeroed(t, stored, tt.name+" on an expired entry")
		})
	}
}
