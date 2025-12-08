package keystore

import (
	"testing"
)

func TestNewMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage()
	if storage == nil {
		t.Fatal("NewMemoryStorage returned nil")
	}
	defer storage.Close()
}

func TestMemoryStorage_PutAndGet(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "test/key"
	data := []byte("test data")

	// Put data
	err := storage.Put(key, data, nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get data back
	retrieved, err := storage.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("Data mismatch: expected %q, got %q", data, retrieved)
	}
}

func TestMemoryStorage_PutWithOptions(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "test/key/options"
	data := []byte("test data with options")

	opts := &PutOptions{
		Permissions: 0600,
		Metadata:    map[string]string{"key": "value"},
	}

	err := storage.Put(key, data, opts)
	if err != nil {
		t.Fatalf("Put with options failed: %v", err)
	}

	retrieved, err := storage.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Error("Data mismatch")
	}
}

func TestMemoryStorage_GetNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	_, err := storage.Get("nonexistent/key")
	if err == nil {
		t.Error("Expected error for nonexistent key")
	}
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStorage_Delete(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "test/delete"
	data := []byte("to be deleted")

	// Put data
	err := storage.Put(key, data, nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify it exists
	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Fatal("Key should exist before delete")
	}

	// Delete
	err = storage.Delete(key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Key should not exist after delete")
	}
}

func TestMemoryStorage_DeleteNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	err := storage.Delete("nonexistent/key")
	if err == nil {
		t.Error("Expected error for deleting nonexistent key")
	}
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStorage_Exists(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "test/exists"

	// Should not exist initially
	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Key should not exist initially")
	}

	// Put data
	err = storage.Put(key, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Should exist now
	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Key should exist after Put")
	}
}

func TestMemoryStorage_List(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	// Put several keys
	keys := []string{
		"prefix/one",
		"prefix/two",
		"prefix/three",
		"other/key",
	}

	for _, key := range keys {
		err := storage.Put(key, []byte("data"), nil)
		if err != nil {
			t.Fatalf("Put failed for %s: %v", key, err)
		}
	}

	// List with prefix
	listed, err := storage.List("prefix/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != 3 {
		t.Errorf("Expected 3 keys with prefix, got %d", len(listed))
	}
}

func TestMemoryStorage_Close(t *testing.T) {
	storage := NewMemoryStorage()

	err := storage.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestMemoryStorage_Close_Nil(t *testing.T) {
	storage := &MemoryStorage{
		backend: nil,
	}

	err := storage.Close()
	if err != nil {
		t.Errorf("Close with nil backend should not error: %v", err)
	}
}
