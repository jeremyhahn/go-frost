package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

func newTestFileStorage(t *testing.T) StorageBackend {
	t.Helper()

	storage, err := NewFileStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStorage failed: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	return storage
}

func TestFileStorage_PutSecretAndGetSecret(t *testing.T) {
	storage := newTestFileStorage(t)

	key := "frost/keypackages/secret.json"
	secret := secmem.NewSecretBytes([]byte("serialized key package"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	// The caller's payload survives the write.
	if got := secretValue(t, secret); got != "serialized key package" {
		t.Errorf("caller secret was modified: %q", got)
	}

	retrieved, err := storage.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	defer retrieved.Destroy()

	if got := secretValue(t, retrieved); got != "serialized key package" {
		t.Errorf("GetSecret returned %q, want %q", got, "serialized key package")
	}

	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Exists = false for a key written through PutSecret")
	}
}

func TestFileStorage_GetSecret_NotFound(t *testing.T) {
	storage := newTestFileStorage(t)

	if _, err := storage.GetSecret("frost/keypackages/missing.json"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileStorage_PutSecret_NilPayload(t *testing.T) {
	storage := newTestFileStorage(t)

	err := storage.PutSecret("frost/keypackages/nil.json", nil, nil)
	var kErr *KeystoreError
	if !errors.As(err, &kErr) || kErr.Op != ErrProtectedMemory.Op {
		t.Errorf("expected a protected memory error for a nil payload, got %v", err)
	}
	if !errors.Is(err, secmem.ErrNilSecret) {
		t.Errorf("expected ErrNilSecret cause, got %v", err)
	}
}

func TestFileStorage_PutSecret_InvalidKey(t *testing.T) {
	storage := newTestFileStorage(t)

	secret := secmem.NewSecretBytes([]byte("payload"))
	defer secret.Destroy()

	if err := storage.PutSecret("", secret, nil); err == nil {
		t.Error("expected an error for an empty key")
	}
}

func TestFileStorage_GetSecret_EmptyPayload(t *testing.T) {
	dir := t.TempDir()
	storage, err := NewFileStorage(dir)
	if err != nil {
		t.Fatalf("NewFileStorage failed: %v", err)
	}
	defer storage.Close()

	key := "frost/keypackages/empty.json"
	path := filepath.Join(dir, key)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	// An empty payload cannot be held in protected memory, so it is reported
	// rather than returned as a nil secret.
	_, err = storage.GetSecret(key)
	var kErr *KeystoreError
	if !errors.As(err, &kErr) || kErr.Op != ErrProtectedMemory.Op {
		t.Errorf("expected a protected memory error for an empty payload, got %v", err)
	}
}
