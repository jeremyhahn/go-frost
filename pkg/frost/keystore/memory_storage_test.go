package keystore

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
	"github.com/jeremyhahn/go-frost/pkg/storage"
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

// secretValue reads a protected payload back into a plain string so tests can
// compare it. It does not consume the secret.
func secretValue(t *testing.T, secret *secmem.SecretBytes) string {
	t.Helper()

	var value string
	if err := secmem.WithSecret(secret, func(b []byte) error {
		value = string(b)
		return nil
	}); err != nil {
		t.Fatalf("failed to read protected payload: %v", err)
	}
	return value
}

func TestMemoryStorage_PutSecretAndGetSecret(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "frost/keypackages/secret.json"
	secret := secmem.NewSecretBytes([]byte("serialized key package"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	// The caller's payload is untouched: PutSecret stores its own copy.
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
}

func TestMemoryStorage_GetSecret_ReturnsIndependentCopy(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "frost/keypackages/independent.json"
	secret := secmem.NewSecretBytes([]byte("payload"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	first, err := storage.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	// Destroying what one caller got must not disturb the stored value.
	first.Destroy()

	second, err := storage.GetSecret(key)
	if err != nil {
		t.Fatalf("second GetSecret failed: %v", err)
	}
	defer second.Destroy()

	if got := secretValue(t, second); got != "payload" {
		t.Errorf("second GetSecret returned %q, want %q", got, "payload")
	}
}

func TestMemoryStorage_GetSecret_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	_, err := storage.GetSecret("frost/keypackages/missing.json")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestMemoryStorage_GetSecret_PromotesPlainValue verifies that reading a value
// written through the plain Put path MOVES it into protected memory rather
// than copying it out.
//
// The assertions are on the backend, not on the returned value: a copy that
// reads back correctly while the original stays in the plain map is exactly
// the defect this guards against. The serialized key package would remain
// resident outside protected memory for the life of the process, however many
// times it was read through the protected API.
func TestMemoryStorage_GetSecret_PromotesPlainValue(t *testing.T) {
	backend := NewMemoryStorage()
	defer backend.Close()
	memory := backend.(*MemoryStorage)

	const key = "frost/keypackages/plain.json"
	const want = "written as plain bytes"

	if err := memory.Put(key, []byte(want), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Precondition: the value starts out in the plain keyspace and nowhere else.
	if _, err := memory.backend.Get(key); err != nil {
		t.Fatalf("precondition: the backend does not hold the plain value: %v", err)
	}
	if _, ok := memory.secrets[key]; ok {
		t.Fatal("precondition: the key is already in the protected keyspace")
	}

	retrieved, err := memory.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	defer retrieved.Destroy()

	if got := secretValue(t, retrieved); got != want {
		t.Errorf("GetSecret returned %q, want %q", got, want)
	}

	// The promotion itself: the plain entry is gone from the backend...
	if _, err := memory.backend.Get(key); err != storage.ErrNotFound {
		t.Errorf("the backend still holds the plain value after a protected read (err = %v); "+
			"the serialized package stays resident outside protected memory", err)
	}

	// ...and the key now lives in the protected keyspace instead, rather than
	// having been dropped from both.
	entry, ok := memory.secrets[key]
	if !ok {
		t.Fatal("the key left the plain keyspace without being installed in the protected one")
	}
	if got := entry.secret.Size(); got != len(want) {
		t.Errorf("promoted secret is %d bytes, want %d", got, len(want))
	}

	// What the caller got back is independent of what the store kept.
	retrieved.Destroy()
	if got := secretValue(t, entry.secret); got != want {
		t.Errorf("stored secret = %q after the returned copy was destroyed, want %q", got, want)
	}

	// Promotion is invisible through the rest of the interface: the key still
	// reads, exists and lists exactly as it did in the plain keyspace.
	data, err := memory.Get(key)
	if err != nil {
		t.Fatalf("Get failed after promotion: %v", err)
	}
	if string(data) != want {
		t.Errorf("Get returned %q after promotion, want %q", data, want)
	}
	exists, err := memory.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed after promotion: %v", err)
	}
	if !exists {
		t.Error("Exists reports the key as absent after promotion")
	}
	keys, err := memory.List("frost/keypackages/")
	if err != nil {
		t.Fatalf("List failed after promotion: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List returned %v after promotion, want exactly [%s]", keys, key)
	}
}

// TestMemoryStorage_GetSecret_PromotionCarriesTTL verifies a promoted value
// keeps the lifetime it was stored with. Promoting it into an entry with no
// expiration would let a value outlive the TTL its writer set, which is the
// same residency problem the promotion exists to solve.
func TestMemoryStorage_GetSecret_PromotionCarriesTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  int64
	}{
		{name: "with a TTL", ttl: 600},
		{name: "without a TTL", ttl: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewMemoryStorage()
			defer backend.Close()
			memory := backend.(*MemoryStorage)

			const key = "frost/keypackages/expiring.json"

			opts := DefaultPutOptions()
			opts.TTL = tt.ttl

			before := time.Now()
			if err := memory.Put(key, []byte("expiring payload"), opts); err != nil {
				t.Fatalf("Put failed: %v", err)
			}

			secret, err := memory.GetSecret(key)
			if err != nil {
				t.Fatalf("GetSecret failed: %v", err)
			}
			defer secret.Destroy()

			entry, ok := memory.secrets[key]
			if !ok {
				t.Fatal("the value was not promoted into the protected keyspace")
			}

			if tt.ttl == 0 {
				if !entry.expiration.IsZero() {
					t.Errorf("promotion invented an expiration of %v for a value stored without a TTL",
						entry.expiration)
				}
				return
			}

			if entry.expiration.IsZero() {
				t.Fatal("promotion dropped the TTL; the value would outlive the lifetime it was stored with")
			}
			earliest := before.Add(time.Duration(tt.ttl) * time.Second)
			latest := time.Now().Add(time.Duration(tt.ttl) * time.Second)
			if entry.expiration.Before(earliest) || entry.expiration.After(latest) {
				t.Errorf("promoted expiration %v is outside [%v, %v]; the remaining lifetime was not carried across",
					entry.expiration, earliest, latest)
			}
		})
	}
}

// TestMemoryStorage_GetSecret_LeavesEmptyPlainValueInPlace verifies a plain
// entry that protected memory cannot represent - it holds no bytes, and a
// zero-length secret cannot be sealed - is reported as an error and left where
// it is. Removing it would discard a value on what the caller meant as a read.
func TestMemoryStorage_GetSecret_LeavesEmptyPlainValueInPlace(t *testing.T) {
	backend := NewMemoryStorage()
	defer backend.Close()
	memory := backend.(*MemoryStorage)

	const key = "frost/keypackages/empty.json"
	if err := memory.Put(key, []byte{}, nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	secret, err := memory.GetSecret(key)
	if err == nil {
		secret.Destroy()
		t.Fatal("expected an error reading an empty value as a secret")
	}
	if !errors.Is(err, errEmptyPayload) {
		t.Errorf("error = %v, want the empty-payload cause", err)
	}
	var keystoreErr *KeystoreError
	if !errors.As(err, &keystoreErr) || keystoreErr.Op != ErrProtectedMemory.Op {
		t.Errorf("error = %v, want a %q keystore error", err, ErrProtectedMemory.Op)
	}

	if _, err := memory.backend.Get(key); err != nil {
		t.Errorf("the empty value was discarded by a failed read: %v", err)
	}
	if _, ok := memory.secrets[key]; ok {
		t.Error("an empty value was installed in the protected keyspace")
	}
}

func TestMemoryStorage_Get_ReadsProtectedValue(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "frost/keypackages/readable.json"
	secret := secmem.NewSecretBytes([]byte("protected payload"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	data, err := storage.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(data) != "protected payload" {
		t.Errorf("Get returned %q, want %q", data, "protected payload")
	}
}

func TestMemoryStorage_SecretKeyspace(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "frost/keypackages/lifecycle.json"
	secret := secmem.NewSecretBytes([]byte("lifecycle"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Exists = false for a key written through PutSecret")
	}

	keys, err := storage.List("frost/keypackages/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List = %v, want [%s]", keys, key)
	}

	if err := storage.Delete(key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	exists, err = storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Exists = true after deleting a protected value")
	}
	if _, err := storage.GetSecret(key); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemoryStorage_OverwriteAcrossKeyspaces(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	key := "frost/keypackages/overwrite.json"
	secret := secmem.NewSecretBytes([]byte("first, protected"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	// A plain Put over a protected key replaces it outright.
	if err := storage.Put(key, []byte("second, plain"), nil); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, err := storage.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(data) != "second, plain" {
		t.Errorf("Get returned %q, want %q", data, "second, plain")
	}

	// ...and a protected Put over a plain key replaces it in the same way,
	// leaving exactly one entry behind.
	replacement := secmem.NewSecretBytes([]byte("third, protected"))
	defer replacement.Destroy()
	if err := storage.PutSecret(key, replacement, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	retrieved, err := storage.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	defer retrieved.Destroy()
	if got := secretValue(t, retrieved); got != "third, protected" {
		t.Errorf("GetSecret returned %q, want %q", got, "third, protected")
	}

	keys, err := storage.List("frost/keypackages/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("List = %v, want a single entry", keys)
	}
}

func TestMemoryStorage_PutSecret_InvalidInput(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	secret := secmem.NewSecretBytes([]byte("payload"))
	defer secret.Destroy()

	if err := storage.PutSecret("", secret, nil); err == nil {
		t.Error("expected an error for an empty key")
	}

	err := storage.PutSecret("frost/keypackages/nil.json", nil, nil)
	var kErr *KeystoreError
	if !errors.As(err, &kErr) || kErr.Op != ErrProtectedMemory.Op {
		t.Errorf("expected a protected memory error for a nil payload, got %v", err)
	}
	if !errors.Is(err, secmem.ErrNilSecret) {
		t.Errorf("expected ErrNilSecret cause, got %v", err)
	}
}

func TestMemoryStorage_SecretExpiration(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	memStorage, ok := storage.(*MemoryStorage)
	if !ok {
		t.Fatalf("NewMemoryStorage returned %T, want *MemoryStorage", storage)
	}

	key := "frost/keypackages/expired.json"
	secret := secmem.NewSecretBytes([]byte("expired payload"))
	defer secret.Destroy()

	if err := storage.PutSecret(key, secret, &PutOptions{TTL: 3600}); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	// A live TTL entry is readable.
	live, err := storage.GetSecret(key)
	if err != nil {
		t.Fatalf("GetSecret failed for a live TTL entry: %v", err)
	}
	live.Destroy()

	// Backdate the expiration rather than waiting for it to elapse.
	memStorage.mu.Lock()
	memStorage.secrets[key].expiration = time.Now().Add(-time.Second)
	memStorage.mu.Unlock()

	if _, err := storage.GetSecret(key); err != ErrNotFound {
		t.Errorf("expected ErrNotFound for an expired entry, got %v", err)
	}
	if _, err := storage.Get(key); err != ErrNotFound {
		t.Errorf("expected ErrNotFound from Get for an expired entry, got %v", err)
	}
	exists, err := storage.Exists(key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Exists = true for an expired entry")
	}
	keys, err := storage.List("frost/keypackages/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List = %v, want no entries", keys)
	}
}

// TestMemoryStorage_ExpirationDestroysTheEnclave pins the lifetime a TTL is
// there to bound. An expired entry must not merely read as absent: its enclave
// has to be destroyed and its entry removed, or the payload stays resident for
// the rest of the process's life. Every accessor is checked, because an entry
// only ever reaped by one of them accumulates under any workload that uses the
// others.
func TestMemoryStorage_ExpirationDestroysTheEnclave(t *testing.T) {
	key := "frost/keypackages/expired.json"

	accessors := []struct {
		name   string
		access func(t *testing.T, s StorageBackend)
	}{
		{
			name: "GetSecret",
			access: func(t *testing.T, s StorageBackend) {
				if _, err := s.GetSecret(key); err != ErrNotFound {
					t.Errorf("GetSecret = %v, want ErrNotFound", err)
				}
			},
		},
		{
			name: "Get",
			access: func(t *testing.T, s StorageBackend) {
				if _, err := s.Get(key); err != ErrNotFound {
					t.Errorf("Get = %v, want ErrNotFound", err)
				}
			},
		},
		{
			name: "Exists",
			access: func(t *testing.T, s StorageBackend) {
				exists, err := s.Exists(key)
				if err != nil {
					t.Fatalf("Exists failed: %v", err)
				}
				if exists {
					t.Error("Exists = true for an expired entry")
				}
			},
		},
		{
			name: "List",
			access: func(t *testing.T, s StorageBackend) {
				keys, err := s.List("frost/keypackages/")
				if err != nil {
					t.Fatalf("List failed: %v", err)
				}
				if len(keys) != 0 {
					t.Errorf("List = %v, want no entries", keys)
				}
			},
		},
		{
			name: "Delete",
			access: func(t *testing.T, s StorageBackend) {
				if err := s.Delete(key); err != ErrNotFound {
					t.Errorf("Delete = %v, want ErrNotFound", err)
				}
			},
		},
	}

	for _, tc := range accessors {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStorage()
			defer store.Close()

			memStore, ok := store.(*MemoryStorage)
			if !ok {
				t.Fatalf("NewMemoryStorage returned %T, want *MemoryStorage", store)
			}

			secret := secmem.NewSecretBytes([]byte("expired payload"))
			defer secret.Destroy()

			if err := store.PutSecret(key, secret, &PutOptions{TTL: 3600}); err != nil {
				t.Fatalf("PutSecret failed: %v", err)
			}

			// Backdate the expiration rather than waiting for it to elapse,
			// and hold on to the enclave so it can be probed after the reap.
			memStore.mu.Lock()
			entry := memStore.secrets[key]
			entry.expiration = time.Now().Add(-time.Second)
			stored := entry.secret
			memStore.mu.Unlock()

			tc.access(t, store)

			memStore.mu.Lock()
			_, present := memStore.secrets[key]
			memStore.mu.Unlock()
			if present {
				t.Error("the expired entry is still in the map; it was hidden rather than reaped")
			}

			if err := secmem.WithSecret(stored, func([]byte) error { return nil }); !errors.Is(err, secmem.ErrDestroyed) {
				t.Errorf("opening the reaped enclave returned %v, want ErrDestroyed; "+
					"the payload is still resident past its TTL", err)
			}
		})
	}
}

func TestMemoryStorage_PutSecretAfterClose(t *testing.T) {
	storage := NewMemoryStorage()

	secret := secmem.NewSecretBytes([]byte("payload"))
	defer secret.Destroy()

	key := "frost/keypackages/closed.json"
	if err := storage.PutSecret(key, secret, nil); err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	if err := storage.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if err := storage.PutSecret(key, secret, nil); err == nil {
		t.Error("expected an error storing a secret after Close")
	}
	if _, err := storage.GetSecret(key); err == nil {
		t.Error("expected an error reading a secret after Close")
	}
}

// TestMemoryStorage_ConcurrentCrossKeyspaceWrite pins the invariant that makes
// a key shared between the plain and protected keyspaces safe: a Put and a
// PutSecret racing on the same key are each atomic, so once both report
// success the key holds exactly one of the two payloads - never nothing.
//
// The interleaving this guards against is Put storing its plain value,
// PutSecret installing its protected clone, Put dropping that clone, and
// PutSecret then deleting the plain value: both calls return nil and the key
// is gone, silently losing a key package. Every iteration starts the two
// writers from a common barrier to open that window as wide as the scheduler
// allows, and checks the invariant unconditionally afterwards.
func TestMemoryStorage_ConcurrentCrossKeyspaceWrite(t *testing.T) {
	const iterations = 200
	const plainValue = "plain payload"
	const protectedValue = "protected payload"

	key := "frost/keypackages/race.json"

	for i := 0; i < iterations; i++ {
		store := NewMemoryStorage()
		secret := secmem.NewSecretBytes([]byte(protectedValue))

		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs[0] = store.Put(key, []byte(plainValue), nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			errs[1] = store.PutSecret(key, secret, nil)
		}()
		close(start)
		wg.Wait()

		for _, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: concurrent write failed: %v", i, err)
			}
		}

		exists, err := store.Exists(key)
		if err != nil {
			t.Fatalf("iteration %d: Exists failed: %v", i, err)
		}
		if !exists {
			t.Fatalf("iteration %d: both writes reported success but the key holds nothing", i)
		}

		data, err := store.Get(key)
		if err != nil {
			t.Fatalf("iteration %d: Get failed: %v", i, err)
		}
		if got := string(data); got != plainValue && got != protectedValue {
			t.Fatalf("iteration %d: Get returned %q, want one of the two payloads", i, got)
		}

		// Whichever keyspace won, the key is present in exactly one of them.
		keys, err := store.List("frost/keypackages/")
		if err != nil {
			t.Fatalf("iteration %d: List failed: %v", i, err)
		}
		if len(keys) != 1 {
			t.Fatalf("iteration %d: List = %v, want a single entry", i, keys)
		}

		secret.Destroy()
		if err := store.Close(); err != nil {
			t.Fatalf("iteration %d: Close failed: %v", i, err)
		}
	}
}

// TestMemoryStorage_ConcurrentDeleteAndPutSecret verifies a Delete racing a
// PutSecret leaves the two keyspaces agreeing with each other. Either outcome
// is legitimate - the delete may land before or after the write - but the
// readers must not disagree: a key Exists reports as present must be readable,
// and one it reports as absent must be absent from both keyspaces.
func TestMemoryStorage_ConcurrentDeleteAndPutSecret(t *testing.T) {
	const iterations = 200
	const protectedValue = "protected payload"

	key := "frost/keypackages/race-delete.json"

	for i := 0; i < iterations; i++ {
		store := NewMemoryStorage()
		if err := store.Put(key, []byte("plain payload"), nil); err != nil {
			t.Fatalf("iteration %d: seeding Put failed: %v", i, err)
		}

		secret := secmem.NewSecretBytes([]byte(protectedValue))

		start := make(chan struct{})
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			// A not-found delete is a legitimate outcome of the race.
			if err := store.Delete(key); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("iteration %d: Delete failed: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := store.PutSecret(key, secret, nil); err != nil {
				t.Errorf("iteration %d: PutSecret failed: %v", i, err)
			}
		}()
		close(start)
		wg.Wait()

		exists, err := store.Exists(key)
		if err != nil {
			t.Fatalf("iteration %d: Exists failed: %v", i, err)
		}

		data, err := store.Get(key)
		switch {
		case exists && err != nil:
			t.Fatalf("iteration %d: Exists reported the key present but Get failed: %v", i, err)
		case exists && string(data) != protectedValue:
			t.Fatalf("iteration %d: Get returned %q, want %q", i, data, protectedValue)
		case !exists && !errors.Is(err, ErrNotFound):
			t.Fatalf("iteration %d: Exists reported the key absent but Get returned (%q, %v)", i, data, err)
		}

		secret.Destroy()
		if err := store.Close(); err != nil {
			t.Fatalf("iteration %d: Close failed: %v", i, err)
		}
	}
}

// gatedBackend wraps a storage.Backend and lets a test observe exactly when a
// mutating call reaches it. entered is signaled on the way in and the call
// then waits for release, which pins the caller inside the backend operation
// for as long as the test needs - no sleeping, no polling.
type gatedBackend struct {
	expiringBackend

	gate    string // "put" or "delete": the operation to hold
	entered chan struct{}
	release chan struct{}
}

func newGatedBackend(gate string) *gatedBackend {
	return &gatedBackend{
		expiringBackend: storage.NewMemoryBackend().(expiringBackend),
		gate:            gate,
		entered:         make(chan struct{}),
		release:         make(chan struct{}),
	}
}

func (g *gatedBackend) hold(op string) {
	if op != g.gate {
		return
	}
	g.entered <- struct{}{}
	<-g.release
}

func (g *gatedBackend) Put(key string, data []byte, opts *storage.Options) error {
	g.hold("put")
	return g.expiringBackend.Put(key, data, opts)
}

func (g *gatedBackend) Delete(key string) error {
	g.hold("delete")
	return g.expiringBackend.Delete(key)
}

// TestMemoryStorage_CrossKeyspaceWritesAreOneCriticalSection is the
// deterministic form of TestMemoryStorage_ConcurrentCrossKeyspaceWrite: rather
// than racing two writers and hoping to hit the bad window, it holds a writer
// inside its backend call and asserts that mu is held at that moment.
//
// That is the property the cross-keyspace invariant rests on. Put must not
// reach the backend before taking mu (or a concurrent PutSecret could install
// a protected value between the two, which Put would then drop), and PutSecret
// must not still be clearing the plain value after releasing mu (or it could
// delete a plain value a later Put had legitimately stored).
func TestMemoryStorage_CrossKeyspaceWritesAreOneCriticalSection(t *testing.T) {
	key := "frost/keypackages/critical-section.json"

	tests := []struct {
		name string
		gate string
		call func(*MemoryStorage, *secmem.SecretBytes) error
	}{
		{
			name: "Put holds mu across the backend write",
			gate: "put",
			call: func(m *MemoryStorage, _ *secmem.SecretBytes) error {
				return m.Put(key, []byte("plain payload"), nil)
			},
		},
		{
			name: "PutSecret holds mu across the plain delete",
			gate: "delete",
			call: func(m *MemoryStorage, secret *secmem.SecretBytes) error {
				return m.PutSecret(key, secret, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := newGatedBackend(tt.gate)
			store := &MemoryStorage{
				backend: gate,
				secrets: make(map[string]*secretEntry),
			}

			secret := secmem.NewSecretBytes([]byte("protected payload"))
			defer secret.Destroy()

			done := make(chan error, 1)
			go func() { done <- tt.call(store, secret) }()

			// The writer is now parked inside the backend operation.
			<-gate.entered

			if store.mu.TryLock() {
				store.mu.Unlock()
				gate.release <- struct{}{}
				<-done
				t.Fatal("mu was free while the writer was mid-transition between keyspaces; " +
					"the plain and protected stores can be observed disagreeing")
			}

			gate.release <- struct{}{}
			if err := <-done; err != nil {
				t.Fatalf("write failed: %v", err)
			}

			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}
		})
	}
}
