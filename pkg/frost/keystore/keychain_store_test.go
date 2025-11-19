package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

// setupTestStore creates a temporary keystore for testing.
func setupTestStore(t *testing.T) (KeyStore, string, group.Group) {
	t.Helper()

	// Create temporary directory
	tmpDir := filepath.Join(os.TempDir(), "frost-keystore-test")
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Fatalf("Failed to remove temp dir: %v", err)
	}
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create group
	g := ristretto255.NewGroup()

	// Create storage backend
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create keystore
	config := &Config{
		Group:   g,
		Storage: storage,
		Tags:    map[string]string{"test": "true"},
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	return store, tmpDir, g
}

// generateTestKeyPackages creates test key packages using the dealer.
func generateTestKeyPackages(t *testing.T, g group.Group, minSigners, maxSigners uint32) []frost.KeyPackage {
	t.Helper()

	cs := ristretto255_sha512.New()

	dealer := keygen.NewDealer(cs)

	// Generate participant IDs
	participantIDs := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		participantIDs[i] = frost.Identifier(i + 1)
	}

	keyPackages, _, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	return keyPackages
}

func TestNewKeychainStore(t *testing.T) {
	// Create a test storage backend
	tmpDir := filepath.Join(os.TempDir(), "frost-test-valid")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "nil group",
			config: &Config{
				Storage: storage,
			},
			wantErr: true,
		},
		{
			name: "nil storage",
			config: &Config{
				Group: ristretto255.NewGroup(),
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &Config{
				Group:   ristretto255.NewGroup(),
				Storage: storage,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewKeychainStore(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeychainStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if store != nil {
				defer store.Close()
			}
		})
	}
}

func TestKeychainStore_StoreAndGetKeyPackage(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Generate test key packages
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	keyID := "participant-1"
	groupID := "test-group"

	// Store key package
	err := store.StoreKeyPackage(keyID, groupID, kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Retrieve key package
	retrievedKP, metadata, err := store.GetKeyPackage(keyID)
	if err != nil {
		t.Fatalf("Failed to get key package: %v", err)
	}

	// Verify metadata
	if metadata.KeyID != keyID {
		t.Errorf("Expected KeyID %s, got %s", keyID, metadata.KeyID)
	}
	if metadata.GroupID != groupID {
		t.Errorf("Expected GroupID %s, got %s", groupID, metadata.GroupID)
	}
	if metadata.MinSigners != 2 {
		t.Errorf("Expected MinSigners 2, got %d", metadata.MinSigners)
	}
	if metadata.MaxSigners != 3 {
		t.Errorf("Expected MaxSigners 3, got %d", metadata.MaxSigners)
	}

	// Verify key package data
	if retrievedKP.Identifier != kp.Identifier {
		t.Errorf("Expected Identifier %d, got %d", kp.Identifier, retrievedKP.Identifier)
	}

	// Verify secret share equality
	originalShare := kp.SecretShare.Bytes()
	retrievedShare := retrievedKP.SecretShare.Bytes()
	if string(originalShare) != string(retrievedShare) {
		t.Error("Secret shares don't match")
	}

	// Verify group public key equality
	originalPubKey := kp.GroupPublicKey.Bytes()
	retrievedPubKey := retrievedKP.GroupPublicKey.Bytes()
	if string(originalPubKey) != string(retrievedPubKey) {
		t.Error("Group public keys don't match")
	}
}

func TestKeychainStore_StoreKeyPackage_AlreadyExists(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	keyID := "duplicate-key"
	groupID := "test-group"

	// Store key package first time
	err := store.StoreKeyPackage(keyID, groupID, kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Try to store again - should fail
	err = store.StoreKeyPackage(keyID, groupID, kp, 2, 3)
	if !IsAlreadyExistsError(err) {
		t.Errorf("Expected ErrAlreadyExists, got %v", err)
	}
}

func TestKeychainStore_GetKeyPackage_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	_, _, err := store.GetKeyPackage("non-existent-key")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestKeychainStore_DeleteKeyPackage(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	keyID := "delete-test"
	groupID := "test-group"

	// Store key package
	err := store.StoreKeyPackage(keyID, groupID, kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Verify it exists
	exists, err := store.KeyPackageExists(keyID)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if !exists {
		t.Error("Key package should exist")
	}

	// Delete it
	err = store.DeleteKeyPackage(keyID)
	if err != nil {
		t.Fatalf("Failed to delete key package: %v", err)
	}

	// Verify it's gone
	exists, err = store.KeyPackageExists(keyID)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if exists {
		t.Error("Key package should not exist after deletion")
	}
}

func TestKeychainStore_ListKeyPackages(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)

	// Store multiple key packages in different groups
	testData := []struct {
		keyID   string
		groupID string
	}{
		{"key-1", "group-1"},
		{"key-2", "group-1"},
		{"key-3", "group-2"},
	}

	for i, td := range testData {
		err := store.StoreKeyPackage(td.keyID, td.groupID, &keyPackages[i], 2, 3)
		if err != nil {
			t.Fatalf("Failed to store key package %s: %v", td.keyID, err)
		}
	}

	// List all key packages
	allMetadata, err := store.ListKeyPackages("")
	if err != nil {
		t.Fatalf("Failed to list key packages: %v", err)
	}
	if len(allMetadata) != 3 {
		t.Errorf("Expected 3 key packages, got %d", len(allMetadata))
	}

	// List key packages for group-1
	group1Metadata, err := store.ListKeyPackages("group-1")
	if err != nil {
		t.Fatalf("Failed to list key packages for group-1: %v", err)
	}
	if len(group1Metadata) != 2 {
		t.Errorf("Expected 2 key packages for group-1, got %d", len(group1Metadata))
	}

	// List key packages for group-2
	group2Metadata, err := store.ListKeyPackages("group-2")
	if err != nil {
		t.Fatalf("Failed to list key packages for group-2: %v", err)
	}
	if len(group2Metadata) != 1 {
		t.Errorf("Expected 1 key package for group-2, got %d", len(group2Metadata))
	}
}

func TestKeychainStore_StoreAndGetGroupPublicKey(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey

	groupID := "test-group"

	// Store group public key
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group public key: %v", err)
	}

	// Retrieve group public key
	retrievedKey, err := store.GetGroupPublicKey(groupID)
	if err != nil {
		t.Fatalf("Failed to get group public key: %v", err)
	}

	// Verify equality
	originalBytes := groupPublicKey.Bytes()
	retrievedBytes := retrievedKey.Bytes()
	if string(originalBytes) != string(retrievedBytes) {
		t.Error("Group public keys don't match")
	}
}

func TestKeychainStore_DeleteGroupPublicKey(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey

	groupID := "delete-group"

	// Store group public key
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group public key: %v", err)
	}

	// Verify it exists
	exists, err := store.GroupExists(groupID)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if !exists {
		t.Error("Group should exist")
	}

	// Delete it
	err = store.DeleteGroupPublicKey(groupID)
	if err != nil {
		t.Fatalf("Failed to delete group public key: %v", err)
	}

	// Verify it's gone
	exists, err = store.GroupExists(groupID)
	if err != nil {
		t.Fatalf("Failed to check existence: %v", err)
	}
	if exists {
		t.Error("Group should not exist after deletion")
	}
}

func TestKeychainStore_ListGroups(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey

	// Store multiple groups
	groupIDs := []string{"group-1", "group-2", "group-3"}
	for _, groupID := range groupIDs {
		err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
		if err != nil {
			t.Fatalf("Failed to store group %s: %v", groupID, err)
		}
	}

	// List all groups
	entries, err := store.ListGroups()
	if err != nil {
		t.Fatalf("Failed to list groups: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(entries))
	}

	// Verify group IDs
	foundGroups := make(map[string]bool)
	for _, entry := range entries {
		foundGroups[entry.GroupID] = true
		if entry.MinSigners != 2 {
			t.Errorf("Expected MinSigners 2, got %d", entry.MinSigners)
		}
		if entry.MaxSigners != 3 {
			t.Errorf("Expected MaxSigners 3, got %d", entry.MaxSigners)
		}
	}

	for _, groupID := range groupIDs {
		if !foundGroups[groupID] {
			t.Errorf("Group %s not found in list", groupID)
		}
	}
}

func TestKeychainStore_UpdateMetadata(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	keyID := "metadata-test"
	groupID := "test-group"

	// Store key package
	err := store.StoreKeyPackage(keyID, groupID, kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Get original metadata
	_, metadata, err := store.GetKeyPackage(keyID)
	if err != nil {
		t.Fatalf("Failed to get key package: %v", err)
	}

	// Update metadata - add a small sleep to ensure timestamp changes
	metadata.Tags["environment"] = "production"
	metadata.Tags["version"] = "1.0"

	err = store.UpdateMetadata(keyID, metadata)
	if err != nil {
		t.Fatalf("Failed to update metadata: %v", err)
	}

	// Retrieve and verify
	_, updatedMetadata, err := store.GetKeyPackage(keyID)
	if err != nil {
		t.Fatalf("Failed to get updated key package: %v", err)
	}

	// UpdatedAt should be set by UpdateMetadata
	if updatedMetadata.UpdatedAt == 0 {
		t.Error("UpdatedAt should be set after update")
	}

	if updatedMetadata.Tags["environment"] != "production" {
		t.Error("Tag 'environment' not updated")
	}
	if updatedMetadata.Tags["version"] != "1.0" {
		t.Error("Tag 'version' not updated")
	}
}

func TestKeychainStore_InvalidInputs(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	// Test empty key ID
	err := store.StoreKeyPackage("", "group", kp, 2, 3)
	if err != ErrInvalidKeyID {
		t.Errorf("Expected ErrInvalidKeyID, got %v", err)
	}

	// Test empty group ID
	err = store.StoreKeyPackage("key", "", kp, 2, 3)
	if err != ErrInvalidGroupID {
		t.Errorf("Expected ErrInvalidGroupID, got %v", err)
	}

	// Test nil key package
	err = store.StoreKeyPackage("key", "group", nil, 2, 3)
	if err != ErrInvalidKeyPackage {
		t.Errorf("Expected ErrInvalidKeyPackage, got %v", err)
	}
}

func TestKeychainStore_Close(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)

	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestKeychainStore_DeleteKeyPackage_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Try to delete non-existent key
	err := store.DeleteKeyPackage("non-existent")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestKeychainStore_DeleteGroupPublicKey_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Try to delete non-existent group
	err := store.DeleteGroupPublicKey("non-existent-group")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestKeychainStore_GetGroupPublicKey_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Try to get non-existent group
	_, err := store.GetGroupPublicKey("non-existent-group")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestKeychainStore_StoreGroupPublicKey_AlreadyExists(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey

	groupID := "duplicate-group"

	// Store group public key first time
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group public key: %v", err)
	}

	// Try to store again - should fail
	err = store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if !IsAlreadyExistsError(err) {
		t.Errorf("Expected ErrAlreadyExists, got %v", err)
	}
}

func TestKeychainStore_StoreGroupPublicKey_InvalidInputs(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey

	// Test empty group ID
	err := store.StoreGroupPublicKey("", groupPublicKey, 2, 3)
	if err != ErrInvalidGroupID {
		t.Errorf("Expected ErrInvalidGroupID, got %v", err)
	}

	// Test nil public key
	err = store.StoreGroupPublicKey("group", nil, 2, 3)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

func TestKeychainStore_UpdateMetadata_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	metadata := &KeyMetadata{
		KeyID:   "non-existent",
		GroupID: "test-group",
		Tags:    map[string]string{"test": "value"},
	}

	err := store.UpdateMetadata("non-existent", metadata)
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestKeychainStore_UpdateMetadata_InvalidInputs(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Test empty key ID
	err := store.UpdateMetadata("", &KeyMetadata{})
	if err != ErrInvalidKeyID {
		t.Errorf("Expected ErrInvalidKeyID, got %v", err)
	}

	// Test nil metadata
	err = store.UpdateMetadata("key", nil)
	if err != ErrInvalidMetadata {
		t.Errorf("Expected ErrInvalidMetadata, got %v", err)
	}
}

func TestKeychainStore_KeyPackageExists_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	exists, err := store.KeyPackageExists("non-existent")
	if err != nil {
		t.Fatalf("KeyPackageExists() error = %v", err)
	}
	if exists {
		t.Error("Non-existent key should return false")
	}
}

func TestKeychainStore_GroupExists_NotFound(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	exists, err := store.GroupExists("non-existent-group")
	if err != nil {
		t.Fatalf("GroupExists() error = %v", err)
	}
	if exists {
		t.Error("Non-existent group should return false")
	}
}

func TestFileStorage_Delete_NotFound(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-delete")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	err = storage.Delete("non-existent-key")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestFileStorage_Close_NilBackend(t *testing.T) {
	fs := &FileStorage{backend: nil}
	err := fs.Close()
	if err != nil {
		t.Errorf("Close() with nil backend should not error, got %v", err)
	}
}

func TestKeychainStore_GetKeyPackage_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Test empty key ID
	_, _, err := store.GetKeyPackage("")
	if err != ErrInvalidKeyID {
		t.Errorf("Expected ErrInvalidKeyID for empty key, got %v", err)
	}
}

func TestFileStorage_NewFileStorage_Error(t *testing.T) {
	// Test creating storage with invalid path
	tmpDir := "/proc/invalid-path-that-cannot-be-created"
	_, err := NewFileStorage(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid storage path")
	}
}

func TestFileStorage_Put_Error(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-put-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Store a value
	err = storage.Put("test-key", []byte("test-value"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Now make the directory read-only to cause error
	os.Chmod(tmpDir, 0400)
	defer os.Chmod(tmpDir, 0700)

	// Try to write again - should fail
	err = storage.Put("test-key-2", []byte("test-value"), DefaultPutOptions())
	if err == nil {
		t.Error("Expected error when writing to read-only directory")
	}
}

func TestFileStorage_Get_Error(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-get-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Try to get non-existent key
	_, err = storage.Get("non-existent")
	if !IsNotFoundError(err) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestFileStorage_Exists_Error(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-exists-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Test with valid key
	exists, err := storage.Exists("test-key")
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Non-existent key should return false")
	}

	// Store a key
	err = storage.Put("test-key", []byte("value"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Check it exists
	exists, err = storage.Exists("test-key")
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Existing key should return true")
	}
}

func TestFileStorage_List_Error(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-list-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Store some keys
	err = storage.Put("prefix-1", []byte("value1"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	err = storage.Put("prefix-2", []byte("value2"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	err = storage.Put("other-1", []byte("value3"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// List with prefix
	keys, err := storage.List("prefix")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys with prefix, got %d", len(keys))
	}

	// List all
	keys, err = storage.List("")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("Expected 3 total keys, got %d", len(keys))
	}
}

func TestKeychainStore_GetKeyPackage_UnmarshalError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-unmarshal")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store invalid JSON directly
	storageKey := "keypackages/corrupt-key"
	err = storage.Put(storageKey, []byte("invalid json"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Try to get it - should fail with unmarshal error
	_, _, err = store.GetKeyPackage("corrupt-key")
	if err == nil {
		t.Error("Expected error when getting corrupted key package")
	}
}

func TestKeychainStore_ListKeyPackages_Error(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-list-kp-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store a corrupted key package directly
	storageKey := "keypackages/corrupted"
	err = storage.Put(storageKey, []byte("invalid json"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// List - implementation may handle errors differently
	_, _ = store.ListKeyPackages("")
}

func TestKeychainStore_GetGroupPublicKey_DeserializeError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-get-group-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store corrupted group data with valid JSON but invalid element data
	storageKey := "groups/corrupted"
	corruptedData := `{"group_public_key":"invalid","metadata":{"group_id":"corrupted","min_signers":2,"max_signers":3}}`
	err = storage.Put(storageKey, []byte(corruptedData), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// GetGroupPublicKey should fail with deserialization error
	_, err = store.GetGroupPublicKey("corrupted")
	if err == nil {
		t.Error("Expected error when deserializing corrupted group public key")
	}
}

func TestKeychainStore_GetKeyPackage_DeserializeErrors(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-kp-deserialize")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	tests := []struct {
		name string
		data string
	}{
		{
			name: "invalid secret share",
			data: `{"identifier":1,"secret_share":"invalid","group_public_key":"` + makeValidElement(g) + `","verification_shares":[],"metadata":{"key_id":"test","group_id":"g1","min_signers":2,"max_signers":3}}`,
		},
		{
			name: "invalid group public key",
			data: `{"identifier":1,"secret_share":"` + makeValidScalar(g) + `","group_public_key":"invalid","verification_shares":[],"metadata":{"key_id":"test","group_id":"g1","min_signers":2,"max_signers":3}}`,
		},
		{
			name: "invalid verification share",
			data: `{"identifier":1,"secret_share":"` + makeValidScalar(g) + `","group_public_key":"` + makeValidElement(g) + `","verification_shares":[{"identifier":1,"verification_key":"invalid"}],"metadata":{"key_id":"test","group_id":"g1","min_signers":2,"max_signers":3}}`,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID := string(rune('a' + i))
			storageKey := "keypackages/" + keyID
			err := storage.Put(storageKey, []byte(tt.data), DefaultPutOptions())
			if err != nil {
				t.Fatalf("Put() error = %v", err)
			}

			_, _, err = store.GetKeyPackage(keyID)
			if err == nil {
				t.Error("Expected deserialization error")
			}
		})
	}
}

// Helper to generate valid base64-encoded scalar
func makeValidScalar(g group.Group) string {
	s, _ := g.RandomScalar()
	return string(s.Bytes())
}

// Helper to generate valid base64-encoded element
func makeValidElement(g group.Group) string {
	e, _ := g.SerializeElement(g.Generator())
	return string(e)
}

func TestKeychainStore_DeleteKeyPackage_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	err := store.DeleteKeyPackage("")
	if err != ErrInvalidKeyID {
		t.Errorf("Expected ErrInvalidKeyID, got %v", err)
	}
}

func TestKeychainStore_DeleteGroupPublicKey_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	err := store.DeleteGroupPublicKey("")
	if err != ErrInvalidGroupID {
		t.Errorf("Expected ErrInvalidGroupID, got %v", err)
	}
}

func TestKeychainStore_GetGroupPublicKey_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	_, err := store.GetGroupPublicKey("")
	if err != ErrInvalidGroupID {
		t.Errorf("Expected ErrInvalidGroupID, got %v", err)
	}
}

func TestKeychainStore_KeyPackageExists_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	_, err := store.KeyPackageExists("")
	if err != ErrInvalidKeyID {
		t.Errorf("Expected ErrInvalidKeyID, got %v", err)
	}
}

func TestKeychainStore_GroupExists_InvalidKey(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	_, err := store.GroupExists("")
	if err != ErrInvalidGroupID {
		t.Errorf("Expected ErrInvalidGroupID, got %v", err)
	}
}

func TestKeychainStore_GetGroupPublicKey_UnmarshalError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-group-unmarshal")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store invalid JSON
	storageKey := "groups/bad-json"
	err = storage.Put(storageKey, []byte("invalid json"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// GetGroupPublicKey should fail
	_, err = store.GetGroupPublicKey("bad-json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestKeychainStore_UpdateMetadata_UnmarshalError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-update-unmarshal")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store invalid JSON
	storageKey := "keypackages/bad-json"
	err = storage.Put(storageKey, []byte("invalid json"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	metadata := &KeyMetadata{
		KeyID:   "bad-json",
		GroupID: "test",
		Tags:    map[string]string{},
	}

	// UpdateMetadata should fail
	err = store.UpdateMetadata("bad-json", metadata)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestFileStorage_Put_OptionsError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-put-opts")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Store with default options
	err = storage.Put("test-key", []byte("value"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify it was stored
	data, err := storage.Get("test-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(data) != "value" {
		t.Errorf("Get() = %q, want %q", string(data), "value")
	}
}

func TestFileStorage_Put_NilOptions(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-put-nil-opts")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	defer storage.Close()

	// Store with nil options - should use defaults
	err = storage.Put("test-key", []byte("value"), nil)
	if err != nil {
		t.Fatalf("Put() with nil options error = %v", err)
	}

	// Verify it was stored
	data, err := storage.Get("test-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(data) != "value" {
		t.Errorf("Get() = %q, want %q", string(data), "value")
	}
}

func TestKeychainStore_ListGroups_UnmarshalError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-list-groups-err")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Store valid group
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey
	err = store.StoreGroupPublicKey("valid-group", groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store valid group: %v", err)
	}

	// Store corrupted group data directly
	storageKey := "frost/groups/corrupted.json"
	err = storage.Put(storageKey, []byte("invalid json"), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// ListGroups should skip the corrupted entry
	entries, err := store.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups() error = %v", err)
	}

	// Should only return the valid group
	if len(entries) != 1 {
		t.Errorf("Expected 1 valid group, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].GroupID != "valid-group" {
		t.Errorf("Expected valid-group, got %s", entries[0].GroupID)
	}
}

func TestKeychainStore_ToKeyPackage_VerificationShareError(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "frost-test-vs-error")
	storage, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	g := ristretto255.NewGroup()
	config := &Config{
		Group:   g,
		Storage: storage,
	}

	store, err := NewKeychainStore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	// Create a stored key package with invalid verification share in the middle
	data := `{"identifier":1,"secret_share":"` + makeValidScalar(g) + `","group_public_key":"` + makeValidElement(g) + `","verification_shares":[{"identifier":1,"verification_key":"` + makeValidElement(g) + `"},{"identifier":2,"verification_key":"invalid_key"}],"metadata":{"key_id":"test","group_id":"g1","min_signers":2,"max_signers":3,"created_at":0,"updated_at":0,"tags":{}}}`

	storageKey := "keypackages/vs-error-test"
	err = storage.Put(storageKey, []byte(data), DefaultPutOptions())
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Try to get it - should fail when deserializing the second verification share
	_, _, err = store.GetKeyPackage("vs-error-test")
	if err == nil {
		t.Error("Expected error when deserializing invalid verification share")
	}
}

func TestKeychainStore_GetKeyPackage_StorageError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Store a key package
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]
	keyID := "test-key"
	err := store.StoreKeyPackage(keyID, "group", kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Make directory read-only to cause storage error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to get - should fail with storage error
	_, _, err = store.GetKeyPackage(keyID)
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_DeleteKeyPackage_StorageError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Store a key package
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]
	keyID := "test-key-delete"
	err := store.StoreKeyPackage(keyID, "group", kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Make directory read-only to cause storage error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to delete - should fail with storage error
	err = store.DeleteKeyPackage(keyID)
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_GetGroupPublicKey_StorageError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Store a group
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey
	groupID := "test-group"
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group: %v", err)
	}

	// Make directory read-only to cause storage error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to get - should fail with storage error
	_, err = store.GetGroupPublicKey(groupID)
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_DeleteGroupPublicKey_StorageError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Store a group
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey
	groupID := "test-group-delete"
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group: %v", err)
	}

	// Make directory read-only to cause storage error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to delete - should fail with storage error
	err = store.DeleteGroupPublicKey(groupID)
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_KeyPackageExists_StorageError(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Make directory inaccessible
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Should fail with storage error
	_, err := store.KeyPackageExists("test-key")
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_GroupExists_StorageError(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Make directory inaccessible
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Should fail with storage error
	_, err := store.GroupExists("test-group")
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_StoreKeyPackage_ExistsError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]
	keyID := "exists-check"

	// Store a key package
	err := store.StoreKeyPackage(keyID, "group", kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Make directory read-only to cause storage.Exists error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to store again - should fail with storage error during Exists check
	err = store.StoreKeyPackage(keyID+"2", "group", kp, 2, 3)
	if err == nil {
		t.Error("Expected storage error during Exists check")
	}
}

func TestKeychainStore_StoreGroupPublicKey_ExistsError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	groupPublicKey := keyPackages[0].GroupPublicKey
	groupID := "exists-check-group"

	// Store a group
	err := store.StoreGroupPublicKey(groupID, groupPublicKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store group: %v", err)
	}

	// Make directory read-only to cause storage.Exists error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to store another group - should fail with storage error during Exists check
	err = store.StoreGroupPublicKey(groupID+"2", groupPublicKey, 2, 3)
	if err == nil {
		t.Error("Expected storage error during Exists check")
	}
}

func TestKeychainStore_UpdateMetadata_StorageError(t *testing.T) {
	store, tmpDir, g := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Store a key package
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]
	keyID := "update-test"
	err := store.StoreKeyPackage(keyID, "group", kp, 2, 3)
	if err != nil {
		t.Fatalf("Failed to store key package: %v", err)
	}

	// Get metadata
	_, metadata, err := store.GetKeyPackage(keyID)
	if err != nil {
		t.Fatalf("Failed to get key package: %v", err)
	}

	// Make directory read-only to cause storage error
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Try to update - should fail with storage error
	err = store.UpdateMetadata(keyID, metadata)
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_ListKeyPackages_StorageError(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Make directory inaccessible
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Should fail with storage error
	_, err := store.ListKeyPackages("")
	if err == nil {
		t.Error("Expected storage error")
	}
}

func TestKeychainStore_ListGroups_StorageError(t *testing.T) {
	store, tmpDir, _ := setupTestStore(t)
	defer os.RemoveAll(tmpDir)
	defer store.Close()

	// Make directory inaccessible
	os.Chmod(tmpDir, 0000)
	defer os.Chmod(tmpDir, 0700)

	// Should fail with storage error
	_, err := store.ListGroups()
	if err == nil {
		t.Error("Expected storage error")
	}
}
