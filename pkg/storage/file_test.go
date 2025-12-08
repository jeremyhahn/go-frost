package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewFileBackend(t *testing.T) {
	tmpDir := t.TempDir()

	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	if backend == nil {
		t.Fatal("NewFileBackend returned nil")
	}
}

func TestNewFileBackend_EmptyPath(t *testing.T) {
	_, err := NewFileBackend("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestNewFileBackend_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	newDir := filepath.Join(tmpDir, "new", "nested", "dir")

	backend, err := NewFileBackend(newDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	// Verify directory was created
	info, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("Directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Expected a directory")
	}
}

func TestFileBackend_Put(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Put("test/key.txt", []byte("test data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify file was created
	fullPath := filepath.Join(tmpDir, "test", "key.txt")
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Error("file was not created")
	}
}

func TestFileBackend_Put_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Put("", []byte("test data"), nil)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestFileBackend_Put_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Put("../outside", []byte("test data"), nil)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for path traversal, got %v", err)
	}
}

func TestFileBackend_Put_WithPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	opts := &Options{Permissions: 0644}
	err := backend.Put("test.txt", []byte("test data"), opts)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify file permissions
	fullPath := filepath.Join(tmpDir, "test.txt")
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected permissions 0644, got %o", info.Mode().Perm())
	}
}

func TestFileBackend_Get(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	key := "test/key.txt"
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

func TestFileBackend_Get_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	_, err := backend.Get("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestFileBackend_Get_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	_, err := backend.Get("../outside")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for path traversal, got %v", err)
	}
}

func TestFileBackend_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	_, err := backend.Get("nonexistent/key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileBackend_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	key := "test/delete.txt"
	err := backend.Put(key, []byte("test data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = backend.Delete(key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file was deleted
	fullPath := filepath.Join(tmpDir, key)
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Error("file was not deleted")
	}
}

func TestFileBackend_Delete_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Delete("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestFileBackend_Delete_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Delete("../outside")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for path traversal, got %v", err)
	}
}

func TestFileBackend_Delete_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	err := backend.Delete("nonexistent/key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileBackend_Delete_CleansEmptyDirs(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	key := "deeply/nested/dir/file.txt"
	err := backend.Put(key, []byte("test data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = backend.Delete(key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Empty parent directories should be cleaned up
	nestedDir := filepath.Join(tmpDir, "deeply", "nested", "dir")
	if _, err := os.Stat(nestedDir); !os.IsNotExist(err) {
		t.Error("empty parent directories should be cleaned up")
	}
}

func TestFileBackend_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	key := "test/exists.txt"

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

func TestFileBackend_Exists_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	_, err := backend.Exists("")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestFileBackend_Exists_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	_, err := backend.Exists("../outside")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for path traversal, got %v", err)
	}
}

func TestFileBackend_List(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	// Put several keys
	keys := []string{
		"prefix/one.txt",
		"prefix/two.txt",
		"prefix/three.txt",
		"other/key.txt",
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

func TestFileBackend_List_SkipsTempFiles(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	// Create a regular file
	err := backend.Put("file.txt", []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Manually create a temp file
	tmpFile := filepath.Join(tmpDir, "file.txt.tmp")
	err = os.WriteFile(tmpFile, []byte("temp"), 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	listed, err := backend.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != 1 {
		t.Errorf("expected 1 key (temp files should be skipped), got %d", len(listed))
	}
}

func TestFileBackend_Close(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)

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

func TestFileBackend_OperationsAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
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

func TestFileBackend_cleanEmptyDirs_OutsideBasePath(t *testing.T) {
	tmpDir := t.TempDir()
	fb, _ := NewFileBackend(tmpDir)
	defer fb.Close()

	// Type assertion to access private method
	fileBackend := fb.(*FileBackend)

	// Should not panic when trying to clean outside base path
	fileBackend.cleanEmptyDirs("/some/other/path")
}

func TestFileBackend_cleanEmptyDirs_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	fb, _ := NewFileBackend(tmpDir)
	defer fb.Close()

	// Type assertion to access private method
	fileBackend := fb.(*FileBackend)

	// Should not remove base path
	fileBackend.cleanEmptyDirs(tmpDir)

	// Base path should still exist
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("base path should not be deleted")
	}
}

func TestFileBackend_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	key := "test.txt"

	// Write first version
	err := backend.Put(key, []byte("version 1"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Overwrite with second version
	err = backend.Put(key, []byte("version 2"), nil)
	if err != nil {
		t.Fatalf("Put (overwrite) failed: %v", err)
	}

	// Verify second version
	data, err := backend.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(data) != "version 2" {
		t.Errorf("expected 'version 2', got %q", data)
	}
}

func TestFileBackend_List_BasePathDeleted(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.MkdirAll(subDir, 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	backend, _ := NewFileBackend(subDir)
	defer backend.Close()

	// Put a key
	err = backend.Put("test.txt", []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Delete the entire base path (simulating external deletion)
	// But first we need to access the internal basePath
	fileBackend := backend.(*FileBackend)

	// Remove all files and the directory
	os.RemoveAll(subDir)

	// List should return empty list when base path doesn't exist
	keys, err := fileBackend.List("")
	if err != nil {
		t.Fatalf("List should not error when base path is deleted: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys when base path deleted, got %d", len(keys))
	}
}

func TestFileBackend_List_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	// List on empty directory should return empty slice
	keys, err := backend.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for empty directory, got %d", len(keys))
	}
}

func TestFileBackend_Put_CreateSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	// Put with deeply nested key
	key := "very/deeply/nested/directory/structure/file.txt"
	err := backend.Put(key, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify file exists
	fullPath := filepath.Join(tmpDir, key)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Error("file was not created")
	}
}

func TestFileBackend_Exists_StatError(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewFileBackend(tmpDir)
	defer backend.Close()

	// Create a subdirectory manually
	subDir := filepath.Join(tmpDir, "testdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Exists on a directory returns true (os.Stat works on both files and directories)
	exists, err := backend.Exists("testdir")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Exists should return true for paths that exist")
	}
}
