package keystore

import (
	"errors"
	"testing"
)

// TestKeystoreError_Error tests the Error() method.
func TestKeystoreError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *KeystoreError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &KeystoreError{
				Op:  "get",
				Err: errors.New("file not found"),
			},
			expected: "keystore: get: file not found",
		},
		{
			name: "without wrapped error",
			err: &KeystoreError{
				Op:  "put",
				Err: nil,
			},
			expected: "keystore: put",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestKeystoreError_Unwrap tests the Unwrap() method.
func TestKeystoreError_Unwrap(t *testing.T) {
	baseErr := errors.New("base error")

	tests := []struct {
		name     string
		err      *KeystoreError
		expected error
	}{
		{
			name: "with wrapped error",
			err: &KeystoreError{
				Op:  "delete",
				Err: baseErr,
			},
			expected: baseErr,
		},
		{
			name: "without wrapped error",
			err: &KeystoreError{
				Op:  "list",
				Err: nil,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Unwrap()
			if result != tt.expected {
				t.Errorf("Unwrap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestKeystoreError_Wrap tests the Wrap() method.
func TestKeystoreError_Wrap(t *testing.T) {
	baseErr := errors.New("underlying error")
	originalErr := &KeystoreError{Op: "store"}

	wrappedErr := originalErr.Wrap(baseErr)

	// Verify it's a KeystoreError
	kErr, ok := wrappedErr.(*KeystoreError)
	if !ok {
		t.Fatal("Wrap() did not return *KeystoreError")
	}

	// Verify operation is preserved
	if kErr.Op != "store" {
		t.Errorf("Wrap() Op = %q, want %q", kErr.Op, "store")
	}

	// Verify error is wrapped
	if kErr.Err != baseErr {
		t.Errorf("Wrap() Err = %v, want %v", kErr.Err, baseErr)
	}

	// Verify unwrapping works
	if !errors.Is(wrappedErr, baseErr) {
		t.Error("Wrap() should allow errors.Is to find wrapped error")
	}
}

// TestErrorSentinels verifies all sentinel errors are defined correctly.
func TestErrorSentinels(t *testing.T) {
	sentinels := []*KeystoreError{
		ErrNotFound,
		ErrAlreadyExists,
		ErrInvalidIdentifier,
		ErrInvalidGroupID,
		ErrInvalidKeyID,
		ErrSerializeScalar,
		ErrDeserializeScalar,
		ErrSerializeElement,
		ErrDeserializeElement,
		ErrMarshalJSON,
		ErrUnmarshalJSON,
		ErrStorageBackend,
		ErrInvalidKeyPackage,
		ErrInvalidMetadata,
	}

	for _, err := range sentinels {
		if err == nil {
			t.Error("sentinel error is nil")
			continue
		}
		if err.Op == "" {
			t.Errorf("sentinel error %v has empty Op", err)
		}
		if err.Error() == "" {
			t.Errorf("sentinel error %v has empty message", err)
		}
	}
}

// TestIsNotFoundError tests the IsNotFoundError helper function.
func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "not found error",
			err:      ErrNotFound,
			expected: true,
		},
		{
			name:     "wrapped not found error",
			err:      ErrNotFound.Wrap(errors.New("underlying")),
			expected: true,
		},
		{
			name:     "different error",
			err:      ErrAlreadyExists,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "standard error",
			err:      errors.New("random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFoundError(tt.err)
			if result != tt.expected {
				t.Errorf("IsNotFoundError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestIsAlreadyExistsError tests the IsAlreadyExistsError helper function.
func TestIsAlreadyExistsError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "already exists error",
			err:      ErrAlreadyExists,
			expected: true,
		},
		{
			name:     "wrapped already exists error",
			err:      ErrAlreadyExists.Wrap(errors.New("underlying")),
			expected: true,
		},
		{
			name:     "different error",
			err:      ErrNotFound,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "standard error",
			err:      errors.New("random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAlreadyExistsError(tt.err)
			if result != tt.expected {
				t.Errorf("IsAlreadyExistsError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestKeystoreError_ErrorsAs tests that errors.As works correctly.
func TestKeystoreError_ErrorsAs(t *testing.T) {
	baseErr := errors.New("base")
	wrappedErr := ErrStorageBackend.Wrap(baseErr)

	var kErr *KeystoreError
	if !errors.As(wrappedErr, &kErr) {
		t.Error("errors.As should succeed for KeystoreError")
	}

	if kErr.Op != ErrStorageBackend.Op {
		t.Errorf("errors.As extracted Op = %q, want %q", kErr.Op, ErrStorageBackend.Op)
	}
}

// TestKeystoreError_ErrorsIs tests that errors.Is works correctly.
func TestKeystoreError_ErrorsIs(t *testing.T) {
	baseErr := errors.New("base error")
	wrappedErr := ErrInvalidKeyPackage.Wrap(baseErr)

	if !errors.Is(wrappedErr, baseErr) {
		t.Error("errors.Is should find wrapped base error")
	}
}
