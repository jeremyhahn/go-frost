package keystore

import (
	"errors"
	"fmt"
)

// Base error type for keystore operations.
type KeystoreError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *KeystoreError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("keystore: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("keystore: %s", e.Op)
}

func (e *KeystoreError) Unwrap() error {
	return e.Err
}

// Wrap creates a new KeystoreError wrapping an underlying error.
func (e *KeystoreError) Wrap(err error) error {
	return &KeystoreError{
		Op:  e.Op,
		Err: err,
	}
}

// Common keystore errors.
var (
	// ErrNotFound is returned when a key package is not found.
	ErrNotFound = &KeystoreError{Op: "not found"}

	// ErrAlreadyExists is returned when attempting to store a key package that already exists.
	ErrAlreadyExists = &KeystoreError{Op: "already exists"}

	// ErrInvalidIdentifier is returned when a participant identifier is invalid.
	ErrInvalidIdentifier = &KeystoreError{Op: "invalid identifier"}

	// ErrInvalidGroupID is returned when a group ID is invalid.
	ErrInvalidGroupID = &KeystoreError{Op: "invalid group ID"}

	// ErrInvalidKeyID is returned when a key ID is invalid.
	ErrInvalidKeyID = &KeystoreError{Op: "invalid key ID"}

	// ErrSerializeScalar is returned when scalar serialization fails.
	ErrSerializeScalar = &KeystoreError{Op: "serialize scalar"}

	// ErrDeserializeScalar is returned when scalar deserialization fails.
	ErrDeserializeScalar = &KeystoreError{Op: "deserialize scalar"}

	// ErrSerializeElement is returned when element serialization fails.
	ErrSerializeElement = &KeystoreError{Op: "serialize element"}

	// ErrDeserializeElement is returned when element deserialization fails.
	ErrDeserializeElement = &KeystoreError{Op: "deserialize element"}

	// ErrMarshalJSON is returned when JSON marshaling fails.
	ErrMarshalJSON = &KeystoreError{Op: "marshal JSON"}

	// ErrUnmarshalJSON is returned when JSON unmarshaling fails.
	ErrUnmarshalJSON = &KeystoreError{Op: "unmarshal JSON"}

	// ErrStorageBackend is returned when the storage backend operation fails.
	ErrStorageBackend = &KeystoreError{Op: "storage backend"}

	// ErrInvalidKeyPackage is returned when a key package is invalid or corrupted.
	ErrInvalidKeyPackage = &KeystoreError{Op: "invalid key package"}

	// ErrInvalidMetadata is returned when key metadata is invalid.
	ErrInvalidMetadata = &KeystoreError{Op: "invalid metadata"}
)

// IsNotFoundError returns true if the error is a "not found" error.
func IsNotFoundError(err error) bool {
	var kErr *KeystoreError
	if errors.As(err, &kErr) {
		return kErr.Op == ErrNotFound.Op
	}
	return false
}

// IsAlreadyExistsError returns true if the error is an "already exists" error.
func IsAlreadyExistsError(err error) bool {
	var kErr *KeystoreError
	if errors.As(err, &kErr) {
		return kErr.Op == ErrAlreadyExists.Op
	}
	return false
}
