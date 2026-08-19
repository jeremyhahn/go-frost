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

	// ErrMissingSecretShare is returned when a stored key package carries no
	// protected secret share.
	ErrMissingSecretShare = &KeystoreError{Op: "missing secret share"}

	// ErrProtectedMemory is returned when a protected memory operation fails,
	// for example opening or copying an enclave holding secret material.
	ErrProtectedMemory = &KeystoreError{Op: "protected memory"}

	// ErrPlaintextSerialization is returned when a StoredKeyPackage is handed
	// to encoding/json. A serialized key package carries the secret share, and
	// encoding/json cannot produce or consume one without leaving plaintext on
	// the ordinary heap, so the type refuses to be marshaled or unmarshaled
	// that way. Use StoredKeyPackage.Seal and OpenStoredKeyPackage, which keep
	// the serialized share in protected memory.
	ErrPlaintextSerialization = &KeystoreError{Op: "plaintext serialization"}
)

// errEmptyPayload is the cause reported when a stored secret payload turns
// out to be empty: protected memory cannot hold a zero-length secret, so the
// stored object is unusable.
var errEmptyPayload = errors.New("stored secret payload is empty")

// Causes reported by the protected-memory serialization boundary in wire.go.
var (
	// errMalformedDocument reports that encoding/json produced something other
	// than the JSON object the share member is spliced into.
	errMalformedDocument = errors.New("serialized key package is not a JSON object")

	// errShareSizeChanged reports that the protected share changed size
	// between the document being sized and the share being encoded into it.
	errShareSizeChanged = errors.New("protected secret share changed size during serialization")

	// errShareNotBase64 reports that the share member does not hold base64.
	// The base64 error itself is not reported, since it quotes the input.
	errShareNotBase64 = errors.New("secret share member is not valid base64")

	// errJSONMalformed reports a document the share scan cannot parse.
	errJSONMalformed = errors.New("malformed JSON document")

	// errJSONMemberMissing reports a document with no such top-level member.
	errJSONMemberMissing = errors.New("JSON member not found")

	// errJSONNotString reports a member whose value is not a JSON string.
	errJSONNotString = errors.New("JSON member is not a string")

	// errJSONEscapedValue reports a string value carrying a JSON escape, which
	// base64 never produces and unescaping would route through the heap.
	errJSONEscapedValue = errors.New("JSON member value contains an escape")

	// errJSONDuplicateMember reports a member appearing more than once, which
	// this package would resolve differently from encoding/json.
	errJSONDuplicateMember = errors.New("JSON member appears more than once")

	// errJSONEscapedKey reports a member name carrying a JSON escape. Such a
	// name reads as one thing to encoding/json, which unescapes it, and as
	// another to a scan that compares raw bytes - so a document could carry
	// the share twice and be seen as carrying it once.
	errJSONEscapedKey = errors.New("JSON member name contains an escape")
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
