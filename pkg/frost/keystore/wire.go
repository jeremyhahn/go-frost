package keystore

// wire.go assembles and reads the stored key package document in protected memory; the format matches encoding/json's.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

const (
	// shareMember is the document member holding the base64 secret share. It
	// is the name the plaintext SecretShare field used to serialize under.
	shareMember = "SecretShare"

	// shareMemberOpen opens the share member where it belongs: immediately
	// after Identifier, which is where the plaintext SecretShare field sat in
	// the struct and so where encoding/json emitted it.
	shareMemberOpen = `,"` + shareMember + `":"`
)

// jsonNull is the JSON literal for a member with no value.
var jsonNull = []byte("null")

// storedKeyPackagePublic is the public half of the document, in member order; only it goes through encoding/json.
type storedKeyPackagePublic struct {
	Identifier         frost.Identifier
	GroupPublicKey     []byte
	VerificationShares []StoredVerificationShare
	Metadata           KeyMetadata
}

// Seal serializes the stored key package into protected memory and returns the
// sealed document. The document is assembled inside a mlock'd buffer: the
// share is base64-encoded straight out of its enclave into that buffer, and
// the public members are spliced in around it. No plaintext copy of the share,
// and no plaintext copy of the document, exists on the ordinary heap at any
// point.
//
// The caller owns the returned payload and must Destroy it.
//
// Seal returns ErrMissingSecretShare when the package carries no protected
// share; a package without a share has nothing to serialize.
func (s *StoredKeyPackage) Seal() (*secmem.SecretBytes, error) {
	if s == nil || s.SecretShareProtected == nil {
		return nil, ErrMissingSecretShare
	}

	public, err := json.Marshal(&storedKeyPackagePublic{
		Identifier:         s.Identifier,
		GroupPublicKey:     s.GroupPublicKey,
		VerificationShares: s.VerificationShares,
		Metadata:           s.Metadata,
	})
	if err != nil {
		return nil, ErrMarshalJSON.Wrap(err)
	}

	// The share member goes after Identifier, between head and tail.
	head, tail, err := splitAfterFirstMember(public)
	if err != nil {
		return nil, ErrMarshalJSON.Wrap(err)
	}

	// prefix opens the share member after head; suffix closes it and appends
	// the rest of the public document. When Identifier is the only public
	// member, tail is just the closing brace and the same splice still holds.
	prefix := make([]byte, 0, len(head)+len(shareMemberOpen))
	prefix = append(prefix, head...)
	prefix = append(prefix, shareMemberOpen...)

	suffix := make([]byte, 0, 1+len(tail))
	suffix = append(suffix, '"')
	suffix = append(suffix, tail...)

	shareLen := s.SecretShareProtected.Size()
	encodedLen := base64.StdEncoding.EncodedLen(shareLen)
	size := len(prefix) + encodedLen + len(suffix)

	payload, err := secmem.NewSecret(size, func(dst []byte) (int, error) {
		n := copy(dst, prefix)

		var encodeErr error
		if err := secmem.WithSecret(s.SecretShareProtected, func(share []byte) error {
			if len(share) != shareLen {
				encodeErr = errShareSizeChanged
				return nil
			}
			base64.StdEncoding.Encode(dst[n:n+encodedLen], share)
			return nil
		}); err != nil {
			return 0, ErrProtectedMemory.Wrap(err)
		}
		if encodeErr != nil {
			return 0, ErrMarshalJSON.Wrap(encodeErr)
		}
		n += encodedLen

		n += copy(dst[n:], suffix)
		return n, nil
	})
	if err != nil {
		if errors.Is(err, secmem.ErrEmptySecret) {
			return nil, ErrMarshalJSON.Wrap(errEmptyPayload)
		}
		return nil, err
	}

	return payload, nil
}

// OpenStoredKeyPackage decodes a document sealed by Seal. The document is
// decoded from inside its enclave and the share is base64-decoded straight
// into a protected buffer of its own, so neither the document nor the share
// exists as an ordinary heap allocation at any point.
//
// Callers own the returned package and must Zeroize it.
func OpenStoredKeyPackage(payload *secmem.SecretBytes) (*StoredKeyPackage, error) {
	var (
		stored    *StoredKeyPackage
		decodeErr error
	)

	if err := secmem.WithSecret(payload, func(document []byte) error {
		stored, decodeErr = decodeStoredKeyPackage(document)
		return nil
	}); err != nil {
		return nil, ErrProtectedMemory.Wrap(err)
	}
	if decodeErr != nil {
		return nil, decodeErr
	}

	return stored, nil
}

// decodeStoredKeyPackage decodes a key-package document held in protected
// memory. document must not be retained: it belongs to an open enclave.
func decodeStoredKeyPackage(document []byte) (*StoredKeyPackage, error) {
	// Decode and validate the public members first; the share member is skipped, not copied.
	var public storedKeyPackagePublic
	if err := json.Unmarshal(document, &public); err != nil {
		return nil, ErrUnmarshalJSON.Wrap(err)
	}

	encoded, err := jsonStringMember(document, shareMember)
	if err != nil {
		if errors.Is(err, errJSONMemberMissing) {
			return nil, ErrMissingSecretShare
		}
		return nil, ErrUnmarshalJSON.Wrap(err)
	}
	if len(encoded) == 0 {
		return nil, ErrMissingSecretShare
	}

	// Decode into a protected buffer, destroyed on failure; the base64 error quotes input, so it is dropped.
	protected, err := secmem.NewSecret(base64.StdEncoding.DecodedLen(len(encoded)), func(dst []byte) (int, error) {
		n, err := base64.StdEncoding.Decode(dst, encoded)
		if err != nil {
			return 0, errShareNotBase64
		}
		return n, nil
	})
	if err != nil {
		if errors.Is(err, secmem.ErrEmptySecret) {
			return nil, ErrMissingSecretShare
		}
		return nil, ErrUnmarshalJSON.Wrap(err)
	}

	return &StoredKeyPackage{
		Identifier:           public.Identifier,
		SecretShareProtected: protected,
		GroupPublicKey:       public.GroupPublicKey,
		VerificationShares:   public.VerificationShares,
		Metadata:             public.Metadata,
	}, nil
}

// splitAfterFirstMember splits a JSON object just past its first member's value; malformed input is rejected.
func splitAfterFirstMember(document []byte) (head, tail []byte, err error) {
	if len(document) < 2 || document[0] != '{' || document[len(document)-1] != '}' {
		return nil, nil, errMalformedDocument
	}

	i := skipJSONSpace(document, 1)
	if i >= len(document) || document[i] != '"' {
		// An empty object has no member to splice the share in after.
		return nil, nil, errMalformedDocument
	}

	_, _, next, _, err := scanJSONString(document, i)
	if err != nil {
		return nil, nil, err
	}

	i = skipJSONSpace(document, next)
	if i >= len(document) || document[i] != ':' {
		return nil, nil, errMalformedDocument
	}

	i, err = skipJSONValue(document, i+1)
	if err != nil {
		return nil, nil, err
	}

	i = skipJSONSpace(document, i)
	if i >= len(document) || (document[i] != ',' && document[i] != '}') {
		return nil, nil, errMalformedDocument
	}

	return document[:i], document[i:], nil
}

// jsonStringMember returns a sub-slice of a unique, unescaped top-level string member; duplicates and escaped names or values are rejected.
func jsonStringMember(document []byte, name string) ([]byte, error) {
	i := skipJSONSpace(document, 0)
	if i >= len(document) || document[i] != '{' {
		return nil, errJSONMalformed
	}

	i = skipJSONSpace(document, i+1)
	if i < len(document) && document[i] == '}' {
		return nil, errJSONMemberMissing
	}

	var value []byte
	found := false

	for {
		keyStart, keyEnd, next, keyEscaped, err := scanJSONString(document, i)
		if err != nil {
			return nil, err
		}

		i = skipJSONSpace(document, next)
		if i >= len(document) || document[i] != ':' {
			return nil, errJSONMalformed
		}
		i = skipJSONSpace(document, i+1)
		if i >= len(document) {
			return nil, errJSONMalformed
		}

		// An escaped name is rejected wholesale rather than skipped: skipping
		// it is what would let a second, escaped copy of the target member
		// slip past the duplicate check above.
		if keyEscaped {
			return nil, errJSONEscapedKey
		}

		if string(document[keyStart:keyEnd]) == name {
			if found {
				return nil, errJSONDuplicateMember
			}
			switch {
			case document[i] == '"':
				valueStart, valueEnd, _, valueEscaped, err := scanJSONString(document, i)
				if err != nil {
					return nil, err
				}
				if valueEscaped {
					return nil, errJSONEscapedValue
				}
				value = document[valueStart:valueEnd]
			case bytes.HasPrefix(document[i:], jsonNull):
				// A null member carries no value, which is what an absent one
				// carries too - and what encoding/json left a []byte field as.
				value = nil
			default:
				return nil, errJSONNotString
			}
			found = true
		}

		i, err = skipJSONValue(document, i)
		if err != nil {
			return nil, err
		}

		i = skipJSONSpace(document, i)
		if i >= len(document) {
			return nil, errJSONMalformed
		}
		switch document[i] {
		case ',':
			i = skipJSONSpace(document, i+1)
		case '}':
			if !found {
				return nil, errJSONMemberMissing
			}
			return value, nil
		default:
			return nil, errJSONMalformed
		}
	}
}

// skipJSONSpace returns the index of the first byte at or after i that is not
// JSON whitespace, or len(document) if there is none.
func skipJSONSpace(document []byte, i int) int {
	for i < len(document) {
		switch document[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// scanJSONString scans the JSON string starting at document[i], which must be
// its opening quote. It returns the bounds of the string's contents, the index
// just past its closing quote, and whether the contents contain an escape.
func scanJSONString(document []byte, i int) (start, end, next int, escaped bool, err error) {
	if i >= len(document) || document[i] != '"' {
		return 0, 0, 0, false, errJSONMalformed
	}

	start = i + 1
	for j := start; j < len(document); j++ {
		switch document[j] {
		case '\\':
			// Skip the escaped byte along with the backslash. The remaining
			// bytes of a \uXXXX escape are hex digits, so neither a quote nor
			// a backslash can hide inside one.
			escaped = true
			j++
		case '"':
			return start, j, j + 1, escaped, nil
		}
	}

	return 0, 0, 0, false, errJSONMalformed
}

// skipJSONValue returns the index just past the JSON value starting at
// document[i].
func skipJSONValue(document []byte, i int) (int, error) {
	i = skipJSONSpace(document, i)
	if i >= len(document) {
		return 0, errJSONMalformed
	}

	switch document[i] {
	case '"':
		_, _, next, _, err := scanJSONString(document, i)
		return next, err

	case '{', '[':
		// Track nesting depth, skipping strings; the document is already valid JSON.
		depth := 0
		for i < len(document) {
			switch document[i] {
			case '"':
				_, _, next, _, err := scanJSONString(document, i)
				if err != nil {
					return 0, err
				}
				i = next
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, nil
				}
			}
			i++
		}
		return 0, errJSONMalformed

	default:
		// A number or one of true, false, null: it ends at the first byte that
		// cannot belong to it.
		for j := i; j < len(document); j++ {
			switch document[j] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				if j == i {
					return 0, errJSONMalformed
				}
				return j, nil
			}
		}
		return 0, errJSONMalformed
	}
}
