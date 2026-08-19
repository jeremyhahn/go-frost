package keystore

// wire.go implements the serialization boundary for stored key packages.
//
// A stored key package carries a secret share, so its serialized form is
// secret too - the document holds the share base64-encoded in plain sight.
// encoding/json cannot produce or consume such a document without leaving the
// share on the ordinary heap: Marshal assembles its result in a buffer drawn
// from a package-level sync.Pool, returns a second heap copy, and puts the
// buffer back in the pool with the plaintext still in it, out of reach of any
// zeroization this package could perform. Decoding a base64 member likewise
// allocates the decoded bytes on the heap.
//
// So the secret-bearing document is assembled inside protected memory instead,
// and read back the same way. encoding/json is still used - for the public
// half of the document, which carries no secret material, and to validate a
// document before its share is located. The wire format is exactly what
// encoding/json produced when the share was a plaintext field, so stores
// written by earlier versions read back unchanged.

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

// storedKeyPackagePublic is the half of a stored key package that carries no
// secret material, and so the only half encoding/json is allowed to see. Its
// fields mirror StoredKeyPackage's public fields in declaration order, which
// is the order they appear in the document.
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

	// The share member goes back exactly where encoding/json put it: after
	// Identifier, the member the struct declared before the share. head is
	// the document up to the end of that member, tail is everything after it,
	// starting at the comma or the closing brace. Neither holds secret
	// material.
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
	// The public members first. storedKeyPackagePublic has no share field, so
	// the decoder skips the share member without ever decoding its value - the
	// share is not copied here. This pass also validates the document, which
	// the scan below is entitled to assume.
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

	// Decode straight into a protected buffer. NewSecret destroys that buffer
	// on a failed decode, so a partially decoded share does not survive; the
	// base64 error itself is dropped for errShareNotBase64, since it quotes
	// the input it rejected.
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

// splitAfterFirstMember splits a JSON object just past its first member's
// value: head is the object up to and including that value, tail is the rest,
// beginning with the separating comma or with the closing brace when the
// member is the only one. Splicing a member in between the two puts it second,
// which is where encoding/json emitted the share while it was a plaintext
// field declared after Identifier.
//
// document is what json.Marshal produced for storedKeyPackagePublic, so it is
// a valid object with at least one member; anything else is rejected rather
// than spliced into something malformed.
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

// jsonStringMember returns the raw bytes of a top-level string member's value
// as a sub-slice of document rather than as a copy. Returning a copy is
// precisely what this file exists to avoid: document is protected memory, and
// a copy of a secret member would be the heap allocation encoding/json was
// replaced to prevent.
//
// The member must appear exactly once. encoding/json resolves a duplicate
// member to the last occurrence, so a document carrying two would decode its
// public and secret halves from different occurrences; such a document is
// rejected instead.
//
// No member name may carry a JSON escape, whichever member it belongs to.
// encoding/json unescapes names and this scan compares raw bytes, so
// "\u0053ecretShare" is a second SecretShare to the decoder and an unrelated
// member to the scan: the document would carry the share twice while looking
// to this function as though it carried it once, and the two parsers would
// disagree about which share it holds. Rejecting every escaped name closes
// that difference without an unescaping pass through the heap. Nothing this
// package writes has one - encoding/json escapes only <, > and & in strings,
// and the field names are plain ASCII.
//
// The value must not contain a JSON escape either. Base64 never produces one,
// so an escape means the member is not what this package wrote, and
// unescaping it would need a pass through the heap.
//
// document is expected to be valid JSON - decodeStoredKeyPackage validates it
// with encoding/json first - but the scan rejects what it does not understand
// rather than trusting that.
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
		// Track nesting depth, skipping over strings so that a brace or
		// bracket inside one is not mistaken for structure. Openers and
		// closers are not matched by kind; the document has already been
		// validated as JSON.
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
