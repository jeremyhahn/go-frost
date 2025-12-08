// Package serialization provides versioned serialization for FROST data structures.
//
// All serialized data includes a header with version and ciphersuite information
// to ensure compatibility and proper deserialization.
package serialization

import (
	"encoding/binary"
	"errors"
)

// Version constants
const (
	// CurrentVersion is the current serialization format version
	CurrentVersion uint8 = 1

	// HeaderSize is the size of the serialization header in bytes
	HeaderSize = 8
)

// Header contains metadata about serialized data.
type Header struct {
	// Version is the serialization format version
	Version uint8

	// CiphersuiteID identifies the ciphersuite used (4 bytes)
	CiphersuiteID uint32

	// DataType identifies the type of serialized data
	DataType DataType

	// Reserved for future use
	Reserved uint16
}

// DataType identifies the type of serialized data
type DataType uint8

const (
	// DataTypeUnknown represents unknown data
	DataTypeUnknown DataType = iota

	// DataTypeSigningNonces represents serialized SigningNonces
	DataTypeSigningNonces

	// DataTypeSigningCommitments represents serialized SigningCommitments
	DataTypeSigningCommitments

	// DataTypeKeyPackage represents serialized KeyPackage
	DataTypeKeyPackage

	// DataTypeSignature represents serialized Signature
	DataTypeSignature

	// DataTypePublicKey represents serialized public key
	DataTypePublicKey

	// DataTypeSecretShare represents serialized secret share
	DataTypeSecretShare

	// DataTypeSignatureShare represents serialized signature share
	DataTypeSignatureShare
)

// String returns a human-readable name for the data type
func (dt DataType) String() string {
	switch dt {
	case DataTypeSigningNonces:
		return "SigningNonces"
	case DataTypeSigningCommitments:
		return "SigningCommitments"
	case DataTypeKeyPackage:
		return "KeyPackage"
	case DataTypeSignature:
		return "Signature"
	case DataTypePublicKey:
		return "PublicKey"
	case DataTypeSecretShare:
		return "SecretShare"
	case DataTypeSignatureShare:
		return "SignatureShare"
	default:
		return "Unknown"
	}
}

// Errors
var (
	ErrInvalidHeader       = errors.New("invalid serialization header")
	ErrVersionMismatch     = errors.New("serialization version mismatch")
	ErrCiphersuiteMismatch = errors.New("ciphersuite mismatch")
	ErrDataTypeMismatch    = errors.New("data type mismatch")
	ErrInvalidData         = errors.New("invalid serialized data")
)

// NewHeader creates a new serialization header.
func NewHeader(ciphersuiteID uint32, dataType DataType) Header {
	return Header{
		Version:       CurrentVersion,
		CiphersuiteID: ciphersuiteID,
		DataType:      dataType,
		Reserved:      0,
	}
}

// Serialize encodes the header to bytes.
func (h Header) Serialize() []byte {
	data := make([]byte, HeaderSize)
	data[0] = h.Version
	binary.BigEndian.PutUint32(data[1:5], h.CiphersuiteID)
	data[5] = byte(h.DataType)
	binary.BigEndian.PutUint16(data[6:8], h.Reserved)
	return data
}

// DeserializeHeader decodes a header from bytes.
func DeserializeHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, ErrInvalidHeader
	}

	return Header{
		Version:       data[0],
		CiphersuiteID: binary.BigEndian.Uint32(data[1:5]),
		DataType:      DataType(data[5]),
		Reserved:      binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

// Validate checks if the header is valid for the expected parameters.
func (h Header) Validate(expectedCiphersuiteID uint32, expectedDataType DataType) error {
	if h.Version != CurrentVersion {
		return ErrVersionMismatch
	}
	if h.CiphersuiteID != expectedCiphersuiteID {
		return ErrCiphersuiteMismatch
	}
	if h.DataType != expectedDataType {
		return ErrDataTypeMismatch
	}
	return nil
}

// CiphersuiteIDFromString converts a ciphersuite ID string to a uint32.
// Uses a simple hash of the string for a compact representation.
func CiphersuiteIDFromString(id string) uint32 {
	// Simple hash for compact representation
	var h uint32
	for _, c := range id {
		h = h*31 + uint32(c)
	}
	return h
}
