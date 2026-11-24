package frost

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// DeriveIdentifier derives a non-zero participant identifier from non-empty data with the suite's HID hash.
func DeriveIdentifier(data []byte, suite ciphersuite.Ciphersuite) (Identifier, error) {
	if len(data) == 0 {
		return 0, NewParameterError("data", "cannot be empty", ErrInvalidParameters)
	}

	// Use HID to hash the data to a scalar
	scalar := suite.HID(data)

	// Convert scalar to bytes
	scalarBytes := scalar.Bytes()

	// Take the first 4 bytes as the identifier (truncation is safe for identifiers)
	// We use the last 4 bytes for big-endian groups, first 4 for little-endian
	grp := suite.Group()
	var id uint32
	if grp.ByteOrder() == group.BigEndian {
		// For big-endian groups, take last 4 bytes
		offset := len(scalarBytes) - 4
		if offset < 0 {
			offset = 0
		}
		id = binary.BigEndian.Uint32(scalarBytes[offset:])
	} else {
		// For little-endian groups, take first 4 bytes
		id = binary.LittleEndian.Uint32(scalarBytes[:4])
	}

	// Ensure non-zero (extremely unlikely to be zero from hash output)
	if id == 0 {
		// If we somehow got zero, just use 1
		id = 1
	}

	return Identifier(id), nil
}

// DeriveIdentifierFromString is a convenience function that derives an identifier from a string.
func DeriveIdentifierFromString(s string, suite ciphersuite.Ciphersuite) (Identifier, error) {
	return DeriveIdentifier([]byte(s), suite)
}

// MustDeriveIdentifier derives an identifier and panics on error.
// Only use this in contexts where errors are truly unexpected (e.g., tests).
func MustDeriveIdentifier(data []byte, suite ciphersuite.Ciphersuite) Identifier {
	id, err := DeriveIdentifier(data, suite)
	if err != nil {
		panic(err)
	}
	return id
}
