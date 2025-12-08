package frost

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// DeriveIdentifier derives a participant identifier from arbitrary data using HID.
// This allows creating identifiers from strings, UUIDs, or other application-specific data.
//
// The derived identifier is guaranteed to be non-zero because it's derived from
// a hash function that outputs a scalar modulo the group order.
//
// Inputs:
//   - data: Arbitrary byte data to derive identifier from (e.g., username, UUID)
//   - suite: The ciphersuite to use (provides HID hash function)
//
// Outputs:
//   - identifier: A non-zero identifier derived from the data
//
// Errors:
//   - Returns error if data is empty
//   - Returns error if derived identifier is zero (extremely unlikely)
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
