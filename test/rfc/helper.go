package rfc

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// scalarFromUint64 creates a Scalar from a uint64 value.
// This is a helper function for test code.
func scalarFromUint64(grp group.Group, value uint64) group.Scalar {
	bytes := make([]byte, grp.ScalarLength())
	binary.LittleEndian.PutUint64(bytes, value)
	scalar, err := grp.DeserializeScalar(bytes)
	if err != nil {
		panic(err)
	}
	return scalar
}

// participantIDsSequential creates a sequential list of participant IDs from 1 to count.
func participantIDsSequential(count int) []frost.Identifier {
	ids := make([]frost.Identifier, count)
	for i := 0; i < count; i++ {
		ids[i] = frost.Identifier(i + 1)
	}
	return ids
}
