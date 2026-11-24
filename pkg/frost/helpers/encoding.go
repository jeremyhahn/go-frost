package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// CommitmentListEncoder encodes commitment lists for hashing.
type CommitmentListEncoder interface {
	// Encode serializes identifier || hiding || binding commitments for each participant.
	Encode(commitmentList frost.CommitmentList) ([]byte, error)

	// GetParticipants returns the identifiers in a commitment list.
	GetParticipants(commitmentList frost.CommitmentList) []frost.Identifier

	// ValidateCommitmentList rejects an empty, unsorted or duplicate commitment list.
	ValidateCommitmentList(commitmentList frost.CommitmentList) error
}

// NewCommitmentListEncoder creates a new commitment list encoder.
func NewCommitmentListEncoder(grp group.Group) CommitmentListEncoder {
	return &commitmentListEncoder{group: grp}
}

type commitmentListEncoder struct {
	group group.Group
}

// Encode implements CommitmentListEncoder.Encode.
func (e *commitmentListEncoder) Encode(commitmentList frost.CommitmentList) ([]byte, error) {
	if len(commitmentList) == 0 {
		return []byte{}, nil
	}

	// Calculate total size
	scalarLen := e.group.ScalarLength()
	elemLen := e.group.ElementLength()
	totalLen := len(commitmentList) * (scalarLen + 2*elemLen)

	result := make([]byte, 0, totalLen)

	// Determine byte order based on group
	useBigEndian := e.group.ByteOrder() == group.BigEndian

	// Encode each commitment
	for _, commitment := range commitmentList {
		// a. Serialize identifier as scalar
		// Create a scalar from the identifier
		identifierBytes := make([]byte, scalarLen)
		id := uint32(commitment.Identifier)

		if useBigEndian {
			// Big-endian encoding
			identifierBytes[scalarLen-1] = byte(id)
			identifierBytes[scalarLen-2] = byte(id >> 8)
			identifierBytes[scalarLen-3] = byte(id >> 16)
			identifierBytes[scalarLen-4] = byte(id >> 24)
		} else {
			// Little-endian encoding (Ed25519, Ed448, ristretto255)
			for j := 0; j < 4 && j < len(identifierBytes); j++ {
				identifierBytes[j] = byte(id >> (8 * j))
			}
		}

		result = append(result, identifierBytes...)

		// b. Serialize hiding_nonce_commitment
		hidingBytes := commitment.HidingNonceCommitment.Bytes()
		result = append(result, hidingBytes...)

		// c. Serialize binding_nonce_commitment
		bindingBytes := commitment.BindingNonceCommitment.Bytes()
		result = append(result, bindingBytes...)
	}

	return result, nil
}

// GetParticipants implements CommitmentListEncoder.GetParticipants
//
// Extracts the list of participant identifiers from a commitment list.
func (e *commitmentListEncoder) GetParticipants(commitmentList frost.CommitmentList) []frost.Identifier {
	if len(commitmentList) == 0 {
		return []frost.Identifier{}
	}

	identifiers := make([]frost.Identifier, len(commitmentList))
	for i, commitment := range commitmentList {
		identifiers[i] = commitment.Identifier
	}

	return identifiers
}

// ValidateCommitmentList implements CommitmentListEncoder.ValidateCommitmentList.
func (e *commitmentListEncoder) ValidateCommitmentList(commitmentList frost.CommitmentList) error {
	// 1. Check if list is empty
	if len(commitmentList) == 0 {
		return frost.ErrEmptyCommitmentList
	}

	// 2. Check if list is sorted by identifier and check for duplicates
	for i := 1; i < len(commitmentList); i++ {
		if commitmentList[i].Identifier <= commitmentList[i-1].Identifier {
			if commitmentList[i].Identifier == commitmentList[i-1].Identifier {
				return frost.ErrDuplicateParticipant
			}
			return frost.ErrUnsortedCommitments
		}
	}

	return nil
}

// IdentifierToScalar encodes an identifier as a scalar in the group's byte order (big-endian for P-256 and secp256k1, little-endian otherwise).
func IdentifierToScalar(grp group.Group, id frost.Identifier) (group.Scalar, error) {
	idBytes := make([]byte, grp.ScalarLength())
	idVal := uint32(id)

	// Determine byte order based on group
	if grp.ByteOrder() == group.BigEndian {
		// Big-endian encoding
		scalarLen := grp.ScalarLength()
		idBytes[scalarLen-1] = byte(idVal)
		idBytes[scalarLen-2] = byte(idVal >> 8)
		idBytes[scalarLen-3] = byte(idVal >> 16)
		idBytes[scalarLen-4] = byte(idVal >> 24)
	} else {
		// Little-endian encoding (Ed25519, Ed448, ristretto255)
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idVal >> (8 * j))
		}
	}

	scalar, err := grp.DeserializeScalar(idBytes)
	secmem.ZeroBytes(idBytes)
	return scalar, err
}
