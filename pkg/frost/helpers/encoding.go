package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// CommitmentListEncoder encodes commitment lists for hashing.
type CommitmentListEncoder interface {
	// Encode serializes a commitment list into a byte string.
	//
	// Inputs:
	// - commitmentList: Sorted list of participant commitments
	//
	// Outputs:
	// - encoded: The serialized representation
	//
	// The encoding concatenates for each participant:
	// identifier || hiding_nonce_commitment || binding_nonce_commitment
	Encode(commitmentList frost.CommitmentList) ([]byte, error)

	// GetParticipants extracts the list of participant identifiers from a commitment list.
	//
	// Inputs:
	// - commitmentList: List of participant commitments
	//
	// Outputs:
	// - identifiers: List of participant identifiers
	GetParticipants(commitmentList frost.CommitmentList) []frost.Identifier

	// ValidateCommitmentList validates that a commitment list is properly formatted.
	// The list must be sorted in ascending order by identifier.
	//
	// Inputs:
	// - commitmentList: List of participant commitments
	//
	// Errors:
	// - Returns error if list is empty
	// - Returns error if list is not sorted
	// - Returns error if list contains duplicates
	ValidateCommitmentList(commitmentList frost.CommitmentList) error
}

// NewCommitmentListEncoder creates a new commitment list encoder.
func NewCommitmentListEncoder(grp group.Group) CommitmentListEncoder {
	return &commitmentListEncoder{group: grp}
}

type commitmentListEncoder struct {
	group group.Group
}

// Encode implements CommitmentListEncoder.Encode
//
// Serializes a commitment list into a byte string by concatenating:
// identifier || hiding_nonce_commitment || binding_nonce_commitment
// for each participant in the list.
func (e *commitmentListEncoder) Encode(commitmentList frost.CommitmentList) ([]byte, error) {
	if len(commitmentList) == 0 {
		return []byte{}, nil
	}

	// Calculate total size
	scalarLen := e.group.ScalarLength()
	elemLen := e.group.ElementLength()
	totalLen := len(commitmentList) * (scalarLen + 2*elemLen)

	result := make([]byte, 0, totalLen)

	// Encode each commitment
	for _, commitment := range commitmentList {
		// a. Serialize identifier as scalar
		// Create a scalar from the identifier
		identifierBytes := make([]byte, scalarLen)
		// Encode as little-endian to match ristretto255 native format
		id := uint32(commitment.Identifier)
		for j := 0; j < 4 && j < len(identifierBytes); j++ {
			identifierBytes[j] = byte(id >> (8 * j))
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

// ValidateCommitmentList implements CommitmentListEncoder.ValidateCommitmentList
//
// Validates that a commitment list is properly formatted:
// - Must not be empty
// - Must be sorted in ascending order by identifier
// - Must not contain duplicate identifiers
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
