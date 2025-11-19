package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// GroupCommitmentComputer computes the group commitment from participant commitments.
type GroupCommitmentComputer interface {
	// Compute calculates the group commitment point from the commitment list.
	//
	// Inputs:
	// - commitmentList: Sorted list of participant commitments
	// - bindingFactors: List of binding factors for each participant
	//
	// Outputs:
	// - groupCommitment: The aggregated group commitment point
	//
	// The group commitment is computed as:
	// sum_{i in participants} (hiding_nonce_commitment_i + binding_factor_i * binding_nonce_commitment_i)
	Compute(commitmentList frost.CommitmentList, bindingFactors frost.BindingFactorList) (group.Element, error)
}

// NewGroupCommitmentComputer creates a new group commitment computer.
func NewGroupCommitmentComputer(grp group.Group) GroupCommitmentComputer {
	return &groupCommitmentComputer{group: grp}
}

type groupCommitmentComputer struct {
	group group.Group
}

// Compute implements GroupCommitmentComputer.Compute
//
// Calculates the group commitment point from the commitment list and binding factors.
// The group commitment is computed as:
// sum_{i in participants} (hiding_nonce_commitment_i + binding_factor_i * binding_nonce_commitment_i)
//
// Algorithm (from RFC 9591 Section 4.5):
// 1. Initialize group_commitment = Identity
// 2. For each participant in commitment_list:
//    a. Get binding_factor for participant
//    b. Compute binding_nonce = binding_factor * binding_nonce_commitment
//    c. Compute commitment = hiding_nonce_commitment + binding_nonce
//    d. Add commitment to group_commitment
// 3. Return group_commitment
func (g *groupCommitmentComputer) Compute(commitmentList frost.CommitmentList, bindingFactors frost.BindingFactorList) (group.Element, error) {
	if len(commitmentList) == 0 {
		return nil, frost.ErrEmptyCommitmentList
	}

	if len(bindingFactors) == 0 {
		return nil, frost.NewParameterError("bindingFactors", "cannot be empty", frost.ErrInvalidParameters)
	}

	// 1. Initialize group_commitment = Identity
	groupCommitment := g.group.Identity()

	// 2. For each participant in commitment_list
	for _, commitment := range commitmentList {
		// a. Get binding_factor for participant
		var bindingFactor group.Scalar
		found := false
		for _, bf := range bindingFactors {
			if bf.Identifier == commitment.Identifier {
				bindingFactor = bf.BindingFactor
				found = true
				break
			}
		}

		if !found {
			return nil, frost.NewParticipantError(commitment.Identifier, "binding factor not found", frost.ErrInvalidBindingFactor)
		}

		// b. Compute binding_nonce = binding_factor * binding_nonce_commitment
		bindingNonce := g.group.ScalarMult(commitment.BindingNonceCommitment, bindingFactor)

		// c. Compute commitment = hiding_nonce_commitment + binding_nonce
		participantCommitment := commitment.HidingNonceCommitment.Add(bindingNonce)

		// d. Add commitment to group_commitment
		groupCommitment = groupCommitment.Add(participantCommitment)
	}

	// 3. Return group_commitment
	return groupCommitment, nil
}
