package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// GroupCommitmentComputer computes the group commitment from participant commitments.
type GroupCommitmentComputer interface {
	// Compute returns the group commitment sum(hiding_i + binding_factor_i * binding_i).
	Compute(commitmentList frost.CommitmentList, bindingFactors frost.BindingFactorList) (group.Element, error)
}

// NewGroupCommitmentComputer creates a new group commitment computer.
func NewGroupCommitmentComputer(grp group.Group) GroupCommitmentComputer {
	return &groupCommitmentComputer{group: grp}
}

type groupCommitmentComputer struct {
	group group.Group
}

// Compute implements GroupCommitmentComputer.Compute per RFC 9591 Section 4.5.
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
		// Security check: Verify commitments are not the identity element
		// RFC 9591 requires that nonce commitments are not the identity,
		// as this would leak information about the secret shares.
		if commitment.HidingNonceCommitment == nil || commitment.HidingNonceCommitment.IsIdentity() {
			return nil, frost.NewParticipantError(commitment.Identifier,
				"hiding nonce commitment is identity element", frost.ErrIdentityElement)
		}
		if commitment.BindingNonceCommitment == nil || commitment.BindingNonceCommitment.IsIdentity() {
			return nil, frost.NewParticipantError(commitment.Identifier,
				"binding nonce commitment is identity element", frost.ErrIdentityElement)
		}

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
