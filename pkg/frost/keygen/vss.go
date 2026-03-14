package keygen

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// VSS implements Verifiable Secret Sharing operations.
type VSS interface {
	// CreateCommitments creates verification shares (commitments) from a polynomial.
	//
	// Inputs:
	// - polynomial: The secret sharing polynomial
	//
	// Outputs:
	// - commitments: List of commitments to polynomial coefficients
	//
	// For each coefficient c_j, computes verification_share_j = ScalarBaseMult(c_j)
	CreateCommitments(polynomial frost.Polynomial) ([]frost.VerificationShare, error)

	// VerifyShare verifies a secret share against verification shares.
	//
	// Inputs:
	// - identifier: The participant's identifier
	// - share: The secret share to verify
	// - commitments: The verification shares
	//
	// Outputs:
	// - valid: True if verification succeeds
	//
	// Verifies: ScalarBaseMult(share) == sum_{j=0}^{degree} commitment_j * identifier^j
	VerifyShare(identifier frost.Identifier, share group.Scalar, commitments []frost.VerificationShare) error

	// CombineShares combines multiple secret shares into a single share.
	// This is used in distributed key generation scenarios.
	//
	// Inputs:
	// - shares: List of secret shares to combine
	//
	// Outputs:
	// - combinedShare: The sum of all input shares
	CombineShares(shares []group.Scalar) (group.Scalar, error)
}

// NewVSS creates a new VSS implementation.
func NewVSS(grp group.Group) VSS {
	return &vss{
		group: grp,
	}
}

type vss struct {
	group group.Group
}

// CreateCommitments implements VSS.CreateCommitments
func (v *vss) CreateCommitments(polynomial frost.Polynomial) ([]frost.VerificationShare, error) {
	if len(polynomial.Coefficients) == 0 {
		return nil, frost.NewParameterError("polynomial", "cannot be empty", frost.ErrInvalidPolynomial)
	}

	commitments := make([]frost.VerificationShare, len(polynomial.Coefficients))
	for i, coefficient := range polynomial.Coefficients {
		commitment := v.group.ScalarBaseMult(coefficient)
		commitments[i] = frost.VerificationShare{
			Identifier:      frost.Identifier(i),
			VerificationKey: commitment,
		}
	}

	return commitments, nil
}

// VerifyShare implements VSS.VerifyShare
func (v *vss) VerifyShare(identifier frost.Identifier, share group.Scalar, commitments []frost.VerificationShare) error {
	if identifier == 0 {
		return frost.NewParameterError("identifier", "cannot be zero", frost.ErrInvalidParticipant)
	}

	if len(commitments) == 0 {
		return frost.NewParameterError("commitments", "cannot be empty", frost.ErrInvalidParameters)
	}

	if commitments == nil {
		return frost.NewParameterError("commitments", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Compute left side: ScalarBaseMult(share)
	left := v.group.ScalarBaseMult(share)

	// Compute right side: sum_{j=0}^{degree} commitment_j * identifier^j
	right := v.group.Identity()

	// Convert identifier to scalar using group-specific byte ordering
	idScalar, err := helpers.IdentifierToScalar(v.group, identifier)
	if err != nil {
		return frost.NewParameterError("identifier", "failed to convert to scalar", err)
	}

	// Compute identifier^j for each term
	// Start with id^0 = 1 (use IdentifierToScalar for consistent encoding)
	idPower, _ := helpers.IdentifierToScalar(v.group, frost.Identifier(1))

	for j := 0; j < len(commitments); j++ {
		// term = commitment[j] * identifier^j
		term := v.group.ScalarMult(commitments[j].VerificationKey, idPower)
		right = right.Add(term)

		// Update power for next iteration: identifier^(j+1) = identifier^j * identifier
		if j < len(commitments)-1 {
			idPower = idPower.Mul(idScalar)
		}
	}

	// Verify left == right
	if !left.Equal(right) {
		return frost.NewVerificationError("share", "share verification failed", frost.ErrInvalidKeyShare)
	}

	return nil
}

// CombineShares implements VSS.CombineShares
func (v *vss) CombineShares(shares []group.Scalar) (group.Scalar, error) {
	if shares == nil {
		return nil, frost.NewParameterError("shares", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(shares) == 0 {
		return nil, frost.NewParameterError("shares", "cannot be empty", frost.ErrInvalidParameters)
	}

	// Initialize result to zero
	result := v.group.NewScalar()

	// Add all shares
	for _, share := range shares {
		result = result.Add(share)
	}

	return result, nil
}
