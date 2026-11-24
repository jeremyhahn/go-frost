// Package keygen implements key generation for FROST.
package keygen

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Reconstruct recovers the group secret from at least minSigners distinct shares by Lagrange interpolation; for key recovery only.
func Reconstruct(shares []ShareInput, suite ciphersuite.Ciphersuite) (group.Scalar, error) {
	if len(shares) == 0 {
		return nil, frost.NewParameterError("shares", "cannot be empty", frost.ErrInvalidParameters)
	}

	// Check for nil shares and duplicate identifiers
	seen := make(map[frost.Identifier]bool)
	for _, s := range shares {
		if s.Share == nil {
			return nil, frost.NewParameterError("shares", "contains nil share", frost.ErrInvalidParameters)
		}
		if seen[s.Identifier] {
			return nil, frost.NewParameterError("shares", "contains duplicate identifiers", frost.ErrDuplicateParticipant)
		}
		seen[s.Identifier] = true
	}

	grp := suite.Group()
	polyHelper := helpers.NewPolynomialHelper(grp)

	// Extract participant IDs and convert to scalars
	xCoords := make([]group.Scalar, len(shares))
	for i, s := range shares {
		idScalar, err := helpers.IdentifierToScalar(grp, s.Identifier)
		if err != nil {
			return nil, frost.NewParameterError("identifier", "failed to convert to scalar", err)
		}
		xCoords[i] = idScalar
	}

	// Use Lagrange interpolation to recover secret at x=0
	// secret = sum(share_i * lambda_i) where lambda_i is the Lagrange coefficient
	secret := grp.NewScalar()

	for i, s := range shares {
		// Compute Lagrange coefficient for this participant
		lambda, err := polyHelper.DeriveInterpolatingValue(xCoords, xCoords[i])
		if err != nil {
			return nil, frost.NewParticipantError(s.Identifier, "failed to compute Lagrange coefficient", err)
		}

		// Multiply share by Lagrange coefficient
		term := s.Share.Mul(lambda)

		// Add to accumulator
		secret = secret.Add(term)
	}

	return secret, nil
}

// VerifyReconstruction returns nil if g^secret equals groupPublicKey.
func VerifyReconstruction(secret group.Scalar, groupPublicKey group.Element, grp group.Group) error {
	if secret == nil {
		return frost.NewParameterError("secret", "cannot be nil", frost.ErrInvalidParameters)
	}
	if groupPublicKey == nil {
		return frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Compute g^secret
	computedPublicKey := grp.ScalarBaseMult(secret)

	// Compare with expected public key
	if !computedPublicKey.Equal(groupPublicKey) {
		return frost.NewVerificationError("secret", "reconstructed secret doesn't match group public key", frost.ErrInvalidKeyShare)
	}

	return nil
}
