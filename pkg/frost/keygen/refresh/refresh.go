// Package refresh implements key refresh for FROST.
//
// Key refresh allows participants to update their secret shares without changing
// the group public key. This is useful for:
//   - Proactive security: Periodically refreshing shares limits the window
//     of vulnerability if a share is compromised
//   - Adding/removing participants: Combined with share redistribution
//
// The refresh process works by adding shares of a "zero" polynomial to each
// participant's existing share. Since the polynomial evaluates to zero at x=0,
// the sum of all a_0 coefficients remains unchanged, preserving the group secret.
//
// Two approaches are supported:
//  1. Trusted Dealer Refresh: A trusted party generates and distributes refresh shares
//  2. DKG-Based Refresh: Participants jointly generate refresh shares (more secure)
package refresh

import (
	"runtime"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/dkg"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// RefreshShare represents a refresh share that will be added to a participant's
// existing signing share.
type RefreshShare struct {
	// Identifier is the participant's identifier
	Identifier frost.Identifier

	// Share is the refresh value to add to the existing signing share
	Share group.Scalar

	// Commitment is the VSS commitment for verification
	Commitment []group.Element
}

// Zeroize securely erases the refresh share from memory.
//
// This method should be called after the refresh share has been applied
// to reduce the risk of memory disclosure attacks.
func (rs *RefreshShare) Zeroize() {
	runtime.KeepAlive(rs.Share)
	if rs.Share != nil {
		bytes := rs.Share.Bytes()
		secmem.ZeroBytes(bytes)
		rs.Share = rs.Share.Sub(rs.Share)
	}
	runtime.KeepAlive(rs.Share)
}

// ComputeRefreshingShares generates refresh shares using a trusted dealer.
//
// This creates shares of a polynomial with zero constant term, meaning the
// sum of all refreshed shares evaluates to the same group secret.
//
// Inputs:
//   - currentPublicKeyPackage: The current group's public key package
//   - maxSigners: Total number of participants
//   - minSigners: Threshold required to sign
//   - identifiers: Participant identifiers to generate refresh shares for
//   - suite: The ciphersuite to use
//
// Outputs:
//   - refreshShares: One refresh share per participant
//   - newPublicKeyPackage: Updated public key package with new verifying shares
//
// Note: The VerifyingKey in the new PublicKeyPackage should be identical to the old one.
func ComputeRefreshingShares(
	currentPublicKeyPackage *dkg.PublicKeyPackage,
	maxSigners, minSigners uint32,
	identifiers []frost.Identifier,
	suite ciphersuite.Ciphersuite,
) ([]RefreshShare, *dkg.PublicKeyPackage, error) {
	if currentPublicKeyPackage == nil {
		return nil, nil, frost.NewParameterError("currentPublicKeyPackage", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(identifiers) == 0 {
		return nil, nil, frost.NewParameterError("identifiers", "cannot be empty", frost.ErrInvalidParameters)
	}

	if minSigners < 2 {
		return nil, nil, frost.NewParameterError("minSigners", "must be at least 2", frost.ErrInvalidThreshold)
	}

	if minSigners > maxSigners {
		return nil, nil, frost.NewParameterError("minSigners", "cannot exceed maxSigners", frost.ErrInvalidThreshold)
	}

	grp := suite.Group()
	polyHelper := helpers.NewPolynomialHelper(grp)

	// Generate polynomial with zero constant term
	// f(x) = 0 + a_1*x + a_2*x^2 + ... + a_(t-1)*x^(t-1)
	coefficients := make([]group.Scalar, minSigners)

	// First coefficient is zero
	coefficients[0] = grp.NewScalar() // Zero scalar

	// Generate random coefficients for the rest
	for i := uint32(1); i < minSigners; i++ {
		scalar, err := grp.RandomScalar()
		if err != nil {
			return nil, nil, frost.NewParameterError("coefficients", "failed to generate random coefficient", err)
		}
		coefficients[i] = scalar
	}

	// Compute commitments to coefficients
	// Note: commitment[0] will be identity element (g^0 = 1)
	commitment := make([]group.Element, minSigners)
	for i, coeff := range coefficients {
		commitment[i] = grp.ScalarBaseMult(coeff)
	}

	// Generate refresh shares for each participant
	refreshShares := make([]RefreshShare, len(identifiers))
	newVerifyingShares := make(map[frost.Identifier]group.Element)

	for i, id := range identifiers {
		// Convert identifier to scalar
		idScalar, err := helpers.IdentifierToScalar(grp, id)
		if err != nil {
			return nil, nil, frost.NewParticipantError(id, "failed to convert ID to scalar", err)
		}

		// Evaluate polynomial at participant ID
		poly := frost.Polynomial{Coefficients: coefficients}
		share := polyHelper.Evaluate(poly, idScalar)

		// Create refresh share (skipping first commitment since it's identity)
		refreshShares[i] = RefreshShare{
			Identifier: id,
			Share:      share,
			Commitment: commitment[1:], // Skip the identity commitment
		}

		// Compute new verifying share by adding refresh commitment to old
		oldVerifyingShare, ok := currentPublicKeyPackage.VerifyingShares[id]
		if !ok {
			return nil, nil, frost.NewParticipantError(id, "not found in current public key package", frost.ErrInvalidParticipant)
		}

		// Compute refresh verifying share (evaluation of commitment polynomial at id)
		refreshVerifyingShare := evaluateCommitmentPolynomial(commitment, idScalar, grp)

		// New verifying share = old + refresh
		newVerifyingShares[id] = oldVerifyingShare.Add(refreshVerifyingShare)
	}

	// The group public key remains unchanged (since we added g^0 = identity)
	newPublicKeyPackage := &dkg.PublicKeyPackage{
		VerifyingShares: newVerifyingShares,
		VerifyingKey:    currentPublicKeyPackage.VerifyingKey,
	}

	return refreshShares, newPublicKeyPackage, nil
}

// ApplyRefreshShare applies a refresh share to update a participant's key package.
//
// This adds the refresh share to the existing signing share and updates the
// verifying share accordingly.
//
// Inputs:
//   - refreshShare: The refresh share received from the dealer
//   - currentKeyPackage: The participant's current key package
//   - suite: The ciphersuite to use
//
// Outputs:
//   - newKeyPackage: Updated key package with refreshed shares
//
// Note: The GroupPublicKey in the new KeyPackage should be identical to the old one.
func ApplyRefreshShare(
	refreshShare RefreshShare,
	currentKeyPackage *frost.KeyPackage,
	suite ciphersuite.Ciphersuite,
) (*frost.KeyPackage, error) {
	if currentKeyPackage == nil {
		return nil, frost.NewParameterError("currentKeyPackage", "cannot be nil", frost.ErrInvalidParameters)
	}

	if refreshShare.Share == nil {
		return nil, frost.NewParameterError("refreshShare", "share cannot be nil", frost.ErrInvalidParameters)
	}

	if refreshShare.Identifier != currentKeyPackage.Identifier {
		return nil, frost.NewParameterError("refreshShare", "identifier mismatch", frost.ErrInvalidParticipant)
	}

	grp := suite.Group()

	// Verify the refresh share (optional but recommended)
	// For this, we need to add identity to the beginning of the commitment
	fullCommitment := make([]group.Element, len(refreshShare.Commitment)+1)
	fullCommitment[0] = grp.Identity()
	copy(fullCommitment[1:], refreshShare.Commitment)

	idScalar, err := helpers.IdentifierToScalar(grp, refreshShare.Identifier)
	if err != nil {
		return nil, frost.NewParameterError("identifier", "failed to convert to scalar", err)
	}

	// Verify share
	left := grp.ScalarBaseMult(refreshShare.Share)
	right := evaluateCommitmentPolynomial(fullCommitment, idScalar, grp)
	if !left.Equal(right) {
		return nil, frost.NewVerificationError("refreshShare", "invalid refresh share", frost.ErrInvalidKeyShare)
	}

	// Compute new signing share
	newSigningShare := currentKeyPackage.SecretShare.Add(refreshShare.Share)

	// Compute new verifying share
	newVerifyingShare := grp.ScalarBaseMult(newSigningShare)

	// Update verification shares in the package
	newVerificationShares := make([]frost.VerificationShare, len(currentKeyPackage.VerificationShares))
	for i, vs := range currentKeyPackage.VerificationShares {
		if vs.Identifier == refreshShare.Identifier {
			newVerificationShares[i] = frost.VerificationShare{
				Identifier:      vs.Identifier,
				VerificationKey: newVerifyingShare,
			}
		} else {
			newVerificationShares[i] = vs
		}
	}

	// Create new key package
	return &frost.KeyPackage{
		Identifier:         currentKeyPackage.Identifier,
		SecretShare:        newSigningShare,
		GroupPublicKey:     currentKeyPackage.GroupPublicKey, // Unchanged
		VerificationShares: newVerificationShares,
		MinSigners:         currentKeyPackage.MinSigners, // Unchanged
		MaxSigners:         currentKeyPackage.MaxSigners, // Unchanged
	}, nil
}

// evaluateCommitmentPolynomial evaluates the commitment polynomial at point x.
// Returns: product(commitment[k]^(x^k)) for k=0..t-1
func evaluateCommitmentPolynomial(commitment []group.Element, x group.Scalar, grp group.Group) group.Element {
	// Start with identity
	result := grp.Identity()

	// Create scalar 1
	oneBytes := make([]byte, grp.ScalarLength())
	if grp.ByteOrder() == group.BigEndian {
		oneBytes[len(oneBytes)-1] = 1
	} else {
		oneBytes[0] = 1
	}
	xPower, _ := grp.DeserializeScalar(oneBytes)
	secmem.ZeroBytes(oneBytes)

	for _, c := range commitment {
		// Compute commitment[k]^(x^k)
		term := grp.ScalarMult(c, xPower)

		// Add to result
		result = result.Add(term)

		// Update x^k for next iteration
		xPower = xPower.Mul(x)
	}

	return result
}
