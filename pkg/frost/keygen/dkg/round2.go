package dkg

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Part2 runs DKG round 2: verifies every proof of knowledge and computes the shares f_i(j) to send privately to each participant.
func Part2(
	secretPackage *Round1SecretPackage,
	round1Packages map[frost.Identifier]*Round1Package,
	suite ciphersuite.Ciphersuite,
) (*Round2SecretPackage, map[frost.Identifier]*Round2Package, error) {
	if secretPackage == nil {
		return nil, nil, frost.NewParameterError("secretPackage", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Validate that we received packages from all other participants
	expectedCount := int(secretPackage.MaxSigners - 1)
	if len(round1Packages) != expectedCount {
		return nil, nil, frost.NewParameterError("round1Packages",
			"wrong number of packages received", frost.ErrInsufficientParticipants)
	}

	grp := suite.Group()

	// Verify all proofs of knowledge
	for senderID, pkg := range round1Packages {
		// Validate commitment length
		if uint(len(pkg.Commitment)) != uint(secretPackage.MinSigners) {
			return nil, nil, frost.NewParticipantError(senderID,
				"invalid commitment length", frost.ErrInvalidCommitment)
		}

		// Verify the proof of knowledge
		if err := VerifyProofOfKnowledge(senderID, pkg, suite); err != nil {
			return nil, nil, err
		}
	}

	// Compute our own share: f_i(i)
	myIDScalar, err := helpers.IdentifierToScalar(grp, secretPackage.Identifier)
	if err != nil {
		return nil, nil, frost.NewParameterError("identifier", "failed to convert to scalar", err)
	}
	ownShare := evaluatePolynomial(secretPackage.Coefficients, myIDScalar, grp)

	// Compute shares for all other participants
	round2Packages := make(map[frost.Identifier]*Round2Package)

	for peerID := range round1Packages {
		// Convert peer ID to scalar
		peerIDScalar, err := helpers.IdentifierToScalar(grp, peerID)
		if err != nil {
			return nil, nil, frost.NewParticipantError(peerID, "failed to convert ID to scalar", err)
		}

		// Compute share: f_i(peer_id)
		share := evaluatePolynomial(secretPackage.Coefficients, peerIDScalar, grp)

		round2Packages[peerID] = &Round2Package{
			SigningShare: share,
		}
	}

	// Create round 2 secret package
	round2SecretPackage := &Round2SecretPackage{
		Identifier:  secretPackage.Identifier,
		Commitment:  secretPackage.Commitment,
		SecretShare: ownShare,
		MinSigners:  secretPackage.MinSigners,
		MaxSigners:  secretPackage.MaxSigners,
	}

	return round2SecretPackage, round2Packages, nil
}

// VerifyShare checks g^share == product(commitment[k]^(id^k)) against the sender's VSS commitment.
func VerifyShare(
	identifier frost.Identifier,
	share group.Scalar,
	commitment []group.Element,
	suite ciphersuite.Ciphersuite,
) error {
	if len(commitment) == 0 {
		return frost.NewParameterError("commitment", "cannot be empty", frost.ErrInvalidCommitment)
	}

	if share == nil {
		return frost.NewParameterError("share", "cannot be nil", frost.ErrInvalidParameters)
	}

	grp := suite.Group()

	// Convert identifier to scalar
	idScalar, err := helpers.IdentifierToScalar(grp, identifier)
	if err != nil {
		return frost.NewParameterError("identifier", "failed to convert to scalar", err)
	}

	// Compute left side: g^share
	left := grp.ScalarBaseMult(share)

	// Compute right side: product(commitment[k]^(id^k)) for k=0..t-1
	// This is equivalent to evaluating the commitment polynomial at id
	right := evaluateCommitmentPolynomial(commitment, idScalar, grp)

	// Check equality
	if !left.Equal(right) {
		return frost.NewParticipantError(identifier, "invalid share", frost.ErrInvalidKeyShare)
	}

	return nil
}

// evaluateCommitmentPolynomial returns product(commitment[k]^(x^k)).
func evaluateCommitmentPolynomial(commitment []group.Element, x group.Scalar, grp group.Group) group.Element {
	// Start with identity
	result := grp.Identity()

	// x^k accumulator, starts at x^0 = 1
	// Create scalar 1 using the group's byte order
	xPowerBytes := make([]byte, grp.ScalarLength())
	if grp.ByteOrder() == group.BigEndian {
		xPowerBytes[len(xPowerBytes)-1] = 1
	} else {
		xPowerBytes[0] = 1
	}
	xPower, _ := grp.DeserializeScalar(xPowerBytes)
	secmem.ZeroBytes(xPowerBytes)

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
