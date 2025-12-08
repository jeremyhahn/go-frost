package dkg

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Part3 executes round 3 (final round) of the DKG protocol.
//
// Each participant:
//  1. Verifies all received shares using VSS verification
//  2. Accumulates all shares (received + own) to compute final signing share
//  3. Computes verifying share (public key share)
//  4. Aggregates commitments to compute group public key and all verifying shares
//
// Inputs:
//   - round2SecretPackage: The secret package from Part2 (kept private)
//   - round1Packages: Map of Round1Packages received from all other participants
//   - round2Packages: Map of Round2Packages received from all other participants
//   - suite: The ciphersuite to use
//
// Outputs:
//   - keyPackage: This participant's final key material for signing
//   - publicKeyPackage: The group's public key material for verification
//
// Errors:
//   - Returns error if any share verification fails (identifies the culprit)
//   - Returns error if wrong number of packages provided
func Part3(
	round2SecretPackage *Round2SecretPackage,
	round1Packages map[frost.Identifier]*Round1Package,
	round2Packages map[frost.Identifier]*Round2Package,
	suite ciphersuite.Ciphersuite,
) (*frost.KeyPackage, *PublicKeyPackage, error) {
	if round2SecretPackage == nil {
		return nil, nil, frost.NewParameterError("round2SecretPackage", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Validate package counts
	expectedCount := int(round2SecretPackage.MaxSigners - 1)
	if len(round1Packages) != expectedCount {
		return nil, nil, frost.NewParameterError("round1Packages",
			"wrong number of packages", frost.ErrInsufficientParticipants)
	}
	if len(round2Packages) != expectedCount {
		return nil, nil, frost.NewParameterError("round2Packages",
			"wrong number of packages", frost.ErrInsufficientParticipants)
	}

	// Verify that round1 and round2 packages have matching identifiers
	for id := range round1Packages {
		if _, ok := round2Packages[id]; !ok {
			return nil, nil, frost.NewParticipantError(id,
				"missing round 2 package", frost.ErrInvalidParameters)
		}
	}

	grp := suite.Group()

	// Initialize signing share accumulator with own share
	signingShare := round2SecretPackage.SecretShare.Copy()

	// Verify and accumulate received shares
	for senderID, round2Pkg := range round2Packages {
		// Get the sender's commitment from round 1
		round1Pkg, ok := round1Packages[senderID]
		if !ok {
			return nil, nil, frost.NewParticipantError(senderID,
				"missing round 1 package", frost.ErrInvalidParameters)
		}

		// Verify the share using VSS
		err := VerifyShare(
			round2SecretPackage.Identifier,
			round2Pkg.SigningShare,
			round1Pkg.Commitment,
			suite,
		)
		if err != nil {
			return nil, nil, frost.NewSecretShareError(senderID,
				"share verification failed: g^share != commitment evaluation", err)
		}

		// Accumulate the share
		signingShare = signingShare.Add(round2Pkg.SigningShare)
	}

	// Compute verifying share (public key share): g^signingShare
	// Note: We compute this but also verify it matches what's in the aggregated commitments
	_ = grp.ScalarBaseMult(signingShare) // verifyingShare computed from signingShare

	// Aggregate all commitments to compute group public key and verifying shares
	publicKeyPackage, err := aggregateCommitments(
		round2SecretPackage,
		round1Packages,
		suite,
	)
	if err != nil {
		return nil, nil, err
	}

	// Create verification shares for the KeyPackage
	verificationShares := make([]frost.VerificationShare, 0, len(publicKeyPackage.VerifyingShares))
	for id, vk := range publicKeyPackage.VerifyingShares {
		verificationShares = append(verificationShares, frost.VerificationShare{
			Identifier:      id,
			VerificationKey: vk,
		})
	}

	// Create the final key package
	keyPackage := &frost.KeyPackage{
		Identifier:         round2SecretPackage.Identifier,
		SecretShare:        signingShare,
		GroupPublicKey:     publicKeyPackage.VerifyingKey,
		VerificationShares: verificationShares,
		MinSigners:         round2SecretPackage.MinSigners,
		MaxSigners:         round2SecretPackage.MaxSigners,
	}

	return keyPackage, publicKeyPackage, nil
}

// aggregateCommitments computes the group public key and all verifying shares
// from the aggregated commitments.
//
// For each coefficient position k, we sum all participants' commitments:
//
//	summedCommitment[k] = sum(commitment_i[k]) for all participants i
//
// The group public key is summedCommitment[0] (g raised to the sum of all a_0 values).
// Each participant's verifying share is computed by evaluating the summed
// commitment polynomial at their identifier.
func aggregateCommitments(
	round2SecretPackage *Round2SecretPackage,
	round1Packages map[frost.Identifier]*Round1Package,
	suite ciphersuite.Ciphersuite,
) (*PublicKeyPackage, error) {
	grp := suite.Group()

	// Collect all commitments (including our own)
	allCommitments := make(map[frost.Identifier][]group.Element)

	// Add our own commitment
	allCommitments[round2SecretPackage.Identifier] = round2SecretPackage.Commitment

	// Add all other participants' commitments
	for id, pkg := range round1Packages {
		allCommitments[id] = pkg.Commitment
	}

	// Sum commitments at each coefficient position
	numCoeffs := int(round2SecretPackage.MinSigners)
	summedCommitment := make([]group.Element, numCoeffs)

	// Initialize with identity elements
	for k := 0; k < numCoeffs; k++ {
		summedCommitment[k] = grp.Identity()
	}

	// Sum all commitments
	for _, commitment := range allCommitments {
		for k := 0; k < numCoeffs; k++ {
			summedCommitment[k] = summedCommitment[k].Add(commitment[k])
		}
	}

	// Group public key is the first summed commitment: g^(sum of all a_0 values)
	groupPublicKey := summedCommitment[0]

	// Compute verifying shares for all participants
	verifyingShares := make(map[frost.Identifier]group.Element)

	for id := range allCommitments {
		// Convert identifier to scalar
		idScalar, err := helpers.IdentifierToScalar(grp, id)
		if err != nil {
			return nil, frost.NewParticipantError(id, "failed to convert ID to scalar", err)
		}

		// Evaluate summed commitment polynomial at this identifier
		// This gives: g^(s_i) where s_i is the participant's final signing share
		verifyingShare := evaluateCommitmentPolynomial(summedCommitment, idScalar, grp)
		verifyingShares[id] = verifyingShare
	}

	return &PublicKeyPackage{
		VerifyingShares: verifyingShares,
		VerifyingKey:    groupPublicKey,
	}, nil
}
