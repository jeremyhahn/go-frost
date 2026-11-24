package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// CheaterDetectionStrategy defines how the aggregator handles invalid signature shares.
type CheaterDetectionStrategy int

const (
	// CheaterDetectionDisabled performs no per-share verification.
	// Fastest option, but provides no attribution on failure.
	// Use when all participants are trusted.
	CheaterDetectionDisabled CheaterDetectionStrategy = iota

	// CheaterDetectionFirstCheater stops verification at the first invalid share.
	// Identifies the first malicious participant found.
	// Good balance between performance and attribution.
	CheaterDetectionFirstCheater

	// CheaterDetectionAllCheaters verifies all shares to find all invalid ones.
	// Identifies all malicious participants at the cost of checking every share.
	// Use when you want to identify and exclude all cheaters.
	CheaterDetectionAllCheaters
)

// String returns a human-readable name for the strategy.
func (s CheaterDetectionStrategy) String() string {
	switch s {
	case CheaterDetectionDisabled:
		return "Disabled"
	case CheaterDetectionFirstCheater:
		return "FirstCheater"
	case CheaterDetectionAllCheaters:
		return "AllCheaters"
	default:
		return "Unknown"
	}
}

// AggregateWithStrategy combines signature shares using the specified cheater detection strategy.
//
// Strategies:
//   - CheaterDetectionDisabled: No verification, fastest but no attribution
//   - CheaterDetectionFirstCheater: Stop at first invalid share
//   - CheaterDetectionAllCheaters: Verify all shares, collect all cheaters
//
// Inputs:
//   - groupPublicKey: The group's public key
//   - commitmentList: Sorted list of participant commitments
//   - msg: The message being signed
//   - signatureShares: List of signature shares
//   - verificationShares: Public key shares for verification (required unless strategy is Disabled)
//   - strategy: The cheater detection strategy to use
//   - suite: The ciphersuite to use
//   - minSigners: Minimum number of signers required
//
// Outputs:
//   - signature: The complete FROST threshold signature
//
// Errors:
//   - Returns SignatureShareError with culprits if any invalid shares detected
//   - Returns error if insufficient signature shares
func AggregateWithStrategy(
	groupPublicKey group.Element,
	commitmentList frost.CommitmentList,
	msg []byte,
	signatureShares []frost.SignatureShare,
	verificationShares []frost.VerificationShare,
	strategy CheaterDetectionStrategy,
	suite ciphersuite.Ciphersuite,
	minSigners uint32,
) (frost.Signature, error) {
	agg := NewAggregator(suite, minSigners)

	switch strategy {
	case CheaterDetectionDisabled:
		return agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)

	case CheaterDetectionFirstCheater:
		return agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)

	case CheaterDetectionAllCheaters:
		return aggregateWithAllCheaterDetection(
			groupPublicKey,
			commitmentList,
			msg,
			signatureShares,
			verificationShares,
			suite,
			minSigners,
		)

	default:
		return frost.Signature{}, frost.NewParameterError("strategy", "unknown cheater detection strategy", frost.ErrInvalidParameters)
	}
}

// aggregateWithAllCheaterDetection verifies all shares and collects all cheaters before failing.
func aggregateWithAllCheaterDetection(
	groupPublicKey group.Element,
	commitmentList frost.CommitmentList,
	msg []byte,
	signatureShares []frost.SignatureShare,
	verificationShares []frost.VerificationShare,
	suite ciphersuite.Ciphersuite,
	minSigners uint32,
) (frost.Signature, error) {
	// Create helper instances
	grp := suite.Group()
	encoder := helpers.NewCommitmentListEncoder(grp)
	bindingComputer := helpers.NewBindingFactorComputer(suite)
	commitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	polynomialHelper := helpers.NewPolynomialHelper(grp)
	challengeComputer := helpers.NewChallengeComputer(suite)

	// Validate commitment list
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return frost.Signature{}, err
	}

	// Validate group public key
	if groupPublicKey == nil {
		return frost.Signature{}, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Check that len(signatureShares) >= minSigners
	if uint(len(signatureShares)) < uint(minSigners) {
		return frost.Signature{}, frost.ErrInsufficientParticipants
	}

	// Validate verification shares provided
	if len(verificationShares) == 0 {
		return frost.Signature{}, frost.NewParameterError("verificationShares", "cannot be empty for cheater detection", frost.ErrInvalidParameters)
	}

	// Compute binding factors for all participants
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		return frost.Signature{}, err
	}

	// Compute group commitment R
	groupCommitment, err := commitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		return frost.Signature{}, err
	}

	// Security check: Group commitment must not be identity
	if groupCommitment.IsIdentity() {
		return frost.Signature{}, frost.NewVerificationError("groupCommitment",
			"group commitment is identity element", frost.ErrIdentityElement)
	}

	// Compute challenge (needed for share verification)
	challenge, err := challengeComputer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		return frost.Signature{}, frost.NewParameterError("challenge", "failed to compute", err)
	}

	// Get participant identifiers from commitment list for Lagrange interpolation
	participants := encoder.GetParticipants(commitmentList)
	participantScalars := make([]group.Scalar, len(participants))
	for i, id := range participants {
		scalar, err := helpers.IdentifierToScalar(grp, id)
		if err != nil {
			return frost.Signature{}, frost.NewParameterError("participantScalar", "failed to create", err)
		}
		participantScalars[i] = scalar
	}

	// Build lookup maps for faster access
	verificationKeyMap := make(map[frost.Identifier]group.Element)
	for _, vs := range verificationShares {
		verificationKeyMap[vs.Identifier] = vs.VerificationKey
	}

	commitmentMap := make(map[frost.Identifier]frost.SigningCommitments)
	for _, c := range commitmentList {
		commitmentMap[c.Identifier] = c
	}

	bindingFactorMap := make(map[frost.Identifier]group.Scalar)
	for _, bf := range bindingFactors {
		bindingFactorMap[bf.Identifier] = bf.BindingFactor
	}

	// Verify ALL shares and collect culprits
	var culprits []frost.Identifier

	for _, share := range signatureShares {
		// Find verification key for this participant
		verificationKey, ok := verificationKeyMap[share.Identifier]
		if !ok {
			culprits = append(culprits, share.Identifier)
			continue
		}

		// Get binding factor for this participant
		bindingFactor, ok := bindingFactorMap[share.Identifier]
		if !ok {
			culprits = append(culprits, share.Identifier)
			continue
		}

		// Find participant's commitment from list
		participantCommitment, ok := commitmentMap[share.Identifier]
		if !ok {
			culprits = append(culprits, share.Identifier)
			continue
		}

		// Compute lambda_i (Lagrange coefficient) for this participant
		shareIDScalar, err := helpers.IdentifierToScalar(grp, share.Identifier)
		if err != nil {
			culprits = append(culprits, share.Identifier)
			continue
		}

		lambda, err := polynomialHelper.DeriveInterpolatingValue(participantScalars, shareIDScalar)
		if err != nil {
			culprits = append(culprits, share.Identifier)
			continue
		}

		// Verify signature share using equation:
		// sig_share * G == hiding_commitment + binding_factor * binding_commitment + lambda_i * verification_key * challenge
		left := grp.ScalarBaseMult(share.SignatureShare)

		// Right side components
		right := participantCommitment.HidingNonceCommitment.Copy()
		bindingTerm := grp.ScalarMult(participantCommitment.BindingNonceCommitment, bindingFactor)
		right = right.Add(bindingTerm)

		challengeTerm := grp.ScalarMult(verificationKey, challenge)
		lambdaChallengeTerm := grp.ScalarMult(challengeTerm, lambda)
		right = right.Add(lambdaChallengeTerm)

		// Verify equation
		if !left.Equal(right) {
			culprits = append(culprits, share.Identifier)
		}
	}

	// If any cheaters found, return error with all culprits
	if len(culprits) > 0 {
		return frost.Signature{}, frost.NewSignatureShareError(
			culprits,
			"signature share verification failed",
			frost.ErrInvalidSignatureShare)
	}

	// All shares verified! Now aggregate them
	z := grp.NewScalar()
	for _, share := range signatureShares {
		z = z.Add(share.SignatureShare)
	}

	return frost.Signature{
		R: groupCommitment,
		Z: z,
	}, nil
}
