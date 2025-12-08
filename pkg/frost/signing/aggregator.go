package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Aggregator aggregates signature shares from participants into a complete signature.
type Aggregator interface {
	// Aggregate combines signature shares from threshold participants into a complete signature.
	//
	// Inputs:
	// - groupPublicKey: The group's public key (needed for binding factor computation)
	// - commitmentList: Sorted list of participant commitments from round one
	// - msg: The message being signed
	// - signatureShares: List of signature shares from round two
	//
	// Outputs:
	// - signature: The complete FROST threshold signature
	//
	// The aggregated signature is (R, z) where:
	// - R is the group commitment point
	// - z is the sum of all signature shares
	//
	// Errors:
	// - Returns error if insufficient signature shares
	// - Returns error if commitment list is invalid
	Aggregate(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte, signatureShares []frost.SignatureShare) (frost.Signature, error)

	// AggregateWithVerification combines signature shares with identifiable abort protection.
	//
	// This method verifies each signature share before aggregation, enabling
	// identification of malicious participants who provide invalid shares.
	// This implements RFC 9591 Section 7.4 (Identifiable Abort).
	//
	// Inputs:
	// - groupPublicKey: The group's public key (needed for binding factor computation)
	// - commitmentList: Sorted list of participant commitments from round one
	// - msg: The message being signed
	// - signatureShares: List of signature shares from round two
	// - verificationShares: Public key shares for all participants (for share verification)
	//
	// Outputs:
	// - signature: The complete FROST threshold signature
	//
	// Errors:
	// - Returns error if any signature share fails verification (identifies malicious participant)
	// - Returns error if insufficient signature shares
	// - Returns error if commitment list is invalid
	//
	// Security: Enabling identifiable abort prevents malicious participants from causing
	// signature failure without detection. The cost is additional verification overhead.
	AggregateWithVerification(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte, signatureShares []frost.SignatureShare, verificationShares []frost.VerificationShare) (frost.Signature, error)

	// Verify verifies a FROST signature against a message and public key.
	//
	// Inputs:
	// - msg: The message that was signed
	// - signature: The FROST signature to verify
	// - publicKey: The group's public key
	//
	// Errors:
	// - Returns error if signature verification fails
	//
	// Verification checks: ScalarBaseMult(z) == R + challenge * publicKey
	Verify(msg []byte, signature frost.Signature, publicKey group.Element) error
}

// NewAggregator creates a new signature aggregator.
func NewAggregator(suite ciphersuite.Ciphersuite, minSigners uint32) Aggregator {
	return &aggregator{
		suite:      suite,
		minSigners: minSigners,
	}
}

type aggregator struct {
	suite      ciphersuite.Ciphersuite
	minSigners uint32
}

// Aggregate implements Aggregator.Aggregate
//
// Combines signature shares from threshold participants into a complete signature.
// The aggregated signature is (R, z) where:
// - R is the group commitment point
// - z is the sum of all signature shares
//
// Algorithm (from RFC 9591 Section 5.3):
// 1. Validate commitment list (must be sorted and non-empty)
// 2. Check that len(signatureShares) >= minSigners
// 3. Compute binding factors for all participants
// 4. Compute group commitment R
// 5. Initialize z = 0
// 6. For each signature share: z = z + signature_share
// 7. Return signature (R, z)
func (a *aggregator) Aggregate(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte, signatureShares []frost.SignatureShare) (frost.Signature, error) {
	// Create helper instances
	encoder := helpers.NewCommitmentListEncoder(a.suite.Group())
	bindingComputer := helpers.NewBindingFactorComputer(a.suite)
	commitmentComputer := helpers.NewGroupCommitmentComputer(a.suite.Group())

	// 1. Validate commitment list
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return frost.Signature{}, err
	}

	// Validate group public key
	if groupPublicKey == nil {
		return frost.Signature{}, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// 2. Check that len(signatureShares) >= minSigners
	if uint32(len(signatureShares)) < a.minSigners {
		return frost.Signature{}, frost.ErrInsufficientParticipants
	}

	// 3. Compute binding factors for all participants
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		return frost.Signature{}, err
	}

	// 4. Compute group commitment R
	groupCommitment, err := commitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		return frost.Signature{}, err
	}

	// Security check: Group commitment must not be identity
	// This could happen if commitments cancel out, indicating a potential attack
	if groupCommitment.IsIdentity() {
		return frost.Signature{}, frost.NewVerificationError("groupCommitment",
			"group commitment is identity element", frost.ErrIdentityElement)
	}

	// 5. Initialize z = 0
	z := a.suite.Group().NewScalar()

	// 6. For each signature share: z = z + signature_share
	for _, share := range signatureShares {
		z = z.Add(share.SignatureShare)
	}

	// 7. Return signature (R, z)
	return frost.Signature{
		R: groupCommitment,
		Z: z,
	}, nil
}

// AggregateWithVerification implements Aggregator.AggregateWithVerification
//
// Combines signature shares with identifiable abort protection by verifying
// each share before aggregation. This implements RFC 9591 Section 7.4.
//
// Algorithm:
// 1-4. Same as Aggregate (validate, compute binding factors, group commitment)
//  5. For each signature share:
//     a. Find participant's verification key
//     b. Verify share using verification equation
//     c. If verification fails, return error identifying the malicious participant
//  6. Sum all signature shares into z (only if all shares verified)
//  7. Return signature (R, z)
func (a *aggregator) AggregateWithVerification(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte, signatureShares []frost.SignatureShare, verificationShares []frost.VerificationShare) (frost.Signature, error) {
	// Create helper instances
	encoder := helpers.NewCommitmentListEncoder(a.suite.Group())
	bindingComputer := helpers.NewBindingFactorComputer(a.suite)
	commitmentComputer := helpers.NewGroupCommitmentComputer(a.suite.Group())
	polynomialHelper := helpers.NewPolynomialHelper(a.suite.Group())
	challengeComputer := helpers.NewChallengeComputer(a.suite)
	grp := a.suite.Group()

	// 1. Validate commitment list
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return frost.Signature{}, err
	}

	// Validate group public key
	if groupPublicKey == nil {
		return frost.Signature{}, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// 2. Check that len(signatureShares) >= minSigners
	if uint32(len(signatureShares)) < a.minSigners {
		return frost.Signature{}, frost.ErrInsufficientParticipants
	}

	// Validate verification shares provided
	if len(verificationShares) == 0 {
		return frost.Signature{}, frost.NewParameterError("verificationShares", "cannot be empty for verification", frost.ErrInvalidParameters)
	}

	// 3. Compute binding factors for all participants
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		return frost.Signature{}, err
	}

	// 4. Compute group commitment R
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
	// Uses group-specific byte ordering (little-endian for Ed25519/Ed448/ristretto255,
	// big-endian for P-256/secp256k1)
	participants := encoder.GetParticipants(commitmentList)
	participantScalars := make([]group.Scalar, len(participants))
	for i, id := range participants {
		scalar, err := helpers.IdentifierToScalar(grp, id)
		if err != nil {
			return frost.Signature{}, frost.NewParameterError("participantScalar", "failed to create", err)
		}
		participantScalars[i] = scalar
	}

	// 5. Verify each signature share before aggregating
	for _, share := range signatureShares {
		// Find verification key for this participant
		var verificationKey group.Element
		for _, vs := range verificationShares {
			if vs.Identifier == share.Identifier {
				verificationKey = vs.VerificationKey
				break
			}
		}

		if verificationKey == nil {
			return frost.Signature{}, frost.NewParticipantError(share.Identifier,
				"verification key not found", frost.ErrInvalidParameters)
		}

		// Get binding factor for this participant
		bindingFactor, err := bindingComputer.GetBindingFactor(bindingFactors, share.Identifier)
		if err != nil {
			return frost.Signature{}, frost.NewParticipantError(share.Identifier,
				"binding factor not found", err)
		}

		// Find participant's commitment from list
		var participantCommitment frost.SigningCommitments
		found := false
		for _, commitment := range commitmentList {
			if commitment.Identifier == share.Identifier {
				participantCommitment = commitment
				found = true
				break
			}
		}

		if !found {
			return frost.Signature{}, frost.NewParticipantError(share.Identifier,
				"commitment not found in commitment list", frost.ErrInvalidCommitment)
		}

		// Compute lambda_i (Lagrange coefficient) for this participant
		shareIDScalar, err := helpers.IdentifierToScalar(grp, share.Identifier)
		if err != nil {
			return frost.Signature{}, frost.NewParameterError("shareIDScalar", "failed to create", err)
		}

		lambda, err := polynomialHelper.DeriveInterpolatingValue(participantScalars, shareIDScalar)
		if err != nil {
			return frost.Signature{}, frost.NewParticipantError(share.Identifier,
				"failed to compute interpolating value", err)
		}

		// Verify signature share using equation:
		// sig_share * G == hiding_commitment + binding_factor * binding_commitment + lambda_i * verification_key * challenge
		//
		// Left side: sig_share * G
		left := grp.ScalarBaseMult(share.SignatureShare)

		// Right side components:
		// 1. hiding_commitment
		right := participantCommitment.HidingNonceCommitment.Copy()

		// 2. + binding_factor * binding_commitment
		bindingTerm := grp.ScalarMult(participantCommitment.BindingNonceCommitment, bindingFactor)
		right = right.Add(bindingTerm)

		// 3. + lambda_i * verification_key * challenge
		challengeTerm := grp.ScalarMult(verificationKey, challenge)
		lambdaChallengeTerm := grp.ScalarMult(challengeTerm, lambda)
		right = right.Add(lambdaChallengeTerm)

		// Verify equation
		if !left.Equal(right) {
			return frost.Signature{}, frost.NewSignatureShareError(
				[]frost.Identifier{share.Identifier},
				"signature share verification failed: sig_share*G != commitment + lambda*pk*challenge",
				frost.ErrInvalidSignatureShare)
		}
	}

	// 6. All shares verified! Now aggregate them
	z := grp.NewScalar()
	for _, share := range signatureShares {
		z = z.Add(share.SignatureShare)
	}

	// 7. Return signature (R, z)
	return frost.Signature{
		R: groupCommitment,
		Z: z,
	}, nil
}

// Verify implements Aggregator.Verify
//
// Verifies a FROST signature against a message and public key.
// Verification checks: ScalarBaseMult(z) == R + challenge * publicKey
//
// Algorithm (from RFC 9591 Section 5.3):
// 1. Validate inputs (signature R and Z, public key)
// 2. Compute challenge = H2(R || publicKey || msg)
// 3. Compute left = ScalarBaseMult(z)
// 4. Compute right = R + ScalarMult(publicKey, challenge)
// 5. Verify left == right
// 6. Return error if verification fails
func (a *aggregator) Verify(msg []byte, signature frost.Signature, publicKey group.Element) error {
	// 1. Validate inputs
	if signature.R == nil {
		return frost.NewParameterError("signature.R", "cannot be nil", frost.ErrInvalidSignature)
	}
	if signature.Z == nil {
		return frost.NewParameterError("signature.Z", "cannot be nil", frost.ErrInvalidSignature)
	}
	if publicKey == nil {
		return frost.NewParameterError("publicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Security check: R must not be the identity element
	// An identity R would indicate a malformed or malicious signature
	if signature.R.IsIdentity() {
		return frost.NewVerificationError("signature", "R is identity element", frost.ErrIdentityElement)
	}

	// Security check: Public key must not be the identity element
	if publicKey.IsIdentity() {
		return frost.NewParameterError("publicKey", "public key is identity element", frost.ErrIdentityElement)
	}

	// 2. Compute challenge = H2(R || publicKey || msg)
	challengeComputer := helpers.NewChallengeComputer(a.suite)
	challenge, err := challengeComputer.Compute(signature.R, publicKey, msg)
	if err != nil {
		return frost.NewVerificationError("signature", "failed to compute challenge", err)
	}

	// 3. Compute left = ScalarBaseMult(z)
	left := a.suite.Group().ScalarBaseMult(signature.Z)

	// 4. Compute right = R + ScalarMult(publicKey, challenge)
	challengePublicKey := a.suite.Group().ScalarMult(publicKey, challenge)
	right := signature.R.Add(challengePublicKey)

	// 5. Verify left == right
	if !left.Equal(right) {
		return frost.NewVerificationError("signature", "signature verification equation failed", frost.ErrInvalidSignature)
	}

	// 6. Return success
	return nil
}
