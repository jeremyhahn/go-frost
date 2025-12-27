// Package signing implements rerandomized FROST for unlinkable signatures.
//
// Re-randomized FROST allows producing signatures that are unlinkable to the
// original public key. This is useful for privacy-preserving applications
// where you want to prove ownership of a key without revealing which key.
//
// The protocol works by:
// 1. Computing a randomizer from the signing package and randomness
// 2. Each participant randomizes their key package by adding the randomizer to their secret share
// 3. The aggregator uses the randomized public key package
// 4. The final signature verifies against the randomized public key
//
// Security: The randomizer MUST be sent to all participants via a confidential channel.
// All participants MUST use the same randomizer value.
package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// RandomizedParams contains the parameters for a rerandomized signing session.
type RandomizedParams struct {
	// Randomizer is the scalar used to randomize keys
	Randomizer group.Scalar

	// RandomizerElement is the randomizer * G (for public key randomization)
	RandomizerElement group.Element

	// RandomizedVerifyingKey is the randomized group public key: pk' = pk + randomizer * G
	RandomizedVerifyingKey group.Element
}

// NewRandomizedParams creates RandomizedParams from a randomizer scalar and group public key.
//
// Inputs:
//   - randomizer: The randomizer scalar (should be derived deterministically from signing package)
//   - groupPublicKey: The original group public key
//   - suite: The ciphersuite to use
//
// Outputs:
//   - params: The randomized parameters
//
// Errors:
//   - Returns error if the randomized public key is the identity element
func NewRandomizedParams(
	randomizer group.Scalar,
	groupPublicKey group.Element,
	suite ciphersuite.Ciphersuite,
) (*RandomizedParams, error) {
	if groupPublicKey == nil {
		return nil, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}
	if randomizer == nil {
		return nil, frost.NewParameterError("randomizer", "cannot be nil", frost.ErrInvalidParameters)
	}

	grp := suite.Group()

	// Compute randomizer element: randomizer * G
	randomizerElement := grp.ScalarBaseMult(randomizer)

	// Compute randomized public key: pk' = pk + randomizer * G
	randomizedPK := groupPublicKey.Add(randomizerElement)

	// Security check: randomized public key must not be identity
	if randomizedPK.IsIdentity() {
		return nil, frost.NewParameterError("randomizedPublicKey",
			"randomized public key is identity element", frost.ErrIdentityElement)
	}

	return &RandomizedParams{
		Randomizer:             randomizer,
		RandomizerElement:      randomizerElement,
		RandomizedVerifyingKey: randomizedPK,
	}, nil
}

// ComputeRandomizer computes a randomizer for rerandomized FROST.
// The randomizer is derived from the signing package and additional randomness
// to ensure binding to the specific signing session.
//
// Inputs:
//   - signingPackage: The signing package for this session
//   - randomness: Additional randomness (from coordinator)
//   - groupPublicKey: The original group public key
//   - suite: The ciphersuite to use
//
// Outputs:
//   - params: The randomized parameters
//
// Errors:
//   - Returns error if the randomized public key is the identity element
func ComputeRandomizer(
	msg []byte,
	commitmentList frost.CommitmentList,
	randomness group.Scalar,
	groupPublicKey group.Element,
	suite ciphersuite.Ciphersuite,
) (*RandomizedParams, error) {
	if groupPublicKey == nil {
		return nil, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Compute randomizer: hash(randomness || encoded_commitments)
	// This binds the randomizer to the specific signing session
	var input []byte
	input = append(input, randomness.Bytes()...)
	for _, c := range commitmentList {
		input = append(input, c.Identifier.Serialize()...)
		input = append(input, c.HidingNonceCommitment.Bytes()...)
		input = append(input, c.BindingNonceCommitment.Bytes()...)
	}
	input = append(input, msg...)

	randomizer := suite.H3(input)

	return NewRandomizedParams(randomizer, groupPublicKey, suite)
}

// RandomizeKeyPackage creates a randomized key package for rerandomized signing.
// Each participant must call this with the same randomizer before signing.
//
// Inputs:
//   - keyPackage: The original key package
//   - params: The randomized parameters (with shared randomizer)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - randomizedKeyPackage: The key package with randomized secret share
//
// The randomized secret share is: s_i' = s_i + randomizer
// This ensures that when participants sign, the randomizer contribution
// is automatically included in their signature shares.
func RandomizeKeyPackage(
	keyPackage frost.KeyPackage,
	params *RandomizedParams,
	_ ciphersuite.Ciphersuite,
) frost.KeyPackage {
	// Randomize secret share: s_i' = s_i + randomizer
	randomizedSecretShare := keyPackage.SecretShare.Add(params.Randomizer)

	// Randomize verification shares: Y_i' = Y_i + randomizer * G
	var randomizedVerificationShares []frost.VerificationShare
	for _, vs := range keyPackage.VerificationShares {
		randomizedVS := frost.VerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: vs.VerificationKey.Add(params.RandomizerElement),
		}
		randomizedVerificationShares = append(randomizedVerificationShares, randomizedVS)
	}

	return frost.KeyPackage{
		Identifier:         keyPackage.Identifier,
		SecretShare:        randomizedSecretShare,
		GroupPublicKey:     params.RandomizedVerifyingKey,
		VerificationShares: randomizedVerificationShares,
		MinSigners:         keyPackage.MinSigners,
		MaxSigners:         keyPackage.MaxSigners,
	}
}

// RerandomizedSign performs rerandomized FROST signing.
// This is the main entry point for participants in a rerandomized signing session.
//
// Inputs:
//   - msg: The message to sign
//   - keyPackage: The original (non-randomized) key package
//   - noncePkg: The nonce package from round one
//   - commitments: Map of all participant commitments
//   - params: The randomized parameters (shared by all participants)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - signatureShare: The signature share (includes randomizer contribution)
func RerandomizedSign(
	msg []byte,
	keyPackage *frost.KeyPackage,
	noncePkg *NoncePackage,
	commitments map[frost.Identifier]*frost.SigningCommitments,
	params *RandomizedParams,
	suite ciphersuite.Ciphersuite,
) (*SignatureShare, error) {
	// Randomize the key package
	randomizedKeyPackage := RandomizeKeyPackage(*keyPackage, params, suite)

	// Sign with the randomized key package
	return Sign(msg, &randomizedKeyPackage, noncePkg, commitments, suite)
}

// RerandomizedAggregate aggregates signature shares for rerandomized FROST.
//
// Inputs:
//   - msg: The message that was signed
//   - commitments: Map of all participant commitments
//   - signatureShares: Map of signature shares from participants
//   - verificationShares: Map of verification shares (original, non-randomized)
//   - params: The randomized parameters
//   - suite: The ciphersuite to use
//
// Outputs:
//   - signature: The final FROST signature (verifies against randomized public key)
func RerandomizedAggregate(
	msg []byte,
	commitments map[frost.Identifier]*frost.SigningCommitments,
	signatureShares map[frost.Identifier]*SignatureShare,
	verificationShares map[frost.Identifier]frost.VerificationShare,
	params *RandomizedParams,
	suite ciphersuite.Ciphersuite,
) (frost.Signature, error) {
	// Randomize the verification shares
	randomizedVerificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for id, vs := range verificationShares {
		randomizedVerificationShares[id] = frost.VerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: vs.VerificationKey.Add(params.RandomizerElement),
		}
	}

	// Aggregate with the randomized public key
	return Aggregate(msg, commitments, signatureShares, randomizedVerificationShares,
		params.RandomizedVerifyingKey, suite)
}

// RerandomizedVerify verifies a rerandomized signature against the randomized public key.
func RerandomizedVerify(
	msg []byte,
	signature frost.Signature,
	params *RandomizedParams,
	suite ciphersuite.Ciphersuite,
) error {
	return VerifySignature(msg, signature, params.RandomizedVerifyingKey, suite)
}

// RerandomizedParticipant wraps a Participant to add rerandomization support.
// This provides a convenient interface for rerandomized signing.
type RerandomizedParticipant struct {
	keyPackage frost.KeyPackage
	params     *RandomizedParams
	suite      ciphersuite.Ciphersuite
}

// NewRerandomizedParticipant creates a participant that produces rerandomized signatures.
//
// Inputs:
//   - keyPackage: The original (non-randomized) key package
//   - params: The randomized parameters (must be shared by all participants)
//   - suite: The ciphersuite to use
func NewRerandomizedParticipant(
	keyPackage frost.KeyPackage,
	params *RandomizedParams,
	suite ciphersuite.Ciphersuite,
) *RerandomizedParticipant {
	return &RerandomizedParticipant{
		keyPackage: keyPackage,
		params:     params,
		suite:      suite,
	}
}

// RoundOne generates nonces and commitments for rerandomized signing.
// This is the same as regular FROST round one.
func (rp *RerandomizedParticipant) RoundOne() (frost.SigningNonces, frost.SigningCommitments, error) {
	participant := NewParticipant(rp.keyPackage, rp.suite)
	return participant.RoundOne()
}

// RoundTwo generates a rerandomized signature share.
// The key package is randomized internally before signing.
//
// Inputs:
//   - nonces: The signing nonces from round one
//   - msg: The message being signed
//   - commitmentList: Sorted list of participant commitments
//
// Outputs:
//   - signatureShare: The rerandomized signature share
func (rp *RerandomizedParticipant) RoundTwo(
	nonces frost.SigningNonces,
	msg []byte,
	commitmentList frost.CommitmentList,
) (frost.SignatureShare, error) {
	// Randomize the key package
	randomizedKeyPackage := RandomizeKeyPackage(rp.keyPackage, rp.params, rp.suite)

	// Create participant with randomized key package
	participant := NewParticipant(randomizedKeyPackage, rp.suite)

	// Sign with the randomized key package
	return participant.RoundTwo(nonces, msg, commitmentList)
}

// RerandomizedAggregator aggregates rerandomized signature shares.
type RerandomizedAggregator struct {
	suite      ciphersuite.Ciphersuite
	minSigners uint32
	params     *RandomizedParams
}

// NewRerandomizedAggregator creates an aggregator for rerandomized signatures.
func NewRerandomizedAggregator(
	suite ciphersuite.Ciphersuite,
	minSigners uint32,
	params *RandomizedParams,
) *RerandomizedAggregator {
	return &RerandomizedAggregator{
		suite:      suite,
		minSigners: minSigners,
		params:     params,
	}
}

// Aggregate combines rerandomized signature shares into a signature.
// The resulting signature verifies against the randomized public key.
//
// Inputs:
//   - commitmentList: Sorted list of participant commitments
//   - msg: The message being signed
//   - signatureShares: List of signature shares (already include randomizer contribution)
//   - verificationShares: Original (non-randomized) verification shares
//
// Outputs:
//   - signature: The rerandomized FROST signature
func (ra *RerandomizedAggregator) Aggregate(
	commitmentList frost.CommitmentList,
	msg []byte,
	signatureShares []frost.SignatureShare,
	verificationShares []frost.VerificationShare,
) (frost.Signature, error) {
	// Randomize the verification shares
	randomizedVerificationShares := make([]frost.VerificationShare, len(verificationShares))
	for i, vs := range verificationShares {
		randomizedVerificationShares[i] = frost.VerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: vs.VerificationKey.Add(ra.params.RandomizerElement),
		}
	}

	// Create aggregator with randomized parameters
	agg := NewAggregator(ra.suite, ra.minSigners)

	// Aggregate with the randomized public key and verification shares
	return agg.AggregateWithVerification(
		ra.params.RandomizedVerifyingKey,
		commitmentList,
		msg,
		signatureShares,
		randomizedVerificationShares,
	)
}

// Verify verifies a rerandomized signature against the randomized public key.
func (ra *RerandomizedAggregator) Verify(
	msg []byte,
	signature frost.Signature,
) error {
	agg := NewAggregator(ra.suite, ra.minSigners)
	return agg.Verify(msg, signature, ra.params.RandomizedVerifyingKey)
}

// GetRandomizedPublicKey returns the randomized public key for verification.
func (ra *RerandomizedAggregator) GetRandomizedPublicKey() group.Element {
	return ra.params.RandomizedVerifyingKey
}
