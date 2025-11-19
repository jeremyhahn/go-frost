// Package signing implements the two-round FROST signing protocol.
//
// The FROST signing protocol consists of:
// - Round 1: Commitment generation
// - Round 2: Signature share generation
// - Aggregation: Signature share aggregation
package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Participant represents a signing participant in the FROST protocol.
type Participant interface {
	// Identifier returns the participant's unique identifier.
	Identifier() frost.Identifier

	// RoundOne generates signing nonces and commitments for round one.
	//
	// Outputs:
	// - nonces: The secret nonces (must be stored securely until round two)
	// - commitments: The public commitments to broadcast
	//
	// Each participant generates two random nonces (hiding and binding) and
	// computes commitments to these nonces by multiplying with the generator.
	RoundOne() (frost.SigningNonces, frost.SigningCommitments, error)

	// RoundTwo generates a signature share using the participant's key share,
	// nonces from round one, and the aggregated commitment list.
	//
	// Inputs:
	// - nonces: The nonces generated in round one
	// - msg: The message to sign
	// - commitmentList: Sorted list of all participants' commitments
	//
	// Outputs:
	// - signatureShare: The participant's signature share
	//
	// The signature share is computed as:
	// z_i = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * secret_share * challenge)
	RoundTwo(nonces frost.SigningNonces, msg []byte, commitmentList frost.CommitmentList) (frost.SignatureShare, error)

	// VerifySignatureShare verifies a signature share from another participant.
	//
	// Inputs:
	// - share: The signature share to verify
	// - msg: The message being signed
	// - commitmentList: The commitment list used in signing
	//
	// Outputs:
	// - valid: True if the signature share is valid
	//
	// This is used for identifiable abort to detect malicious participants.
	VerifySignatureShare(share frost.SignatureShare, msg []byte, commitmentList frost.CommitmentList) error
}

// NewParticipant creates a new signing participant.
func NewParticipant(keyPackage frost.KeyPackage, suite ciphersuite.Ciphersuite) Participant {
	return &participant{
		keyPackage: keyPackage,
		suite:      suite,
	}
}

type participant struct {
	keyPackage frost.KeyPackage
	suite      ciphersuite.Ciphersuite
}

// Identifier implements Participant.Identifier
func (p *participant) Identifier() frost.Identifier {
	return p.keyPackage.Identifier
}

// RoundOne implements Participant.RoundOne
//
// Generates signing nonces and commitments for round one.
// Each participant generates two random nonces (hiding and binding) and
// computes commitments to these nonces by multiplying with the generator.
//
// Algorithm (from RFC 9591 Section 5.1):
// 1. Generate hiding_nonce using nonce_generate(secret_share)
// 2. Generate binding_nonce using nonce_generate(secret_share)
// 3. Compute hiding_nonce_commitment = ScalarBaseMult(hiding_nonce)
// 4. Compute binding_nonce_commitment = ScalarBaseMult(binding_nonce)
// 5. Return nonces and commitments
func (p *participant) RoundOne() (frost.SigningNonces, frost.SigningCommitments, error) {
	grp := p.suite.Group()

	// 1. Generate hiding_nonce using nonce_generate(secret_share)
	randomScalar, err := grp.RandomScalar()
	if err != nil {
		return frost.SigningNonces{}, frost.SigningCommitments{}, frost.NewParameterError("randomScalar", "failed to generate", err)
	}

	// Use H3 to generate hiding nonce from secret + randomness
	hidingInput := append(randomScalar.Bytes(), p.keyPackage.SecretShare.Bytes()...)
	hidingNonce := p.suite.H3(hidingInput)

	// 2. Generate binding_nonce using nonce_generate(secret_share)
	randomScalar2, err := grp.RandomScalar()
	if err != nil {
		return frost.SigningNonces{}, frost.SigningCommitments{}, frost.NewParameterError("randomScalar", "failed to generate", err)
	}

	bindingInput := append(randomScalar2.Bytes(), p.keyPackage.SecretShare.Bytes()...)
	bindingNonce := p.suite.H3(bindingInput)

	// Verify nonces are not zero
	if hidingNonce.IsZero() {
		return frost.SigningNonces{}, frost.SigningCommitments{}, frost.NewParameterError("hidingNonce", "generated zero nonce", frost.ErrInvalidNonce)
	}
	if bindingNonce.IsZero() {
		return frost.SigningNonces{}, frost.SigningCommitments{}, frost.NewParameterError("bindingNonce", "generated zero nonce", frost.ErrInvalidNonce)
	}

	// 3. Compute hiding_nonce_commitment = ScalarBaseMult(hiding_nonce)
	hidingNonceCommitment := grp.ScalarBaseMult(hidingNonce)

	// 4. Compute binding_nonce_commitment = ScalarBaseMult(binding_nonce)
	bindingNonceCommitment := grp.ScalarBaseMult(bindingNonce)

	// 5. Create commitments structure
	commitments := frost.SigningCommitments{
		Identifier:             p.keyPackage.Identifier,
		HidingNonceCommitment:  hidingNonceCommitment,
		BindingNonceCommitment: bindingNonceCommitment,
	}

	// Create nonces structure with embedded commitments
	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitments,
	}

	return nonces, commitments, nil
}

// RoundTwo implements Participant.RoundTwo
//
// Generates a signature share using the participant's key share,
// nonces from round one, and the aggregated commitment list.
//
// Algorithm (from RFC 9591 Section 5.2):
// 1. Validate commitment list (sorted, no duplicates)
// 2. Compute binding factors
// 3. Compute group commitment
// 4. Get participant identifiers from commitment list
// 5. Compute lambda_i = derive_interpolating_value(identifiers, identifier)
// 6. Compute challenge = H2(group_commitment || group_public_key || msg)
// 7. Get binding_factor for this participant
// 8. Compute sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * secret_share * challenge)
// 9. Return signature share
func (p *participant) RoundTwo(nonces frost.SigningNonces, msg []byte, commitmentList frost.CommitmentList) (frost.SignatureShare, error) {
	grp := p.suite.Group()

	// Import helper functions
	encoder := helpers.NewCommitmentListEncoder(grp)
	bindingComputer := helpers.NewBindingFactorComputer(p.suite)
	groupCommitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	polynomialHelper := helpers.NewPolynomialHelper(grp)
	challengeComputer := helpers.NewChallengeComputer(p.suite)

	// 1. Validate commitment list
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return frost.SignatureShare{}, err
	}

	// 2. Compute binding factors
	bindingFactors, err := bindingComputer.Compute(p.keyPackage.GroupPublicKey, commitmentList, msg)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParameterError("bindingFactors", "failed to compute", err)
	}

	// 3. Compute group commitment
	groupCommitment, err := groupCommitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParameterError("groupCommitment", "failed to compute", err)
	}

	// 4. Get participant identifiers from commitment list
	participants := encoder.GetParticipants(commitmentList)

	// Convert participant identifiers to scalars for interpolation
	participantScalars := make([]group.Scalar, len(participants))
	for i, id := range participants {
		// Create scalar from identifier
		idBytes := make([]byte, grp.ScalarLength())
		idVal := uint32(id)
		// Encode as big-endian to match dealer.go convention
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[len(idBytes)-1-j] = byte(idVal >> (8 * j))
		}

		scalar, err := grp.DeserializeScalar(idBytes)
		if err != nil {
			return frost.SignatureShare{}, frost.NewParameterError("participantScalar", "failed to create", err)
		}
		participantScalars[i] = scalar
	}

	// 5. Compute lambda_i = derive_interpolating_value(identifiers, identifier)
	myIDBytes := make([]byte, grp.ScalarLength())
	myIDVal := uint32(p.keyPackage.Identifier)
	// Encode as big-endian to match dealer.go convention
	for j := 0; j < 4 && j < len(myIDBytes); j++ {
		myIDBytes[len(myIDBytes)-1-j] = byte(myIDVal >> (8 * j))
	}

	myIDScalar, err := grp.DeserializeScalar(myIDBytes)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParameterError("myIDScalar", "failed to create", err)
	}

	lambda, err := polynomialHelper.DeriveInterpolatingValue(participantScalars, myIDScalar)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParameterError("lambda", "failed to compute interpolating value", err)
	}

	// 6. Compute challenge = H2(group_commitment || group_public_key || msg)
	challenge, err := challengeComputer.Compute(groupCommitment, p.keyPackage.GroupPublicKey, msg)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParameterError("challenge", "failed to compute", err)
	}

	// 7. Get binding_factor for this participant
	bindingFactor, err := bindingComputer.GetBindingFactor(bindingFactors, p.keyPackage.Identifier)
	if err != nil {
		return frost.SignatureShare{}, frost.NewParticipantError(p.keyPackage.Identifier, "binding factor not found", err)
	}

	// 8. Compute sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * secret_share * challenge)
	// sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda * secret_share * challenge)

	// Part 1: hiding_nonce
	sigShare := nonces.HidingNonce.Copy()

	// Part 2: binding_nonce * binding_factor
	bindingPart := nonces.BindingNonce.Mul(bindingFactor)
	sigShare = sigShare.Add(bindingPart)

	// Part 3: lambda * secret_share * challenge
	secretPart := lambda.Mul(p.keyPackage.SecretShare).Mul(challenge)
	sigShare = sigShare.Add(secretPart)

	// 9. Return signature share
	return frost.SignatureShare{
		Identifier:     p.keyPackage.Identifier,
		SignatureShare: sigShare,
	}, nil
}

// VerifySignatureShare implements Participant.VerifySignatureShare
//
// Verifies a signature share from another participant using identifiable abort.
// This allows detection of malicious participants who provide invalid shares.
//
// Algorithm (from RFC 9591 Section 5.4):
// 1. Compute binding factors
// 2. Compute group commitment
// 3. Get participant identifiers
// 4. Compute lambda_i for the share's participant
// 5. Compute challenge
// 6. Get participant's commitment from list
// 7. Get participant's verification share
// 8. Verify: ScalarBaseMult(sig_share) == hiding_commitment + binding_factor*binding_commitment + lambda_i*verification_key*challenge
func (p *participant) VerifySignatureShare(share frost.SignatureShare, msg []byte, commitmentList frost.CommitmentList) error {
	grp := p.suite.Group()

	// Import helper functions
	encoder := helpers.NewCommitmentListEncoder(grp)
	bindingComputer := helpers.NewBindingFactorComputer(p.suite)
	groupCommitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	polynomialHelper := helpers.NewPolynomialHelper(grp)
	challengeComputer := helpers.NewChallengeComputer(p.suite)

	// 1. Validate commitment list
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return err
	}

	// 2. Compute binding factors
	bindingFactors, err := bindingComputer.Compute(p.keyPackage.GroupPublicKey, commitmentList, msg)
	if err != nil {
		return frost.NewParameterError("bindingFactors", "failed to compute", err)
	}

	// 3. Compute group commitment (for challenge computation)
	groupCommitment, err := groupCommitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		return frost.NewParameterError("groupCommitment", "failed to compute", err)
	}

	// 4. Get participant identifiers from commitment list
	participants := encoder.GetParticipants(commitmentList)

	// Convert participant identifiers to scalars for interpolation
	participantScalars := make([]group.Scalar, len(participants))
	for i, id := range participants {
		// Create scalar from identifier (little-endian for ristretto255)
		idBytes := make([]byte, grp.ScalarLength())
		idVal := uint32(id)
		// Encode as little-endian to match ristretto255 native format
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idVal >> (8 * j))
		}

		scalar, err := grp.DeserializeScalar(idBytes)
		if err != nil {
			return frost.NewParameterError("participantScalar", "failed to create", err)
		}
		participantScalars[i] = scalar
	}

	// 5. Compute lambda_i for the share's participant
	shareIDBytes := make([]byte, grp.ScalarLength())
	shareIDVal := uint32(share.Identifier)
	// Encode as little-endian to match ristretto255 native format
	for j := 0; j < 4 && j < len(shareIDBytes); j++ {
		shareIDBytes[j] = byte(shareIDVal >> (8 * j))
	}

	shareIDScalar, err := grp.DeserializeScalar(shareIDBytes)
	if err != nil {
		return frost.NewParameterError("shareIDScalar", "failed to create", err)
	}

	lambda, err := polynomialHelper.DeriveInterpolatingValue(participantScalars, shareIDScalar)
	if err != nil {
		return frost.NewParameterError("lambda", "failed to compute interpolating value", err)
	}

	// 6. Compute challenge = H2(group_commitment || group_public_key || msg)
	challenge, err := challengeComputer.Compute(groupCommitment, p.keyPackage.GroupPublicKey, msg)
	if err != nil {
		return frost.NewParameterError("challenge", "failed to compute", err)
	}

	// 7. Get binding_factor for the share's participant
	bindingFactor, err := bindingComputer.GetBindingFactor(bindingFactors, share.Identifier)
	if err != nil {
		return frost.NewParticipantError(share.Identifier, "binding factor not found", err)
	}

	// 8. Get participant's commitment from list
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
		return frost.NewParticipantError(share.Identifier, "commitment not found in list", frost.ErrInvalidCommitment)
	}

	// 9. Compute participant's verification share (public key) by evaluating
	// the verification polynomial at the participant's identifier.
	// This is the counterpart to secret share evaluation in key generation.
	// PK_i = sum_{j=0}^{degree} (commitment_j * identifier^j)
	//
	// NOTE: Must use little-endian encoding to match ristretto255 native format.
	// The ristretto255 library's DeserializeScalar expects little-endian bytes.

	// Convert participant identifier to scalar using LITTLE-ENDIAN encoding
	// (matching ristretto255 native format used in vss.go)
	polyIDBytes := make([]byte, grp.ScalarLength())
	polyIDValue := uint32(share.Identifier)
	for j := 0; j < 4 && j < len(polyIDBytes); j++ {
		polyIDBytes[j] = byte(polyIDValue >> (8 * j))
	}

	polyIDScalar, err := grp.DeserializeScalar(polyIDBytes)
	if err != nil {
		return frost.NewParameterError("polyIDScalar", "failed to create", err)
	}

	// Compute identifier^j for each power
	verificationKey := grp.Identity()
	idPower := grp.NewScalar()

	// Start with id^0 = 1
	oneBytes := make([]byte, grp.ScalarLength())
	oneBytes[0] = 1
	idPower, _ = grp.DeserializeScalar(oneBytes)

	// Evaluate polynomial: sum_{j=0}^{degree} (commitment_j * identifier^j)
	for j := 0; j < len(p.keyPackage.VerificationShares); j++ {
		// Term = commitment[j] * identifier^j
		term := grp.ScalarMult(p.keyPackage.VerificationShares[j].VerificationKey, idPower)
		verificationKey = verificationKey.Add(term)

		// Update power for next iteration: identifier^(j+1) = identifier^j * identifier
		if j < len(p.keyPackage.VerificationShares)-1 {
			idPower = idPower.Mul(polyIDScalar)
		}
	}

	// 10. Verify: ScalarBaseMult(sig_share) == hiding_commitment + binding_factor*binding_commitment + lambda_i*verification_key*challenge
	// Left side: sig_share * G
	leftSide := grp.ScalarBaseMult(share.SignatureShare)

	// Right side: hiding_commitment + binding_factor*binding_commitment + lambda_i*verification_key*challenge
	// Part 1: hiding_commitment
	rightSide := participantCommitment.HidingNonceCommitment.Copy()

	// Part 2: binding_factor * binding_commitment
	bindingPart := grp.ScalarMult(participantCommitment.BindingNonceCommitment, bindingFactor)
	rightSide = rightSide.Add(bindingPart)

	// Part 3: lambda * verification_key * challenge
	// First: verification_key * challenge
	verificationPart := grp.ScalarMult(verificationKey, challenge)
	// Then: result * lambda
	verificationPart = grp.ScalarMult(verificationPart, lambda)
	rightSide = rightSide.Add(verificationPart)

	// Compare left and right sides
	if !leftSide.Equal(rightSide) {
		return frost.NewVerificationError("signature share", "verification equation failed", frost.ErrInvalidSignatureShare)
	}

	return nil
}
