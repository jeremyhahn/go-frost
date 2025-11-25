package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// ChallengeComputer computes the signature challenge.
type ChallengeComputer interface {
	// Compute calculates the signature challenge scalar.
	//
	// Inputs:
	// - groupCommitment: The aggregated group commitment point (R)
	// - groupPublicKey: The group's public key
	// - msg: The message being signed
	//
	// Outputs:
	// - challenge: The challenge scalar
	//
	// The challenge is computed as:
	// H2(group_commitment || group_public_key || msg)
	Compute(groupCommitment group.Element, groupPublicKey group.Element, msg []byte) (group.Scalar, error)
}

// NewChallengeComputer creates a new challenge computer.
func NewChallengeComputer(suite ciphersuite.Ciphersuite) ChallengeComputer {
	return &challengeComputer{suite: suite}
}

type challengeComputer struct {
	suite ciphersuite.Ciphersuite
}

// Compute implements ChallengeComputer.Compute
//
// Calculates the signature challenge scalar.
// The challenge is computed as:
// H2(group_commitment || group_public_key || msg)
//
// Algorithm (from RFC 9591 Section 4.6):
// 1. Serialize group_commitment
// 2. Serialize group_public_key
// 3. Compute challenge_input = group_commitment_enc || group_public_key_enc || msg
// 4. Return H2(challenge_input)
func (c *challengeComputer) Compute(groupCommitment group.Element, groupPublicKey group.Element, msg []byte) (group.Scalar, error) {
	if groupCommitment == nil {
		return nil, frost.NewParameterError("groupCommitment", "cannot be nil", frost.ErrInvalidParameters)
	}

	if groupPublicKey == nil {
		return nil, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// 1. Serialize group_commitment
	groupCommitmentBytes := groupCommitment.Bytes()

	// 2. Serialize group_public_key
	groupPublicKeyBytes := groupPublicKey.Bytes()

	// 3. Compute challenge_input = group_commitment_enc || group_public_key_enc || msg
	challengeInput := append(groupCommitmentBytes, groupPublicKeyBytes...)
	challengeInput = append(challengeInput, msg...)

	// 4. Return H2(challenge_input)
	challenge := c.suite.H2(challengeInput)

	// A zero challenge indicates a potential hash collision or implementation bug.
	// This should essentially never happen with proper hash functions (probability ~2^-256).
	// Use VerificationError as this is a protocol-level failure, not a parameter issue.
	if challenge.IsZero() {
		return nil, frost.NewVerificationError("challenge", "computed challenge is zero - possible hash collision", frost.ErrInvalidChallenge)
	}

	return challenge, nil
}
