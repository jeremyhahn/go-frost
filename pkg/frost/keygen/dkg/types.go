// Package dkg implements Distributed Key Generation for FROST.
//
// This package implements the DKG protocol from the FROST paper (Figure 1),
// which is a variant of Pedersen's DKG with Schnorr proofs of knowledge
// to protect against rogue-key attacks.
//
// The protocol consists of three rounds:
//
//  1. Part1: Each participant generates a secret polynomial and broadcasts
//     commitments to its coefficients along with a Schnorr proof of knowledge.
//
//  2. Part2: Each participant verifies the proofs from all other participants
//     and sends secret shares to each other participant on secure channels.
//
//  3. Part3: Each participant verifies received shares using VSS verification,
//     accumulates them to form the final signing share, and computes the
//     group public key.
//
// Security Requirements:
//   - Round 1 packages must be broadcast (all participants see the same values)
//   - Round 2 packages must be sent on confidential, authenticated channels
//   - All proofs and shares must be verified before use
package dkg

import (
	"runtime"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Signature represents a Schnorr signature used as a proof of knowledge.
// This proves that the participant knows the secret coefficient a_0
// without revealing it.
type Signature struct {
	// R is the commitment point: R = g^k where k is a random nonce
	R group.Element

	// Z is the response scalar: z = k + a_0 * challenge
	Z group.Scalar
}

// Round1Package is broadcast to all participants in round 1.
// It contains the public commitments to polynomial coefficients and
// a proof of knowledge of the secret coefficient.
type Round1Package struct {
	// Commitment contains commitments to the polynomial coefficients.
	// These are [g^a_0, g^a_1, ..., g^a_(t-1)] where t is minSigners.
	// The length must equal minSigners.
	Commitment []group.Element

	// ProofOfKnowledge is a Schnorr signature proving knowledge of a_0.
	// This protects against rogue-key attacks.
	ProofOfKnowledge Signature
}

// Round1SecretPackage contains secret data that must be kept private
// between round 1 and round 2. This includes the secret polynomial
// coefficients that will be used to generate shares for other participants.
//
// SECURITY: This package MUST NOT be shared with any other participant.
type Round1SecretPackage struct {
	// Identifier is this participant's unique ID
	Identifier frost.Identifier

	// Coefficients are the secret polynomial coefficients [a_0, a_1, ..., a_(t-1)]
	// where a_0 is this participant's secret contribution to the group secret.
	Coefficients []group.Scalar

	// Commitment contains commitments to the polynomial coefficients.
	// These are [g^a_0, g^a_1, ..., g^a_(t-1)].
	Commitment []group.Element

	// MinSigners is the threshold (t) - minimum participants needed to sign
	MinSigners uint32

	// MaxSigners is the total number of participants (n)
	MaxSigners uint32
}

// Round2Package is sent privately to each other participant in round 2.
// It contains the secret share computed for that specific participant.
//
// SECURITY: This package MUST be sent on a confidential, authenticated channel.
type Round2Package struct {
	// SigningShare is the secret share f_i(recipient_id) computed for the recipient.
	// This is a scalar value that the recipient will accumulate with shares
	// from other participants to form their final signing share.
	SigningShare group.Scalar
}

// Zeroize securely erases the signing share from memory.
// This should be called after the share has been transmitted.
func (p *Round2Package) Zeroize() {
	runtime.KeepAlive(p.SigningShare)
	if p.SigningShare != nil {
		bytes := p.SigningShare.Bytes()
		secmem.ZeroBytes(bytes)
		p.SigningShare = p.SigningShare.Sub(p.SigningShare)
	}
	runtime.KeepAlive(p.SigningShare)
}

// Round2SecretPackage contains secret data that must be kept private
// between round 2 and round 3. This includes the participant's own share
// and the commitment for verification.
//
// SECURITY: This package MUST NOT be shared with any other participant.
type Round2SecretPackage struct {
	// Identifier is this participant's unique ID
	Identifier frost.Identifier

	// Commitment contains this participant's polynomial commitments.
	// Used for verification in round 3.
	Commitment []group.Element

	// SecretShare is this participant's own share: f_i(i)
	// This is added to received shares in round 3.
	SecretShare group.Scalar

	// MinSigners is the threshold (t)
	MinSigners uint32

	// MaxSigners is the total number of participants (n)
	MaxSigners uint32
}

// PublicKeyPackage contains the public key material resulting from DKG.
// This includes the group public key and all participants' verification shares.
type PublicKeyPackage struct {
	// VerifyingShares maps each participant's identifier to their public share.
	// These are used to verify signature shares during signing.
	VerifyingShares map[frost.Identifier]group.Element

	// VerifyingKey is the group's public key: g^(sum of all a_0 values)
	// This is used to verify the final aggregated signature.
	VerifyingKey group.Element
}

// Zeroize securely erases the secret coefficients from memory.
// This should be called after round 2 is complete.
func (sp *Round1SecretPackage) Zeroize() {
	for i, coeff := range sp.Coefficients {
		runtime.KeepAlive(coeff)
		if coeff != nil {
			bytes := coeff.Bytes()
			secmem.ZeroBytes(bytes)
			sp.Coefficients[i] = coeff.Sub(coeff)
		}
	}
	for _, coeff := range sp.Coefficients {
		runtime.KeepAlive(coeff)
	}
}

// Zeroize securely erases the secret share from memory.
// This should be called after round 3 is complete.
func (sp *Round2SecretPackage) Zeroize() {
	runtime.KeepAlive(sp.SecretShare)
	if sp.SecretShare != nil {
		bytes := sp.SecretShare.Bytes()
		secmem.ZeroBytes(bytes)
		sp.SecretShare = sp.SecretShare.Sub(sp.SecretShare)
	}
	runtime.KeepAlive(sp.SecretShare)
}
