// Package dkg implements FROST's three-round Pedersen DKG with Schnorr proofs of knowledge; round 1 is broadcast, round 2 needs confidential authenticated channels.
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

// Round1Package is broadcast in round 1: polynomial commitments and a proof of knowledge.
type Round1Package struct {
	// Commitment contains commitments to the polynomial coefficients.
	// These are [g^a_0, g^a_1, ..., g^a_(t-1)] where t is minSigners.
	// The length must equal minSigners.
	Commitment []group.Element

	// ProofOfKnowledge is a Schnorr signature proving knowledge of a_0.
	// This protects against rogue-key attacks.
	ProofOfKnowledge Signature
}

// Round1SecretPackage holds the secret polynomial between rounds 1 and 2; never share it.
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

// Round2Package carries one participant's share; send it on a confidential, authenticated channel.
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

// Round2SecretPackage holds the participant's own share and commitment between rounds 2 and 3; never share it.
type Round2SecretPackage struct {
	// Identifier is this participant's unique ID
	Identifier frost.Identifier

	// Commitment is this participant's polynomial commitment, checked in round 3.
	Commitment []group.Element

	// SecretShare is this participant's own share f_i(i), added in round 3.
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

// Zeroize erases the secret coefficients; call it after round 2.
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

// Zeroize erases the secret share; call it after round 3.
func (sp *Round2SecretPackage) Zeroize() {
	runtime.KeepAlive(sp.SecretShare)
	if sp.SecretShare != nil {
		bytes := sp.SecretShare.Bytes()
		secmem.ZeroBytes(bytes)
		sp.SecretShare = sp.SecretShare.Sub(sp.SecretShare)
	}
	runtime.KeepAlive(sp.SecretShare)
}
