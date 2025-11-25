// Package ristretto255_sha512 implements the FROST(ristretto255, SHA-512) ciphersuite.
//
// This ciphersuite uses ristretto255 for the prime-order group and SHA-512 for
// all hash functions. It implements RFC 9591 Section 6.2.
//
// Context string: "FROST-RISTRETTO255-SHA512-v1"
//
// The ciphersuite provides five domain-separated hash functions:
// - H1: Used for binding factor computation (domain: "rho")
// - H2: Used for challenge computation (domain: "chal")
// - H3: Used for nonce generation (domain: "nonce")
// - H4: Used for message hashing (domain: "msg")
// - H5: Used for commitment list hashing (domain: "com")
package ristretto255_sha512

import (
	"bytes"
	"crypto/sha512"

	ristretto "github.com/gtank/ristretto255"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
)

// Ensure Ristretto255SHA512 implements the Ciphersuite interface
var _ ciphersuite.Ciphersuite = (*Ristretto255SHA512)(nil)

const (
	// contextString is the domain separation string for this ciphersuite
	contextString = "FROST-RISTRETTO255-SHA512-v1"

	// Domain separation tags for hash functions
	domainH1 = "rho"   // Binding factor
	domainH2 = "chal"  // Challenge
	domainH3 = "nonce" // Nonce generation
	domainH4 = "msg"   // Message hashing
	domainH5 = "com"   // Commitment list hashing
)

// Ristretto255SHA512 implements the FROST(ristretto255, SHA-512) ciphersuite.
type Ristretto255SHA512 struct {
	group *ristretto255.Group
}

// New creates a new Ristretto255SHA512 ciphersuite instance.
func New() *Ristretto255SHA512 {
	return &Ristretto255SHA512{
		group: ristretto255.NewGroup(),
	}
}

// ID returns the unique identifier for this ciphersuite.
func (cs *Ristretto255SHA512) ID() string {
	return contextString
}

// Name returns a human-readable name for this ciphersuite.
func (cs *Ristretto255SHA512) Name() string {
	return "FROST(ristretto255, SHA-512)"
}

// ContextString returns the domain separation context string.
func (cs *Ristretto255SHA512) ContextString() string {
	return contextString
}

// Group returns the ristretto255 group implementation.
func (cs *Ristretto255SHA512) Group() group.Group {
	return cs.group
}

// Hash computes SHA-512 hash of the input data.
func (cs *Ristretto255SHA512) Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// H1 is a domain-separated hash-to-scalar function for binding factor computation.
// Implements: H(contextString || "rho" || data) -> Scalar
func (cs *Ristretto255SHA512) H1(data []byte) group.Scalar {
	return cs.hashToScalar(domainH1, data)
}

// H2 is a domain-separated hash-to-scalar function for challenge computation.
// Implements: H(contextString || "chal" || data) -> Scalar
func (cs *Ristretto255SHA512) H2(data []byte) group.Scalar {
	return cs.hashToScalar(domainH2, data)
}

// H3 is a domain-separated hash-to-scalar function for nonce generation.
// Implements: H(contextString || "nonce" || data) -> Scalar
func (cs *Ristretto255SHA512) H3(data []byte) group.Scalar {
	return cs.hashToScalar(domainH3, data)
}

// H4 is a domain-separated hash function for message hashing.
// Implements: H(contextString || "msg" || data) -> bytes
func (cs *Ristretto255SHA512) H4(msg []byte) []byte {
	input := cs.domainSeparate(domainH4, msg)
	return cs.Hash(input)
}

// H5 is a domain-separated hash function for commitment list hashing.
// Implements: H(contextString || "com" || data) -> bytes
func (cs *Ristretto255SHA512) H5(data []byte) []byte {
	input := cs.domainSeparate(domainH5, data)
	return cs.Hash(input)
}

// HashToCurve maps arbitrary byte strings to group elements.
// This uses the hash-to-ristretto255 construction via SetUniformBytes.
func (cs *Ristretto255SHA512) HashToCurve(data []byte) (group.Element, error) {
	// Use a domain-separated hash for hash-to-curve
	input := cs.domainSeparate("h2c", data)

	// Hash the input with SHA-512 to get 64 bytes
	hash := cs.Hash(input)

	// Use SetUniformBytes to map the hash to a group element
	// This method requires exactly 64 bytes and performs the proper mapping
	elem := ristretto.NewElement()
	if _, err := elem.SetUniformBytes(hash); err != nil {
		return nil, frost.NewParameterError("data", "failed to map hash to curve point", err)
	}

	// Wrap in our Element type using the constructor
	return ristretto255.NewElement(elem), nil
}

// VerifySignature verifies a FROST signature against a message and public key.
// Implements Schnorr signature verification for ristretto255.
//
// Signature format: R (32 bytes) || z (32 bytes)
// Verification equation: z * G == R + c * PK
// where c = H2(R || PK || msg)
func (cs *Ristretto255SHA512) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
	// Validate inputs
	if publicKey == nil {
		return frost.NewParameterError("publicKey", "public key is nil", frost.ErrInvalidParameters)
	}

	if publicKey.IsIdentity() {
		return frost.NewVerificationError("signature", "public key is identity element", frost.ErrIdentityElement)
	}

	// Signature format: R (32 bytes) || z (32 bytes)
	if len(signature) != 64 {
		return frost.NewParameterError("signature", "invalid signature length", frost.ErrInvalidSignature)
	}

	// Extract R and z from signature
	rBytes := signature[:32]
	zBytes := signature[32:64]

	// Deserialize R (commitment)
	R, err := cs.group.DeserializeElement(rBytes)
	if err != nil {
		return frost.NewVerificationError("signature", "failed to deserialize R", err)
	}

	// Deserialize z (response scalar)
	z, err := cs.group.DeserializeScalar(zBytes)
	if err != nil {
		return frost.NewVerificationError("signature", "failed to deserialize z", err)
	}

	// Compute challenge: c = H2(R || PK || msg)
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)

	c := cs.H2(challengeInput.Bytes())

	// Verify: z * G == R + c * PK
	// Compute left side: z * G
	left := cs.group.ScalarBaseMult(z)

	// Compute right side: R + c * PK
	cPK := cs.group.ScalarMult(publicKey, c)
	right := R.Add(cPK)

	// Check if left == right
	if !left.Equal(right) {
		return frost.NewVerificationError("signature", "signature verification failed", frost.ErrInvalidSignature)
	}

	return nil
}

// hashToScalar implements hash-to-scalar for ristretto255 using SHA-512.
// According to RFC 9591 Section 6.2, this uses SetUniformBytes which
// performs wide reduction modulo the group order.
func (cs *Ristretto255SHA512) hashToScalar(domain string, data []byte) group.Scalar {
	// Create domain-separated input
	input := cs.domainSeparate(domain, data)

	// Hash with SHA-512 (64 bytes output)
	hash := cs.Hash(input)

	// Use FromUniformBytes for proper wide reduction
	// This is the ristretto255 way of doing hash-to-scalar
	scalar := ristretto.NewScalar()
	scalar.FromUniformBytes(hash)

	// Wrap in our Scalar type using the constructor
	return ristretto255.NewScalar(scalar)
}

// domainSeparate prepends the context string and domain tag to the data.
// Returns: contextString || domain || data
func (cs *Ristretto255SHA512) domainSeparate(domain string, data []byte) []byte {
	result := bytes.NewBuffer(nil)
	result.WriteString(contextString)
	result.WriteString(domain)
	if data != nil {
		result.Write(data)
	}
	return result.Bytes()
}
