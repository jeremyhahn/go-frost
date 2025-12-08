// Package ed448_shake256 implements the FROST(Ed448, SHAKE256) ciphersuite.
//
// This ciphersuite uses Ed448 for the prime-order group and SHAKE256 for
// all hash functions. It implements RFC 9591 Section 6.3.
//
// Context string: "FROST-ED448-SHAKE256-v1"
//
// CRITICAL DIFFERENCE from other ciphersuites:
// SHAKE256 is an extendable-output function (XOF), not a fixed-output hash.
// We use SHAKE256 to generate variable-length output as needed.
//
// Per RFC 9591 Section 6.3, H2 uses the prefix "SigEd448" || 0x00 || 0x00
// for compatibility with RFC 8032 Ed448 signatures. This is different from
// Ed25519 which has no prefix at all.
//
// The ciphersuite provides five domain-separated hash functions:
// - H1: Used for binding factor computation (domain: "rho")
// - H2: Used for challenge computation (prefix: "SigEd448" || 0x00 || 0x00)
// - H3: Used for nonce generation (domain: "nonce")
// - H4: Used for message hashing (domain: "msg")
// - H5: Used for commitment list hashing (domain: "com")
package ed448_shake256

import (
	"bytes"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"golang.org/x/crypto/sha3"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ed448"
)

// Ensure Ed448SHAKE256 implements the Ciphersuite interface
var _ ciphersuite.Ciphersuite = (*Ed448SHAKE256)(nil)

const (
	// contextString is the domain separation string for this ciphersuite
	contextString = "FROST-ED448-SHAKE256-v1"

	// Domain separation tags for hash functions
	domainH1 = "rho"   // Binding factor
	domainH3 = "nonce" // Nonce generation
	domainH4 = "msg"   // Message hashing
	domainH5 = "com"   // Commitment list hashing

	// H2 prefix for RFC 8032 Ed448 compatibility
	// Per RFC 9591 Section 6.3: H2(m) = H("SigEd448" || 0 || 0 || m)
	ed448H2Prefix = "SigEd448"

	// hashOutputSize is the output size for SHAKE256 when used as a hash function
	// For hash-to-scalar, we use 2x the scalar size for wide reduction (114 bytes)
	hashOutputSize = 114
)

// Ed448SHAKE256 implements the FROST(Ed448, SHAKE256) ciphersuite.
type Ed448SHAKE256 struct {
	group *ed448.Group
}

// New creates a new Ed448SHAKE256 ciphersuite instance.
func New() *Ed448SHAKE256 {
	return &Ed448SHAKE256{
		group: ed448.NewGroup(),
	}
}

// ID returns the unique identifier for this ciphersuite.
func (cs *Ed448SHAKE256) ID() string {
	return contextString
}

// Name returns a human-readable name for this ciphersuite.
func (cs *Ed448SHAKE256) Name() string {
	return "FROST(Ed448, SHAKE256)"
}

// ContextString returns the domain separation context string.
func (cs *Ed448SHAKE256) ContextString() string {
	return contextString
}

// Group returns the Ed448 group implementation.
func (cs *Ed448SHAKE256) Group() group.Group {
	return cs.group
}

// Hash computes SHAKE256 hash of the input data with a fixed output length.
// For general hashing, we use 114 bytes (2x the scalar size for wide reduction).
func (cs *Ed448SHAKE256) Hash(data []byte) []byte {
	hash := sha3.NewShake256()
	hash.Write(data)
	output := make([]byte, hashOutputSize)
	hash.Read(output)
	return output
}

// H1 is a domain-separated hash-to-scalar function for binding factor computation.
// Implements: SHAKE256(contextString || "rho" || data) -> Scalar
func (cs *Ed448SHAKE256) H1(data []byte) group.Scalar {
	return cs.hashToScalar(domainH1, data)
}

// H2 is a hash-to-scalar function for challenge computation.
// Per RFC 9591 Section 6.3, H2 uses the Ed448 signature prefix for RFC 8032 compatibility.
// Implements: SHAKE256("SigEd448" || 0x00 || 0x00 || data) -> Scalar
func (cs *Ed448SHAKE256) H2(data []byte) group.Scalar {
	// Per RFC 9591 Section 6.3:
	// H2(m): Implemented by computing H("SigEd448" || 0 || 0 || m)
	// The two zero bytes represent the empty context string for Ed448ph compatibility
	hash := sha3.NewShake256()
	hash.Write([]byte(ed448H2Prefix)) // "SigEd448"
	hash.Write([]byte{0x00, 0x00})    // Two zero bytes (empty context length + empty context)
	hash.Write(data)

	// Read 114 bytes for wide reduction (2x the 57-byte scalar size)
	output := make([]byte, hashOutputSize)
	hash.Read(output)

	// Use NewScalarFromBytes for proper reduction
	return ed448.NewScalarFromBytes(output)
}

// H3 is a domain-separated hash-to-scalar function for nonce generation.
// Implements: SHAKE256(contextString || "nonce" || data) -> Scalar
func (cs *Ed448SHAKE256) H3(data []byte) group.Scalar {
	return cs.hashToScalar(domainH3, data)
}

// H4 is a domain-separated hash function for message hashing.
// Implements: SHAKE256(contextString || "msg" || data) -> bytes
func (cs *Ed448SHAKE256) H4(msg []byte) []byte {
	input := cs.domainSeparate(domainH4, msg)
	return cs.Hash(input)
}

// H5 is a domain-separated hash function for commitment list hashing.
// Implements: SHAKE256(contextString || "com" || data) -> bytes
func (cs *Ed448SHAKE256) H5(data []byte) []byte {
	input := cs.domainSeparate(domainH5, data)
	return cs.Hash(input)
}

// HDKG is a domain-separated hash-to-scalar function for DKG operations.
// Used for computing challenges in the Schnorr proof of knowledge during DKG.
// Implements: SHAKE256(contextString || "dkg" || data) -> Scalar
func (cs *Ed448SHAKE256) HDKG(data []byte) group.Scalar {
	return cs.hashToScalar("dkg", data)
}

// HID is a domain-separated hash-to-scalar function for identifier derivation.
// Used to derive participant identifiers from arbitrary byte strings.
// Implements: SHAKE256(contextString || "id" || data) -> Scalar
func (cs *Ed448SHAKE256) HID(data []byte) group.Scalar {
	return cs.hashToScalar("id", data)
}

// HashToCurve maps arbitrary byte strings to group elements.
// This uses a hash-and-increment approach for edwards448.
// We hash the input and attempt to decode it as a point. If that fails,
// we increment a counter and try again until we find a valid point.
func (cs *Ed448SHAKE256) HashToCurve(data []byte) (group.Element, error) {
	// Use a domain-separated hash for hash-to-curve
	input := cs.domainSeparate("h2c", data)

	curve := goldilocks.Curve{}

	// Try up to 256 iterations to find a valid point
	for i := 0; i < 256; i++ {
		// Hash the input with counter using SHAKE256
		counterBuf := []byte{byte(i)}
		hashInput := append(input, counterBuf...)

		hash := sha3.NewShake256()
		hash.Write(hashInput)

		// Read 57 bytes for Ed448 point encoding
		pointBytes := make([]byte, 57)
		hash.Read(pointBytes)

		// Try to decode as a point
		point, err := goldilocks.FromBytes(pointBytes)
		if err == nil && curve.IsOnCurve(point) {
			// Successfully decoded a valid point on the curve
			return ed448.NewElement(point), nil
		}
		// If decoding failed or point not on curve, try the next counter value
	}

	// This should be extremely unlikely to happen
	return nil, frost.NewParameterError("data", "failed to find valid curve point after 256 attempts", frost.ErrDeserializationFailed)
}

// VerifySignature verifies a FROST signature against a message and public key.
// Implements Schnorr signature verification for Ed448.
//
// Signature format: R (57 bytes) || z (57 bytes)
// Verification equation: z * G == R + c * PK
// where c = H2(R || PK || msg)
func (cs *Ed448SHAKE256) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
	// Validate inputs
	if publicKey == nil {
		return frost.NewParameterError("publicKey", "public key is nil", frost.ErrInvalidParameters)
	}

	if publicKey.IsIdentity() {
		return frost.NewVerificationError("signature", "public key is identity element", frost.ErrIdentityElement)
	}

	// Signature format: R (57 bytes) || z (57 bytes)
	if len(signature) != 114 {
		return frost.NewParameterError("signature", "invalid signature length", frost.ErrInvalidSignature)
	}

	// Extract R and z from signature
	rBytes := signature[:57]
	zBytes := signature[57:114]

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

// hashToScalar implements hash-to-scalar for Ed448 using SHAKE256.
// According to RFC 9591 Section 6.3, this uses wide reduction modulo the group order.
func (cs *Ed448SHAKE256) hashToScalar(domain string, data []byte) group.Scalar {
	// Create domain-separated input
	input := cs.domainSeparate(domain, data)

	// Hash with SHAKE256, reading 114 bytes (2x the scalar size)
	hash := sha3.NewShake256()
	hash.Write(input)
	output := make([]byte, hashOutputSize)
	hash.Read(output)

	// Use NewScalarFromBytes for proper reduction
	return ed448.NewScalarFromBytes(output)
}

// domainSeparate prepends the context string and domain tag to the data.
// Returns: contextString || domain || data
func (cs *Ed448SHAKE256) domainSeparate(domain string, data []byte) []byte {
	result := bytes.NewBuffer(nil)
	result.WriteString(contextString)
	result.WriteString(domain)
	if data != nil {
		result.Write(data)
	}
	return result.Bytes()
}
