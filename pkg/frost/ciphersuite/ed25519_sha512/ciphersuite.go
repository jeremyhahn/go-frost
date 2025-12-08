// Package ed25519_sha512 implements the FROST(Ed25519, SHA-512) ciphersuite.
//
// This ciphersuite uses Ed25519 for the prime-order group and SHA-512 for
// all hash functions. It implements RFC 9591 Section 6.1.
//
// Context string: "FROST-ED25519-SHA512-v1"
//
// CRITICAL DIFFERENCE from ristretto255-sha512:
// H2 (challenge hash) does NOT use the contextString prefix for Ed25519
// compatibility with standard Ed25519 signatures.
//
// The ciphersuite provides five domain-separated hash functions:
// - H1: Used for binding factor computation (domain: "rho")
// - H2: Used for challenge computation (NO domain prefix - Ed25519 compat!)
// - H3: Used for nonce generation (domain: "nonce")
// - H4: Used for message hashing (domain: "msg")
// - H5: Used for commitment list hashing (domain: "com")
package ed25519_sha512

import (
	"bytes"
	"crypto/sha512"

	"filippo.io/edwards25519"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ed25519"
)

// Ensure Ed25519SHA512 implements the Ciphersuite interface
var _ ciphersuite.Ciphersuite = (*Ed25519SHA512)(nil)

const (
	// contextString is the domain separation string for this ciphersuite
	contextString = "FROST-ED25519-SHA512-v1"

	// Domain separation tags for hash functions
	domainH1 = "rho"   // Binding factor
	domainH2 = "chal"  // Challenge (NOTE: not used for H2 in Ed25519!)
	domainH3 = "nonce" // Nonce generation
	domainH4 = "msg"   // Message hashing
	domainH5 = "com"   // Commitment list hashing
)

// Ed25519SHA512 implements the FROST(Ed25519, SHA-512) ciphersuite.
type Ed25519SHA512 struct {
	group *ed25519.Group
}

// New creates a new Ed25519SHA512 ciphersuite instance.
func New() *Ed25519SHA512 {
	return &Ed25519SHA512{
		group: ed25519.NewGroup(),
	}
}

// ID returns the unique identifier for this ciphersuite.
func (cs *Ed25519SHA512) ID() string {
	return contextString
}

// Name returns a human-readable name for this ciphersuite.
func (cs *Ed25519SHA512) Name() string {
	return "FROST(Ed25519, SHA-512)"
}

// ContextString returns the domain separation context string.
func (cs *Ed25519SHA512) ContextString() string {
	return contextString
}

// Group returns the Ed25519 group implementation.
func (cs *Ed25519SHA512) Group() group.Group {
	return cs.group
}

// Hash computes SHA-512 hash of the input data.
func (cs *Ed25519SHA512) Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// H1 is a domain-separated hash-to-scalar function for binding factor computation.
// Implements: H(contextString || "rho" || data) -> Scalar
func (cs *Ed25519SHA512) H1(data []byte) group.Scalar {
	return cs.hashToScalar(domainH1, data)
}

// H2 is a hash-to-scalar function for challenge computation.
// CRITICAL: For Ed25519, H2 does NOT use contextString prefix!
// This ensures compatibility with standard Ed25519 signatures.
// Implements: H(data) -> Scalar (no domain separation)
func (cs *Ed25519SHA512) H2(data []byte) group.Scalar {
	// IMPORTANT: No contextString prefix for Ed25519 compatibility!
	// Hash the data directly
	hash := cs.Hash(data)

	// Use SetUniformBytes for proper wide reduction.
	// SECURITY NOTE: SetUniformBytes requires exactly 64 bytes. SHA-512 always
	// produces 64 bytes, so this should never fail. A failure here indicates
	// a bug in the cryptographic library implementation.
	if len(hash) != 64 {
		panic("FROST library bug: SHA-512 produced unexpected output length")
	}
	scalar, err := edwards25519.NewScalar().SetUniformBytes(hash)
	if err != nil {
		panic("FROST library bug: SetUniformBytes failed with valid 64-byte input: " + err.Error())
	}

	// Wrap in our Scalar type using the constructor
	return ed25519.NewScalar(scalar)
}

// H3 is a domain-separated hash-to-scalar function for nonce generation.
// Implements: H(contextString || "nonce" || data) -> Scalar
func (cs *Ed25519SHA512) H3(data []byte) group.Scalar {
	return cs.hashToScalar(domainH3, data)
}

// H4 is a domain-separated hash function for message hashing.
// Implements: H(contextString || "msg" || data) -> bytes
func (cs *Ed25519SHA512) H4(msg []byte) []byte {
	input := cs.domainSeparate(domainH4, msg)
	return cs.Hash(input)
}

// H5 is a domain-separated hash function for commitment list hashing.
// Implements: H(contextString || "com" || data) -> bytes
func (cs *Ed25519SHA512) H5(data []byte) []byte {
	input := cs.domainSeparate(domainH5, data)
	return cs.Hash(input)
}

// HDKG is a domain-separated hash-to-scalar function for DKG operations.
// Used for computing challenges in the Schnorr proof of knowledge during DKG.
// Implements: H(contextString || "dkg" || data) -> Scalar
func (cs *Ed25519SHA512) HDKG(data []byte) group.Scalar {
	return cs.hashToScalar("dkg", data)
}

// HID is a domain-separated hash-to-scalar function for identifier derivation.
// Used to derive participant identifiers from arbitrary byte strings.
// Implements: H(contextString || "id" || data) -> Scalar
func (cs *Ed25519SHA512) HID(data []byte) group.Scalar {
	return cs.hashToScalar("id", data)
}

// HashToCurve maps arbitrary byte strings to group elements.
// This uses a hash-and-increment approach for edwards25519.
// We hash the input and attempt to decode it as a point. If that fails,
// we increment a counter and try again until we find a valid point.
func (cs *Ed25519SHA512) HashToCurve(data []byte) (group.Element, error) {
	// Use a domain-separated hash for hash-to-curve
	input := cs.domainSeparate("h2c", data)

	// Try up to 256 iterations to find a valid point
	for i := 0; i < 256; i++ {
		// Hash the input with counter
		counterBuf := []byte{byte(i)}
		hashInput := append(input, counterBuf...)
		hash := cs.Hash(hashInput)

		// Try to decode the first 32 bytes as a point
		point := edwards25519.NewIdentityPoint()
		if _, err := point.SetBytes(hash[:32]); err == nil {
			// Successfully decoded a valid point
			return ed25519.NewElement(point), nil
		}
		// If decoding failed, try the next counter value
	}

	// This should be extremely unlikely to happen
	return nil, frost.NewParameterError("data", "failed to find valid curve point after 256 attempts", frost.ErrDeserializationFailed)
}

// VerifySignature verifies a FROST signature against a message and public key.
// Implements Schnorr signature verification for Ed25519.
//
// Signature format: R (32 bytes) || z (32 bytes)
// Verification equation: z * G == R + c * PK
// where c = H2(R || PK || msg)
func (cs *Ed25519SHA512) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
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

// hashToScalar implements hash-to-scalar for Ed25519 using SHA-512.
// According to RFC 9591 Section 6.1, this uses SetUniformBytes which
// performs wide reduction modulo the group order.
func (cs *Ed25519SHA512) hashToScalar(domain string, data []byte) group.Scalar {
	// Create domain-separated input
	input := cs.domainSeparate(domain, data)

	// Hash with SHA-512 (64 bytes output)
	hash := cs.Hash(input)

	// Use SetUniformBytes for proper wide reduction.
	// SECURITY NOTE: SetUniformBytes requires exactly 64 bytes. SHA-512 always
	// produces 64 bytes, so this should never fail. A failure here indicates
	// a bug in the cryptographic library implementation.
	if len(hash) != 64 {
		panic("FROST library bug: SHA-512 produced unexpected output length")
	}
	scalar, err := edwards25519.NewScalar().SetUniformBytes(hash)
	if err != nil {
		panic("FROST library bug: SetUniformBytes failed with valid 64-byte input: " + err.Error())
	}

	// Wrap in our Scalar type using the constructor
	return ed25519.NewScalar(scalar)
}

// domainSeparate prepends the context string and domain tag to the data.
// Returns: contextString || domain || data
func (cs *Ed25519SHA512) domainSeparate(domain string, data []byte) []byte {
	result := bytes.NewBuffer(nil)
	result.WriteString(contextString)
	result.WriteString(domain)
	if data != nil {
		result.Write(data)
	}
	return result.Bytes()
}
