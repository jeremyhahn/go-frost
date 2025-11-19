// Package secp256k1_sha256 implements the FROST(secp256k1, SHA-256) ciphersuite.
//
// This ciphersuite uses secp256k1 (Bitcoin/blockchain curve) for the prime-order group
// and SHA-256 for all hash functions. It implements RFC 9591 Section 6.5.
//
// Context string: "FROST-secp256k1-SHA256-v1"
//
// The ciphersuite provides five domain-separated hash functions:
// - H1: Used for binding factor computation (domain: "rho")
// - H2: Used for challenge computation (domain: "chal")
// - H3: Used for nonce generation (domain: "nonce")
// - H4: Used for message hashing (domain: "msg")
// - H5: Used for commitment list hashing (domain: "com")
package secp256k1_sha256

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/secp256k1"
)

// Ensure Secp256k1SHA256 implements the Ciphersuite interface
var _ ciphersuite.Ciphersuite = (*Secp256k1SHA256)(nil)

const (
	// contextString is the domain separation string for this ciphersuite
	contextString = "FROST-secp256k1-SHA256-v1"

	// Domain separation tags for hash functions
	domainH1 = "rho"   // Binding factor
	domainH2 = "chal"  // Challenge
	domainH3 = "nonce" // Nonce generation
	domainH4 = "msg"   // Message hashing
	domainH5 = "com"   // Commitment list hashing
)

// Secp256k1SHA256 implements the FROST(secp256k1, SHA-256) ciphersuite.
type Secp256k1SHA256 struct {
	group *secp256k1.Group
}

// New creates a new Secp256k1SHA256 ciphersuite instance.
func New() *Secp256k1SHA256 {
	return &Secp256k1SHA256{
		group: secp256k1.NewGroup(),
	}
}

// ID returns the unique identifier for this ciphersuite.
func (cs *Secp256k1SHA256) ID() string {
	return contextString
}

// Name returns a human-readable name for this ciphersuite.
func (cs *Secp256k1SHA256) Name() string {
	return "FROST(secp256k1, SHA-256)"
}

// ContextString returns the domain separation context string.
func (cs *Secp256k1SHA256) ContextString() string {
	return contextString
}

// Group returns the secp256k1 group implementation.
func (cs *Secp256k1SHA256) Group() group.Group {
	return cs.group
}

// Hash computes SHA-256 hash of the input data.
func (cs *Secp256k1SHA256) Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// H1 is a domain-separated hash-to-scalar function for binding factor computation.
// Implements: H(contextString || "rho" || data) -> Scalar
func (cs *Secp256k1SHA256) H1(data []byte) group.Scalar {
	return cs.hashToScalar(domainH1, data)
}

// H2 is a domain-separated hash-to-scalar function for challenge computation.
// Implements: H(contextString || "chal" || data) -> Scalar
func (cs *Secp256k1SHA256) H2(data []byte) group.Scalar {
	return cs.hashToScalar(domainH2, data)
}

// H3 is a domain-separated hash-to-scalar function for nonce generation.
// Implements: H(contextString || "nonce" || data) -> Scalar
func (cs *Secp256k1SHA256) H3(data []byte) group.Scalar {
	return cs.hashToScalar(domainH3, data)
}

// H4 is a domain-separated hash function for message hashing.
// Implements: H(contextString || "msg" || data) -> bytes
func (cs *Secp256k1SHA256) H4(msg []byte) []byte {
	input := cs.domainSeparate(domainH4, msg)
	return cs.Hash(input)
}

// H5 is a domain-separated hash function for commitment list hashing.
// Implements: H(contextString || "com" || data) -> bytes
func (cs *Secp256k1SHA256) H5(data []byte) []byte {
	input := cs.domainSeparate(domainH5, data)
	return cs.Hash(input)
}

// HashToCurve maps arbitrary byte strings to group elements.
// This uses a hash-and-increment approach for secp256k1.
// We hash the input and attempt to decode it as a point. If that fails,
// we increment a counter and try again until we find a valid point.
func (cs *Secp256k1SHA256) HashToCurve(data []byte) (group.Element, error) {
	// Use a domain-separated hash for hash-to-curve
	input := cs.domainSeparate("h2c", data)

	// Try up to 256 iterations to find a valid point
	for i := 0; i < 256; i++ {
		// Hash the input with counter
		counterBuf := []byte{byte(i)}
		hashInput := append(input, counterBuf...)
		hash := cs.Hash(hashInput)

		// Try to construct a point from the hash
		// Use the hash as x-coordinate and solve for y
		x := new(big.Int).SetBytes(hash)
		// Reduce x modulo the field prime
		x.Mod(x, secp.S256().P)

		// Try to find a valid y for this x
		if point := cs.tryFindPoint(x); point != nil {
			return point, nil
		}
	}

	// This should be extremely unlikely to happen
	return nil, frost.NewParameterError("data", "failed to find valid curve point after 256 attempts", frost.ErrDeserializationFailed)
}

// tryFindPoint attempts to find a valid point on the curve with the given x-coordinate.
func (cs *Secp256k1SHA256) tryFindPoint(x *big.Int) group.Element {
	// Try compressed point encoding with both 0x02 and 0x03 prefixes
	for _, prefix := range []byte{0x02, 0x03} {
		compressed := make([]byte, 33)
		compressed[0] = prefix
		xBytes := x.Bytes()
		// Ensure x is within valid range and pad to 32 bytes
		if len(xBytes) > 32 {
			continue
		}
		copy(compressed[33-len(xBytes):], xBytes)

		elem, err := cs.group.DeserializeElement(compressed)
		if err == nil {
			return elem
		}
	}

	return nil
}

// VerifySignature verifies a FROST signature against a message and public key.
// Implements Schnorr signature verification for secp256k1.
//
// Signature format: R (33 bytes) || z (32 bytes)
// Verification equation: z * G == R + c * PK
// where c = H2(R || PK || msg)
func (cs *Secp256k1SHA256) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
	// Validate inputs
	if publicKey == nil {
		return frost.NewParameterError("publicKey", "public key is nil", frost.ErrInvalidParameters)
	}

	if publicKey.IsIdentity() {
		return frost.NewVerificationError("signature", "public key is identity element", frost.ErrIdentityElement)
	}

	// Signature format: R (33 bytes) || z (32 bytes)
	expectedLen := cs.group.ElementLength() + cs.group.ScalarLength()
	if len(signature) != expectedLen {
		return frost.NewParameterError("signature", "invalid signature length", frost.ErrInvalidSignature)
	}

	// Extract R and z from signature
	rBytes := signature[:cs.group.ElementLength()]
	zBytes := signature[cs.group.ElementLength():]

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

// hashToScalar implements hash-to-scalar for secp256k1 using SHA-256.
// According to RFC 9591 Section 6.5, this uses wide reduction modulo the group order.
func (cs *Secp256k1SHA256) hashToScalar(domain string, data []byte) group.Scalar {
	// Create domain-separated input
	input := cs.domainSeparate(domain, data)

	// Hash with SHA-256 (32 bytes output)
	hash := cs.Hash(input)

	// For secp256k1 with SHA-256, we need to perform wide reduction
	// We can hash again to get 64 bytes for better uniformity
	hash2 := cs.Hash(append(hash, 0x00))
	wideHash := append(hash, hash2...)

	// Convert to big.Int and reduce modulo group order
	// Get the group order from secp256k1
	groupOrder := secp.S256().N

	hashInt := new(big.Int).SetBytes(wideHash)
	hashInt.Mod(hashInt, groupOrder)

	// Convert to ModNScalar
	var scalar secp.ModNScalar
	scalar.SetByteSlice(hashInt.Bytes())

	return secp256k1.NewScalar(scalar)
}

// domainSeparate prepends the context string and domain tag to the data.
// Returns: contextString || domain || data
func (cs *Secp256k1SHA256) domainSeparate(domain string, data []byte) []byte {
	result := bytes.NewBuffer(nil)
	result.WriteString(contextString)
	result.WriteString(domain)
	if data != nil {
		result.Write(data)
	}
	return result.Bytes()
}
