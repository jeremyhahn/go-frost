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

	secp "gitlab.com/yawning/secp256k1-voi"

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

// secp256k1 curve parameters
var (
	// groupOrder is the order of the secp256k1 group
	// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	groupOrder = new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})

	// fieldPrime is the field prime for secp256k1
	// p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	fieldPrime = new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
	})
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
		x.Mod(x, fieldPrime)

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

// hashToScalar implements hash-to-scalar for secp256k1 using hash_to_field from RFC 9380.
// Per RFC 9591 Section 6.5, this uses expand_message_xmd with SHA-256 and L=48.
func (cs *Secp256k1SHA256) hashToScalar(domain string, data []byte) group.Scalar {
	// DST = contextString || domain (e.g., "FROST-secp256k1-SHA256-v1" || "rho")
	dst := []byte(contextString + domain)

	// Use expand_message_xmd with L=48 bytes per RFC 9591 Section 6.5
	uniformBytes := expandMessageXMD(data, dst, 48)

	// Convert to big.Int and reduce modulo group order
	hashInt := new(big.Int).SetBytes(uniformBytes)
	hashInt.Mod(hashInt, groupOrder)

	// Convert to scalar via bytes
	scalarBytes := hashInt.Bytes()
	// Pad to 32 bytes (big-endian)
	padded := make([]byte, 32)
	copy(padded[32-len(scalarBytes):], scalarBytes)

	var buf [32]byte
	copy(buf[:], padded)
	// NewScalarFromBytes returns (scalar, wasReduced) where wasReduced is 0 if canonical, 1 if reduced
	// Since we already reduced modulo order, this should always succeed
	scalar, _ := secp.NewScalarFromBytes(&buf)

	return secp256k1.NewScalar(scalar)
}

// expandMessageXMD implements expand_message_xmd from RFC 9380 Section 5.3.1.
// This is used for hash_to_field to produce uniform random bytes.
//
// Parameters (for SHA-256):
// - b_in_bytes = 32 (SHA-256 output size)
// - s_in_bytes = 64 (SHA-256 input block size)
func expandMessageXMD(msg, dst []byte, lenInBytes int) []byte {
	const (
		bInBytes = 32 // SHA-256 output size
		sInBytes = 64 // SHA-256 input block size
	)

	// Step 1: ell = ceil(len_in_bytes / b_in_bytes)
	ell := (lenInBytes + bInBytes - 1) / bInBytes

	// Step 2: Abort checks (len(DST) <= 255, ell <= 255, len_in_bytes <= 65535)
	if ell > 255 || len(dst) > 255 || lenInBytes > 65535 {
		panic("expandMessageXMD: invalid parameters")
	}

	// Step 3: DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst)))

	// Step 4: Z_pad = I2OSP(0, s_in_bytes)
	zPad := make([]byte, sInBytes)

	// Step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
	libStr := []byte{byte(lenInBytes >> 8), byte(lenInBytes)}

	// Step 6: msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	msgPrime := make([]byte, 0, sInBytes+len(msg)+2+1+len(dstPrime))
	msgPrime = append(msgPrime, zPad...)
	msgPrime = append(msgPrime, msg...)
	msgPrime = append(msgPrime, libStr...)
	msgPrime = append(msgPrime, 0x00)
	msgPrime = append(msgPrime, dstPrime...)

	// Step 7: b_0 = H(msg_prime)
	b0Hash := sha256.Sum256(msgPrime)
	b0 := b0Hash[:]

	// Step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	b1Input := make([]byte, 0, bInBytes+1+len(dstPrime))
	b1Input = append(b1Input, b0...)
	b1Input = append(b1Input, 0x01)
	b1Input = append(b1Input, dstPrime...)
	b1Hash := sha256.Sum256(b1Input)
	b1 := b1Hash[:]

	// Collect b values
	uniformBytes := make([]byte, 0, ell*bInBytes)
	uniformBytes = append(uniformBytes, b1...)

	// Step 9-10: for i in (2, ..., ell): b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
	bPrev := b1
	for i := 2; i <= ell; i++ {
		// strxor(b_0, b_(i-1))
		xored := make([]byte, bInBytes)
		for j := 0; j < bInBytes; j++ {
			xored[j] = b0[j] ^ bPrev[j]
		}

		// H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
		biInput := make([]byte, 0, bInBytes+1+len(dstPrime))
		biInput = append(biInput, xored...)
		biInput = append(biInput, byte(i))
		biInput = append(biInput, dstPrime...)
		biHash := sha256.Sum256(biInput)
		bi := biHash[:]

		uniformBytes = append(uniformBytes, bi...)
		bPrev = bi
	}

	// Step 12: return substr(uniform_bytes, 0, len_in_bytes)
	return uniformBytes[:lenInBytes]
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
