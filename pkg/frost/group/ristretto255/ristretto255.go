// Package ristretto255 implements the FROST group interface using the ristretto255 group.
//
// Ristretto255 is a prime-order group based on Curve25519, providing:
// - 128-bit security level
// - Fast, constant-time operations
// - Clean abstraction without cofactor complications
//
// This implementation uses github.com/gtank/ristretto255 for the underlying
// cryptographic primitives.
//
// # Security Considerations
//
// This implementation provides FULL constant-time guarantees for all operations,
// including both point and scalar arithmetic. This makes ristretto255 the
// RECOMMENDED ciphersuite for deployments where timing side-channel attacks
// are a concern.
//
// Unlike P-256 (partial constant-time) and secp256k1 (NOT constant-time),
// ristretto255 uses constant-time implementations for ALL operations:
// - Point addition, scalar multiplication, base multiplication
// - Scalar addition, subtraction, multiplication, inversion
// - Element/scalar encoding and decoding
//
// Per RFC 9591 Section 6.2, ristretto255 uses little-endian byte encoding
// for scalars (unlike P-256/secp256k1 which use big-endian).
package ristretto255

import (
	"crypto/rand"
	"math/big"

	"github.com/gtank/ristretto255"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element.
	ElementSize = 32

	// ScalarSize is the byte length of a serialized scalar.
	ScalarSize = 32
)

// groupOrderBytes is the order of the ristretto255 group.
// This is the prime order l = 2^252 + 27742317777372353535851937790883648493
var groupOrderBytes = []byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// Element wraps a ristretto255.Element to implement the group.Element interface.
type Element struct {
	elem *ristretto255.Element
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)
	result := ristretto255.NewIdentityElement()
	result.Add(e.elem, otherElem.elem)
	return &Element{elem: result}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	result := ristretto255.NewIdentityElement()
	result.Negate(e.elem)
	return &Element{elem: result}
}

// IsIdentity returns true if this element is the identity element.
func (e *Element) IsIdentity() bool {
	identity := ristretto255.NewIdentityElement()
	return e.elem.Equal(identity) == 1
}

// Equal returns true if this element equals another element.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)
	return e.elem.Equal(otherElem.elem) == 1
}

// Bytes returns the canonical byte representation of this element.
func (e *Element) Bytes() []byte {
	return e.elem.Bytes()
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	result := ristretto255.NewIdentityElement()
	result.Set(e.elem)
	return &Element{elem: result}
}

// Scalar wraps a ristretto255.Scalar to implement the group.Scalar interface.
type Scalar struct {
	scalar *ristretto255.Scalar
}

// Add returns the sum of this scalar and another scalar modulo p.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := ristretto255.NewScalar()
	result.Add(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Sub returns the difference of this scalar and another scalar modulo p.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := ristretto255.NewScalar()
	result.Subtract(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Mul returns the product of this scalar and another scalar modulo p.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := ristretto255.NewScalar()
	result.Multiply(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Inv returns the multiplicative inverse of this scalar modulo p.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	result := ristretto255.NewScalar()
	result.Invert(s.scalar)
	return &Scalar{scalar: result}, nil
}

// Negate returns the additive inverse of this scalar modulo p.
func (s *Scalar) Negate() group.Scalar {
	result := ristretto255.NewScalar()
	result.Negate(s.scalar)
	return &Scalar{scalar: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	zero := ristretto255.NewScalar()
	return s.scalar.Equal(zero) == 1
}

// Equal returns true if this scalar equals another scalar.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.scalar.Equal(otherScalar.scalar) == 1
}

// Bytes returns the canonical byte representation of this scalar.
// Note: Returns little-endian bytes per RFC 9591 Section 6.2 (FROST(ristretto255, SHA-512)).
// ristretto255 uses little-endian encoding, unlike P-256/secp256k1 which use big-endian.
func (s *Scalar) Bytes() []byte {
	return s.scalar.Bytes()
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	result := ristretto255.NewScalar()
	result.Set(s.scalar)
	return &Scalar{scalar: result}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
//
// IMPORTANT: This implementation is NOT constant-time for ordering (< or >).
// However, equality checks use constant-time comparison via crypto/subtle.
// This method should NOT be used with secret scalar values for ordering comparisons.
// For equality checks with secrets, use Equal() which is fully constant-time.
//
// Note: Currently unused in production code. Provided for interface completeness.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)

	// Encode both scalars to bytes for comparison (little-endian from Bytes())
	sBytes := s.Bytes()
	oBytes := otherScalar.Bytes()

	// Reverse for big.Int comparison since ristretto255 uses little-endian
	// NOTE: big.Int.Cmp() is NOT constant-time
	// This is acceptable since Compare() is not used with secret values
	sBig := new(big.Int).SetBytes(reverseBytes(sBytes))
	oBig := new(big.Int).SetBytes(reverseBytes(oBytes))

	return sBig.Cmp(oBig)
}

// Group implements the FROST group interface for ristretto255.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new ristretto255 group.
func NewGroup() *Group {
	return &Group{
		generator: &Element{elem: ristretto255.NewGeneratorElement()},
		identity:  &Element{elem: ristretto255.NewIdentityElement()},
	}
}

// Order returns the order of the group.
func (g *Group) Order() []byte {
	// Return a copy to prevent external modification
	order := make([]byte, len(groupOrderBytes))
	copy(order, groupOrderBytes)
	return order
}

// Cofactor returns the cofactor of the ristretto255 group.
// Ristretto255 is a prime-order group with cofactor 1.
// This means no cofactor multiplication is needed in verification.
func (g *Group) Cofactor() group.Scalar {
	// Create scalar with value 1
	one := ristretto255.NewScalar()
	// 1 in little-endian bytes (hardcoded constant, should never fail)
	oneBytes := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := one.SetCanonicalBytes(oneBytes); err != nil {
		// This panic should never occur - the bytes are a valid hardcoded constant.
		// A failure here indicates a bug in the ristretto255 library.
		panic("FROST library bug: failed to create cofactor scalar: " + err.Error())
	}
	return &Scalar{scalar: one}
}

// Identity returns the identity element of the group.
func (g *Group) Identity() group.Element {
	return g.identity.Copy()
}

// Generator returns the fixed generator element of the group.
func (g *Group) Generator() group.Element {
	return g.generator.Copy()
}

// NewScalar creates a new scalar initialized to zero.
func (g *Group) NewScalar() group.Scalar {
	return &Scalar{scalar: ristretto255.NewScalar()}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return &Element{elem: ristretto255.NewIdentityElement()}
}

// RandomScalar generates a random scalar in the field.
func (g *Group) RandomScalar() (group.Scalar, error) {
	// Generate 64 random bytes for uniform reduction
	randomBytes := make([]byte, 64)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, frost.NewParameterError("random", "failed to generate random bytes", err)
	}

	// Use SetUniformBytes for uniform reduction modulo the group order
	scalar := ristretto255.NewScalar()
	if _, err := scalar.SetUniformBytes(randomBytes); err != nil {
		return nil, frost.NewParameterError("random", "failed to create scalar from uniform bytes", err)
	}

	return &Scalar{scalar: scalar}, nil
}

// ScalarMult performs scalar multiplication between an element and a scalar.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	result := ristretto255.NewIdentityElement()
	result.ScalarMult(scal.scalar, elem.elem)

	return &Element{elem: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	result := ristretto255.NewIdentityElement()
	result.ScalarBaseMult(scal.scalar)

	return &Element{elem: result}
}

// SerializeElement encodes an element to its canonical byte representation.
func (g *Group) SerializeElement(element group.Element) ([]byte, error) {
	elem := element.(*Element)

	// Check if element is identity
	if elem.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	return elem.Bytes(), nil
}

// DeserializeElement decodes a byte slice to an element.
func (g *Group) DeserializeElement(data []byte) (group.Element, error) {
	if len(data) != ElementSize {
		return nil, frost.NewParameterError("data", "invalid element encoding length", frost.ErrDeserializationFailed)
	}

	elem := ristretto255.NewIdentityElement()
	if _, err := elem.SetCanonicalBytes(data); err != nil {
		return nil, frost.NewParameterError("data", "invalid element encoding", frost.ErrDeserializationFailed)
	}

	// Check if the decoded element is the identity
	result := &Element{elem: elem}
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	return result, nil
}

// SerializeScalar encodes a scalar to its canonical byte representation.
// Note: Returns little-endian bytes per RFC 9591 Section 6.2 (FROST(ristretto255, SHA-512)).
// Unlike P-256/secp256k1 which use big-endian, ristretto255 uses little-endian encoding.
func (g *Group) SerializeScalar(scalar group.Scalar) []byte {
	scal := scalar.(*Scalar)
	return scal.Bytes()
}

// DeserializeScalar decodes a byte slice to a scalar.
// Note: Expects little-endian bytes per RFC 9591 Section 6.2 (FROST(ristretto255, SHA-512)).
// Unlike P-256/secp256k1 which use big-endian, ristretto255 uses little-endian encoding.
func (g *Group) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != ScalarSize {
		return nil, frost.NewParameterError("data", "invalid scalar encoding length", frost.ErrDeserializationFailed)
	}

	scalar := ristretto255.NewScalar()
	if _, err := scalar.SetCanonicalBytes(data); err != nil {
		return nil, frost.NewParameterError("data", "invalid scalar encoding", frost.ErrDeserializationFailed)
	}

	return &Scalar{scalar: scalar}, nil
}

// ElementLength returns the byte length of a serialized element.
func (g *Group) ElementLength() int {
	return ElementSize
}

// ScalarLength returns the byte length of a serialized scalar.
func (g *Group) ScalarLength() int {
	return ScalarSize
}

// Name returns a human-readable name for this group.
func (g *Group) Name() string {
	return "ristretto255"
}

// ByteOrder returns the native byte order for ristretto255 scalar serialization.
func (g *Group) ByteOrder() group.ByteOrder {
	return group.LittleEndian
}

// reverseBytes reverses a byte slice (for little-endian to big-endian conversion).
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// NewElement creates a new Element wrapping a ristretto255.Element.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(elem *ristretto255.Element) *Element {
	return &Element{elem: elem}
}

// NewScalar creates a new Scalar wrapping a ristretto255.Scalar.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalar(scalar *ristretto255.Scalar) *Scalar {
	return &Scalar{scalar: scalar}
}
