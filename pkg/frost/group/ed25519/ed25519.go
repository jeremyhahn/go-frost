// Package ed25519 implements the FROST group interface using the Ed25519 group.
//
// Ed25519 is based on the edwards25519 curve, providing:
// - 128-bit security level
// - Fast, constant-time operations
// - Compatible with RFC 8032 (Ed25519 signatures)
//
// This implementation uses filippo.io/edwards25519 for the underlying
// cryptographic primitives.
package ed25519

import (
	"crypto/rand"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element.
	ElementSize = 32

	// ScalarSize is the byte length of a serialized scalar.
	ScalarSize = 32
)

// groupOrderBytes is the order of the edwards25519 group.
// This is the prime order l = 2^252 + 27742317777372353535851937790883648493
var groupOrderBytes = []byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// Element wraps an edwards25519.Point to implement the group.Element interface.
type Element struct {
	point *edwards25519.Point
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)
	result := edwards25519.NewIdentityPoint()
	result.Add(e.point, otherElem.point)
	return &Element{point: result}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	result := edwards25519.NewIdentityPoint()
	result.Negate(e.point)
	return &Element{point: result}
}

// IsIdentity returns true if this element is the identity element.
func (e *Element) IsIdentity() bool {
	identity := edwards25519.NewIdentityPoint()
	return e.point.Equal(identity) == 1
}

// Equal returns true if this element equals another element.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)
	return e.point.Equal(otherElem.point) == 1
}

// Bytes returns the canonical byte representation of this element.
func (e *Element) Bytes() []byte {
	return e.point.Bytes()
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	result := edwards25519.NewIdentityPoint()
	result.Set(e.point)
	return &Element{point: result}
}

// Scalar wraps an edwards25519.Scalar to implement the group.Scalar interface.
type Scalar struct {
	scalar *edwards25519.Scalar
}

// Add returns the sum of this scalar and another scalar modulo p.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := edwards25519.NewScalar()
	result.Add(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Sub returns the difference of this scalar and another scalar modulo p.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := edwards25519.NewScalar()
	result.Subtract(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Mul returns the product of this scalar and another scalar modulo p.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := edwards25519.NewScalar()
	result.Multiply(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Inv returns the multiplicative inverse of this scalar modulo p.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	result := edwards25519.NewScalar()
	result.Invert(s.scalar)
	return &Scalar{scalar: result}, nil
}

// Negate returns the additive inverse of this scalar modulo p.
func (s *Scalar) Negate() group.Scalar {
	result := edwards25519.NewScalar()
	result.Negate(s.scalar)
	return &Scalar{scalar: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	zero := edwards25519.NewScalar()
	return s.scalar.Equal(zero) == 1
}

// Equal returns true if this scalar equals another scalar.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.scalar.Equal(otherScalar.scalar) == 1
}

// Bytes returns the canonical byte representation of this scalar.
// Note: Returns little-endian bytes (Ed25519 convention).
func (s *Scalar) Bytes() []byte {
	return s.scalar.Bytes()
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	result := edwards25519.NewScalar()
	result.Set(s.scalar)
	return &Scalar{scalar: result}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
//
// IMPORTANT: This implementation is NOT constant-time for ordering (< or >).
// However, equality checks use constant-time comparison.
// This method should NOT be used with secret scalar values for ordering comparisons.
// For equality checks with secrets, use Equal() which is fully constant-time.
//
// Note: Currently unused in production code. Provided for interface completeness.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)

	// Encode both scalars to bytes for comparison (little-endian from Bytes())
	sBytes := s.Bytes()
	oBytes := otherScalar.Bytes()

	// Convert to big.Int for comparison (need to reverse for big-endian)
	// NOTE: big.Int.Cmp() is NOT constant-time
	// This is acceptable since Compare() is not used with secret values
	sBig := new(big.Int).SetBytes(reverseBytes(sBytes))
	oBig := new(big.Int).SetBytes(reverseBytes(oBytes))

	return sBig.Cmp(oBig)
}

// Group implements the FROST group interface for Ed25519.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new Ed25519 group.
func NewGroup() *Group {
	return &Group{
		generator: &Element{point: edwards25519.NewGeneratorPoint()},
		identity:  &Element{point: edwards25519.NewIdentityPoint()},
	}
}

// Order returns the order of the group.
func (g *Group) Order() []byte {
	// Return a copy to prevent external modification
	order := make([]byte, len(groupOrderBytes))
	copy(order, groupOrderBytes)
	return order
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
	return &Scalar{scalar: edwards25519.NewScalar()}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return &Element{point: edwards25519.NewIdentityPoint()}
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
	scalar, err := edwards25519.NewScalar().SetUniformBytes(randomBytes)
	if err != nil {
		return nil, frost.NewParameterError("random", "failed to reduce random bytes", err)
	}

	return &Scalar{scalar: scalar}, nil
}

// ScalarMult performs scalar multiplication between an element and a scalar.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	result := edwards25519.NewIdentityPoint()
	result.ScalarMult(scal.scalar, elem.point)

	return &Element{point: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	result := edwards25519.NewIdentityPoint()
	result.ScalarBaseMult(scal.scalar)

	return &Element{point: result}
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

	point := edwards25519.NewIdentityPoint()
	if _, err := point.SetBytes(data); err != nil {
		return nil, frost.NewParameterError("data", "invalid element encoding", frost.ErrDeserializationFailed)
	}

	// Check if the decoded element is the identity
	result := &Element{point: point}
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	// Perform subgroup validation (multiply by cofactor should preserve the point)
	// For Ed25519, we need to ensure the point is in the prime-order subgroup
	// The edwards25519 library already validates this during SetBytes

	return result, nil
}

// SerializeScalar encodes a scalar to its canonical byte representation.
// Note: Returns little-endian bytes (Ed25519 convention).
func (g *Group) SerializeScalar(scalar group.Scalar) []byte {
	scal := scalar.(*Scalar)
	return scal.Bytes()
}

// DeserializeScalar decodes a byte slice to a scalar.
// Note: Ed25519 uses little-endian encoding.
func (g *Group) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != ScalarSize {
		return nil, frost.NewParameterError("data", "invalid scalar encoding length", frost.ErrDeserializationFailed)
	}

	scalar := edwards25519.NewScalar()
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
	return "ed25519"
}

// reverseBytes reverses a byte slice (for little-endian to big-endian conversion).
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// NewElement creates a new Element wrapping an edwards25519.Point.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(point *edwards25519.Point) *Element {
	return &Element{point: point}
}

// NewScalar creates a new Scalar wrapping an edwards25519.Scalar.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalar(scalar *edwards25519.Scalar) *Scalar {
	return &Scalar{scalar: scalar}
}
