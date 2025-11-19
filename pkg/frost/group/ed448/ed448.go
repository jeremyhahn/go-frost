// Package ed448 implements the FROST group interface using the Ed448 group.
//
// Ed448 is based on the edwards448 curve (Goldilocks), providing:
// - 224-bit security level (highest of all RFC 9591 ciphersuites)
// - Fast, constant-time operations
// - Compatible with RFC 8032 (Ed448 signatures)
//
// This implementation uses github.com/otrv4/ed448 for the underlying
// cryptographic primitives.
package ed448

import (
	"crypto/rand"
	"math/big"

	ed "github.com/otrv4/ed448"
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element.
	// Ed448 uses 57 bytes (448 bits + 8 bits for flags)
	ElementSize = 57

	// ScalarSize is the byte length of a serialized scalar.
	// Ed448 scalars are 57 bytes
	ScalarSize = 57

	// pointSize is the internal size used by the ed448 library (56 bytes = 448 bits)
	pointSize = 56

	// scalarSize is the internal size used by the ed448 library
	scalarSize = 57
)

// groupOrderBytes is the order of the edwards448 group.
// This is the prime order l = 2^446 - 13818066809895115352007386748515426880336692926039124645428935903040627522190572831145592726100
var groupOrderBytes = []byte{
	0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
	0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
	0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
	0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	0x00,
}

// Element wraps an ed448.Point to implement the group.Element interface.
type Element struct {
	point ed.Point
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)
	result := e.point.Copy()
	result.Add(e.point, otherElem.point)
	return &Element{point: result}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	// Create identity point (encoded as all zeros, 56 bytes for the library)
	identityBytes := make([]byte, pointSize)
	identity := ed.NewPointFromBytes([][]byte{identityBytes}...)

	result := identity.Copy()
	result.Sub(identity, e.point)
	return &Element{point: result}
}

// IsIdentity returns true if this element is the identity element.
func (e *Element) IsIdentity() bool {
	identityBytes := make([]byte, pointSize)
	identity := ed.NewPointFromBytes([][]byte{identityBytes}...)
	return e.point.Equals(identity)
}

// Equal returns true if this element equals another element.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)
	return e.point.Equals(otherElem.point)
}

// Bytes returns the canonical byte representation of this element.
func (e *Element) Bytes() []byte {
	encoded := e.point.Encode()
	// The library returns 56 bytes, but FROST expects 57 bytes
	// Pad with a zero byte at the end
	if len(encoded) == pointSize {
		result := make([]byte, ElementSize)
		copy(result, encoded)
		return result
	}
	return encoded
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	return &Element{point: e.point.Copy()}
}

// Scalar wraps an ed448.Scalar to implement the group.Scalar interface.
type Scalar struct {
	scalar ed.Scalar
}

// Add returns the sum of this scalar and another scalar modulo p.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := s.scalar.Copy()
	result.Add(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Sub returns the difference of this scalar and another scalar modulo p.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := s.scalar.Copy()
	result.Sub(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Mul returns the product of this scalar and another scalar modulo p.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := s.scalar.Copy()
	result.Mul(s.scalar, otherScalar.scalar)
	return &Scalar{scalar: result}
}

// Inv returns the multiplicative inverse of this scalar modulo p.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	result := s.scalar.Copy()
	if !result.Invert() {
		return nil, frost.NewParameterError("scalar", "failed to invert scalar", frost.ErrInvalidParameters)
	}
	return &Scalar{scalar: result}, nil
}

// Negate returns the additive inverse of this scalar modulo p.
func (s *Scalar) Negate() group.Scalar {
	// Negate by computing 0 - scalar
	zero := ed.NewScalar([][]byte{make([]byte, scalarSize)}...)
	result := zero.Copy()
	result.Sub(zero, s.scalar)
	return &Scalar{scalar: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	zero := ed.NewScalar([][]byte{make([]byte, scalarSize)}...)
	return s.scalar.Equals(zero)
}

// Equal returns true if this scalar equals another scalar.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.scalar.Equals(otherScalar.scalar)
}

// Bytes returns the canonical byte representation of this scalar.
// Note: Returns little-endian bytes (Ed448 convention).
func (s *Scalar) Bytes() []byte {
	encoded := s.scalar.Encode()
	// The library might return fewer than 57 bytes, pad to ScalarSize
	if len(encoded) < ScalarSize {
		result := make([]byte, ScalarSize)
		copy(result, encoded)
		return result
	}
	return encoded
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	return &Scalar{scalar: s.scalar.Copy()}
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

// Group implements the FROST group interface for Ed448.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new Ed448 group.
func NewGroup() *Group {
	identityBytes := make([]byte, pointSize) // Note: library uses 56 bytes for point encoding
	return &Group{
		generator: &Element{point: ed.BasePoint},
		identity:  &Element{point: ed.NewPointFromBytes([][]byte{identityBytes}...)},
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
	zeroBytes := make([]byte, scalarSize)
	return &Scalar{scalar: ed.NewScalar([][]byte{zeroBytes}...)}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return g.identity.Copy()
}

// RandomScalar generates a random scalar in the field.
func (g *Group) RandomScalar() (group.Scalar, error) {
	// Generate 114 random bytes for uniform reduction (2x the scalar size)
	randomBytes := make([]byte, 114)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, frost.NewParameterError("random", "failed to generate random bytes", err)
	}

	// Use BarretDecode for uniform reduction modulo the group order
	zeroBytes := make([]byte, scalarSize)
	scalar := ed.NewScalar([][]byte{zeroBytes}...)

	if err := scalar.BarretDecode(randomBytes); err != nil {
		return nil, frost.NewParameterError("random", "failed to decode random bytes", err)
	}

	return &Scalar{scalar: scalar}, nil
}

// ScalarMult performs scalar multiplication between an element and a scalar.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	result := ed.PointScalarMul(elem.point, scal.scalar)

	return &Element{point: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	result := ed.ScalarBaseMult(scal.scalar)

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

	// The library expects 56 bytes, so we trim the padding byte if present
	dataToUse := data
	if len(data) == ElementSize {
		dataToUse = data[:pointSize]
	}

	point := ed.NewPointFromBytes([][]byte{dataToUse}...)

	// Check if the point is on the curve
	if !point.IsOnCurve() {
		return nil, frost.NewParameterError("data", "point not on curve", frost.ErrDeserializationFailed)
	}

	// Check if the decoded element is the identity
	result := &Element{point: point}
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	return result, nil
}

// SerializeScalar encodes a scalar to its canonical byte representation.
// Note: Returns little-endian bytes (Ed448 convention).
func (g *Group) SerializeScalar(scalar group.Scalar) []byte {
	scal := scalar.(*Scalar)
	return scal.Bytes()
}

// DeserializeScalar decodes a byte slice to a scalar.
// Note: Ed448 uses little-endian encoding.
func (g *Group) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != ScalarSize {
		return nil, frost.NewParameterError("data", "invalid scalar encoding length", frost.ErrDeserializationFailed)
	}

	zeroBytes := make([]byte, scalarSize)
	scalar := ed.NewScalar([][]byte{zeroBytes}...)

	// The library expects exactly scalarSize bytes, trim padding if needed
	dataToUse := data
	if len(data) > scalarSize {
		dataToUse = data[:scalarSize]
	}

	scalar.Decode(dataToUse)

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
	return "ed448"
}

// reverseBytes reverses a byte slice (for little-endian to big-endian conversion).
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// NewElement creates a new Element wrapping an ed448.Point.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(point ed.Point) *Element {
	return &Element{point: point}
}

// NewScalar creates a new Scalar wrapping an ed448.Scalar.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalar(scalar ed.Scalar) *Scalar {
	return &Scalar{scalar: scalar}
}
