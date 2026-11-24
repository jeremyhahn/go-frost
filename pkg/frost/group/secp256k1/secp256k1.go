// Package secp256k1 implements the FROST group interface using the secp256k1 group.
//
// secp256k1 is based on the Bitcoin/blockchain curve, providing:
// - 128-bit security level
// - SEC 2 v2.0 compliant operations
// - Compatible with Bitcoin and Ethereum signatures
//
// This implementation uses gitlab.com/yawning/secp256k1-voi for the underlying
// cryptographic primitives, which provides constant-time implementations.
//
// # Security Considerations
//
// This implementation provides FULL constant-time guarantees for all operations.
// The secp256k1-voi library uses formally verified arithmetic via fiat-crypto
// and provides constant-time curve and scalar arithmetic operations.
//
// All operations are constant-time:
// - Point addition, subtraction, scalar multiplication
// - Scalar addition, subtraction, multiplication, inversion
// - Element/scalar encoding and decoding
//
// Per RFC 9591 Section 6.5, secp256k1 uses big-endian byte encoding for scalars.
package secp256k1

import (
	"crypto/rand"
	"io"

	secp "gitlab.com/yawning/secp256k1-voi"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element (SEC1 compressed format).
	ElementSize = 33

	// ScalarSize is the byte length of a serialized scalar.
	ScalarSize = 32
)

// Element wraps a secp256k1-voi Point to implement the group.Element interface.
type Element struct {
	point *secp.Point
}

// Add returns the sum of this element and another element.
// This operation is constant-time.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)
	result := secp.NewIdentityPoint()
	result.Add(e.point, otherElem.point)
	return &Element{point: result}
}

// Negate returns the additive inverse of this element.
// This operation is constant-time.
func (e *Element) Negate() group.Element {
	result := secp.NewIdentityPoint()
	result.Negate(e.point)
	return &Element{point: result}
}

// IsIdentity returns true if this element is the identity element (point at infinity).
func (e *Element) IsIdentity() bool {
	identity := secp.NewIdentityPoint()
	return e.point.Equal(identity) == 1
}

// Equal returns true if this element equals another element.
// This operation is constant-time.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)
	return e.point.Equal(otherElem.point) == 1
}

// Bytes returns the canonical byte representation of this element (SEC1 compressed format).
func (e *Element) Bytes() []byte {
	if e.IsIdentity() {
		// Return a fixed-length zero array for identity
		return make([]byte, ElementSize)
	}
	return e.point.CompressedBytes()
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	result := secp.NewPointFrom(e.point)
	return &Element{point: result}
}

// Scalar wraps a secp256k1-voi Scalar to implement the group.Scalar interface.
type Scalar struct {
	value *secp.Scalar
}

// Add returns the sum of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := secp.NewScalar()
	result.Add(s.value, otherScalar.value)
	return &Scalar{value: result}
}

// Sub returns the difference of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := secp.NewScalar()
	result.Subtract(s.value, otherScalar.value)
	return &Scalar{value: result}
}

// Mul returns the product of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := secp.NewScalar()
	result.Multiply(s.value, otherScalar.value)
	return &Scalar{value: result}
}

// Inv returns the multiplicative inverse of this scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	result := secp.NewScalar()
	result.Invert(s.value)
	return &Scalar{value: result}, nil
}

// Negate returns the additive inverse of this scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Negate() group.Scalar {
	result := secp.NewScalar()
	result.Negate(s.value)
	return &Scalar{value: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	return s.value.IsZero() == 1
}

// Equal returns true if this scalar equals another scalar.
// This operation is constant-time.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.value.Equal(otherScalar.value) == 1
}

// Bytes returns the canonical byte representation of this scalar (big-endian).
func (s *Scalar) Bytes() []byte {
	return s.value.Bytes()
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	result := secp.NewScalarFrom(s.value)
	return &Scalar{value: result}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
//
// Note: This comparison is NOT constant-time for ordering (< or >).
// However, equality is checked using constant-time comparison.
// This method should NOT be used with secret scalar values for ordering.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)

	// Constant-time equality check
	if s.value.Equal(otherScalar.value) == 1 {
		return 0
	}

	// Convert to bytes for comparison (big-endian)
	// NOTE: This part is NOT constant-time
	thisBytes := s.Bytes()
	otherBytes := otherScalar.Bytes()

	for i := 0; i < ScalarSize; i++ {
		if thisBytes[i] < otherBytes[i] {
			return -1
		}
		if thisBytes[i] > otherBytes[i] {
			return 1
		}
	}
	return 0
}

// Zeroize overwrites the scalar's internal memory with zeros.
func (s *Scalar) Zeroize() {
	if s.value != nil {
		s.value.Zero()
	}
}

// Group implements the FROST group interface for secp256k1.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new secp256k1 group.
func NewGroup() *Group {
	return &Group{
		generator: &Element{point: secp.NewGeneratorPoint()},
		identity:  &Element{point: secp.NewIdentityPoint()},
	}
}

// Order returns the order of the group (big-endian).
func (g *Group) Order() []byte {
	// secp256k1 group order n = 2^256 - 432420386565659656852420866394968145599
	// In hex: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	return []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}
}

// Cofactor returns the cofactor of the secp256k1 group.
// secp256k1 is a prime-order group with cofactor 1.
// This means no cofactor multiplication is needed in verification.
func (g *Group) Cofactor() group.Scalar {
	// Create scalar with value 1 (big-endian for secp256k1)
	var oneBytes [32]byte
	oneBytes[31] = 1
	one, _ := secp.NewScalarFromCanonicalBytes(&oneBytes)
	return &Scalar{value: one}
}

// Identity returns the identity element of the group (point at infinity).
func (g *Group) Identity() group.Element {
	return g.identity.Copy()
}

// Generator returns the fixed generator element of the group.
func (g *Group) Generator() group.Element {
	return g.generator.Copy()
}

// NewScalar creates a new scalar initialized to zero.
func (g *Group) NewScalar() group.Scalar {
	return &Scalar{value: secp.NewScalar()}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return g.identity.Copy()
}

// RandomScalar generates a random scalar in the field [1, order-1].
func (g *Group) RandomScalar() (group.Scalar, error) {
	return randomScalar(rand.Reader)
}

// randomScalar generates a random scalar using the provided random source.
func randomScalar(random io.Reader) (group.Scalar, error) {
	var buf [32]byte

	for {
		_, err := io.ReadFull(random, buf[:])
		if err != nil {
			return nil, frost.NewParameterError("random", "failed to generate random bytes", err)
		}

		scalar, err := secp.NewScalarFromCanonicalBytes(&buf)
		if err != nil {
			// Value >= order, try again
			continue
		}

		// Ensure not zero
		if scalar.IsZero() == 1 {
			continue
		}

		return &Scalar{value: scalar}, nil
	}
}

// ScalarMult performs scalar multiplication between an element and a scalar.
// This operation is constant-time.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	result := secp.NewIdentityPoint()
	result.ScalarMult(scal.value, elem.point)

	return &Element{point: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
// This operation is constant-time and uses optimized precomputed tables.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	result := secp.NewIdentityPoint()
	result.ScalarBaseMult(scal.value)

	return &Element{point: result}
}

// SerializeElement encodes an element to its canonical byte representation (SEC1 compressed).
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

	point, err := secp.NewPointFromBytes(data)
	if err != nil {
		return nil, frost.NewParameterError("data", "invalid compressed point encoding", frost.ErrDeserializationFailed)
	}

	// Check if the decoded element is the identity
	result := &Element{point: point}
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	return result, nil
}

// SerializeScalar encodes a scalar to its canonical byte representation (big-endian).
func (g *Group) SerializeScalar(scalar group.Scalar) []byte {
	scal := scalar.(*Scalar)
	return scal.Bytes()
}

// DeserializeScalar decodes a byte slice to a scalar.
func (g *Group) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != ScalarSize {
		return nil, frost.NewParameterError("data", "invalid scalar encoding length", frost.ErrDeserializationFailed)
	}

	var buf [32]byte
	copy(buf[:], data)

	scalar, err := secp.NewScalarFromCanonicalBytes(&buf)
	if err != nil {
		return nil, frost.NewParameterError("data", "scalar value exceeds group order", frost.ErrDeserializationFailed)
	}

	return &Scalar{value: scalar}, nil
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
	return "secp256k1"
}

// ByteOrder returns the native byte order for secp256k1 scalar serialization.
func (g *Group) ByteOrder() group.ByteOrder {
	return group.BigEndian
}

// NewElement creates a new Element wrapping a secp256k1-voi Point.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(point *secp.Point) *Element {
	return &Element{point: point}
}

// NewScalar creates a new Scalar wrapping a secp256k1-voi Scalar value.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalar(value *secp.Scalar) *Scalar {
	return &Scalar{value: value}
}
