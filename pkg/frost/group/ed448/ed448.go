// Package ed448 implements the FROST group interface using the Ed448 group.
//
// Ed448 is based on the edwards448 curve (Goldilocks), providing:
// - 224-bit security level (highest of all RFC 9591 ciphersuites)
// - Fast, constant-time operations
// - Compatible with RFC 8032 (Ed448 signatures)
//
// This implementation uses github.com/cloudflare/circl/ecc/goldilocks for the
// underlying cryptographic primitives.
package ed448

import (
	"crypto/rand"
	"math/big"

	"github.com/cloudflare/circl/ecc/goldilocks"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element.
	// Ed448 uses 57 bytes (448 bits + sign bit, aligned to bytes)
	ElementSize = 57

	// ScalarSize is the byte length of a serialized scalar.
	// Ed448 scalars are 57 bytes in RFC encoding
	ScalarSize = 57

	// internalScalarSize is the scalar size used by the circl library
	internalScalarSize = 56
)

// groupOrderBytes is the order of the edwards448 group (little-endian).
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

// groupOrder is the group order as big.Int (little-endian bytes converted)
var groupOrder *big.Int

func init() {
	// Convert little-endian group order bytes to big.Int
	groupOrder = new(big.Int).SetBytes(reverseBytes(groupOrderBytes[:56]))
}

// Element wraps a goldilocks.Point to implement the group.Element interface.
type Element struct {
	point *goldilocks.Point
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)
	curve := goldilocks.Curve{}
	result := curve.Add(e.point, otherElem.point)
	return &Element{point: result}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	curve := goldilocks.Curve{}
	identity := curve.Identity()
	// Negate by computing 0 - P
	// We need to use the curve's negation: -P has the same x but negated y
	// For Goldilocks, we can compute identity - P = -P
	// However, circl doesn't have a direct Sub operation
	// We need to use the Add with a negated point

	// Get the bytes, negate the sign bit, and reconstruct
	pointBytes, _ := e.point.MarshalBinary()

	// For Edwards curves, negating a point flips the sign of the x coordinate
	// The sign bit is the LSB of the last byte
	negBytes := make([]byte, len(pointBytes))
	copy(negBytes, pointBytes)
	negBytes[len(negBytes)-1] ^= 0x80 // Flip the sign bit

	negPoint, err := goldilocks.FromBytes(negBytes)
	if err != nil {
		// If decoding fails, fall back to computing 2*identity - P (which equals -P)
		// This shouldn't happen for valid points
		twoIdentity := curve.Double(identity)
		negPoint = curve.Add(twoIdentity, e.point)
	}

	return &Element{point: negPoint}
}

// IsIdentity returns true if this element is the identity element.
func (e *Element) IsIdentity() bool {
	curve := goldilocks.Curve{}
	identity := curve.Identity()

	// Compare by encoding
	eBytes, _ := e.point.MarshalBinary()
	iBytes, _ := identity.MarshalBinary()

	if len(eBytes) != len(iBytes) {
		return false
	}
	for i := range eBytes {
		if eBytes[i] != iBytes[i] {
			return false
		}
	}
	return true
}

// Equal returns true if this element equals another element.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)

	eBytes, _ := e.point.MarshalBinary()
	oBytes, _ := otherElem.point.MarshalBinary()

	if len(eBytes) != len(oBytes) {
		return false
	}
	for i := range eBytes {
		if eBytes[i] != oBytes[i] {
			return false
		}
	}
	return true
}

// Bytes returns the canonical byte representation of this element.
func (e *Element) Bytes() []byte {
	encoded, _ := e.point.MarshalBinary()
	return encoded
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	encoded, _ := e.point.MarshalBinary()
	newPoint, _ := goldilocks.FromBytes(encoded)
	return &Element{point: newPoint}
}

// Scalar wraps a goldilocks.Scalar to implement the group.Scalar interface.
// Uses constant-time operations for all arithmetic to prevent timing attacks.
type Scalar struct {
	value goldilocks.Scalar
}

// Add returns the sum of this scalar and another scalar modulo p.
// Uses constant-time addition from goldilocks library.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result goldilocks.Scalar
	result.Add(&s.value, &otherScalar.value)
	return &Scalar{value: result}
}

// Sub returns the difference of this scalar and another scalar modulo p.
// Uses constant-time subtraction from goldilocks library.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result goldilocks.Scalar
	result.Sub(&s.value, &otherScalar.value)
	return &Scalar{value: result}
}

// Mul returns the product of this scalar and another scalar modulo p.
// Uses constant-time multiplication from goldilocks library.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result goldilocks.Scalar
	result.Mul(&s.value, &otherScalar.value)
	return &Scalar{value: result}
}

// Inv returns the multiplicative inverse of this scalar modulo p.
// Note: Uses big.Int for modular inverse computation. This is acceptable
// because Inv is only used for Lagrange coefficient computation with public
// participant identifiers, not secret values.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	// Convert to big.Int for inverse computation
	bigEndian := reverseBytes(s.value[:])
	value := new(big.Int).SetBytes(bigEndian)
	result := new(big.Int).ModInverse(value, groupOrder)
	if result == nil {
		return nil, frost.NewParameterError("scalar", "failed to invert scalar", frost.ErrInvalidParameters)
	}
	// Convert back to goldilocks.Scalar
	var invScalar goldilocks.Scalar
	invScalar.FromBytes(reverseBytes(result.Bytes()))
	return &Scalar{value: invScalar}, nil
}

// Negate returns the additive inverse of this scalar modulo p.
// Uses constant-time negation from goldilocks library.
func (s *Scalar) Negate() group.Scalar {
	var result goldilocks.Scalar
	copy(result[:], s.value[:])
	result.Neg()
	return &Scalar{value: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	return s.value.IsZero()
}

// Equal returns true if this scalar equals another scalar.
// Uses constant-time comparison.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	// Constant-time comparison using XOR
	var diff byte
	for i := 0; i < len(s.value); i++ {
		diff |= s.value[i] ^ otherScalar.value[i]
	}
	return diff == 0
}

// Bytes returns the canonical byte representation of this scalar.
// Note: Returns little-endian bytes (Ed448 convention), padded to 57 bytes.
func (s *Scalar) Bytes() []byte {
	// goldilocks.Scalar is already little-endian, just pad to 57 bytes
	result := make([]byte, ScalarSize)
	copy(result, s.value[:])
	return result
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	var result goldilocks.Scalar
	copy(result[:], s.value[:])
	return &Scalar{value: result}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
// Note: This comparison is NOT constant-time and should only be used for
// sorting public values, not for comparisons involving secrets.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)
	// Convert to big.Int for comparison (big-endian for proper ordering)
	selfBE := reverseBytes(s.value[:])
	otherBE := reverseBytes(otherScalar.value[:])
	selfInt := new(big.Int).SetBytes(selfBE)
	otherInt := new(big.Int).SetBytes(otherBE)
	return selfInt.Cmp(otherInt)
}

// Zeroize overwrites the scalar's internal memory with zeros.
func (s *Scalar) Zeroize() {
	for i := range s.value {
		s.value[i] = 0
	}
}

// Group implements the FROST group interface for Ed448.
type Group struct {
	curve     goldilocks.Curve
	generator *Element
	identity  *Element
}

// NewGroup creates a new Ed448 group.
func NewGroup() *Group {
	curve := goldilocks.Curve{}
	return &Group{
		curve:     curve,
		generator: &Element{point: curve.Generator()},
		identity:  &Element{point: curve.Identity()},
	}
}

// Order returns the order of the group (little-endian).
func (g *Group) Order() []byte {
	// Return a copy to prevent external modification
	order := make([]byte, len(groupOrderBytes))
	copy(order, groupOrderBytes)
	return order
}

// Cofactor returns the cofactor of the Ed448 group.
// Ed448 has a cofactor of 4 (the curve order is 4 * prime_order).
// This is used in signature verification to ensure RFC 9591 compliance.
func (g *Group) Cofactor() group.Scalar {
	// Create scalar with value 4
	var four goldilocks.Scalar
	// 4 in little-endian bytes (56 bytes for goldilocks internal representation)
	four[0] = 4
	return &Scalar{value: four}
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
	var zero goldilocks.Scalar
	return &Scalar{value: zero}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return g.identity.Copy()
}

// RandomScalar generates a random scalar in the field.
func (g *Group) RandomScalar() (group.Scalar, error) {
	// Generate random bytes (use 64 bytes for uniform distribution after reduction)
	randomBytes := make([]byte, 64)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, frost.NewParameterError("random", "failed to generate random bytes", err)
	}

	// Use goldilocks.Scalar.FromBytes which reduces mod order
	var scalar goldilocks.Scalar
	scalar.FromBytes(randomBytes)

	return &Scalar{value: scalar}, nil
}

// ScalarMult performs scalar multiplication between an element and a scalar.
// Uses constant-time scalar multiplication from goldilocks library.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	// Use the goldilocks.Scalar directly
	result := g.curve.ScalarMult(&scal.value, elem.point)
	return &Element{point: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
// Uses constant-time scalar multiplication from goldilocks library.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	// Use the goldilocks.Scalar directly
	result := g.curve.ScalarBaseMult(&scal.value)
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

	point, err := goldilocks.FromBytes(data)
	if err != nil {
		return nil, frost.NewParameterError("data", "failed to decode point", frost.ErrDeserializationFailed)
	}

	// Check if the point is on the curve
	if !g.curve.IsOnCurve(point) {
		return nil, frost.NewParameterError("data", "point not on curve", frost.ErrDeserializationFailed)
	}

	// Check if the decoded element is the identity
	result := &Element{point: point}
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	// Verify the point is in the prime-order subgroup by checking [l]P == Identity,
	// where l is the group order. Ed448 has cofactor 4, so points on the curve
	// may be in a subgroup of order 4*l. Without this check, small-order or
	// mixed-order points could be accepted, which would compromise VSS/DKG security.
	orderScalar := &Scalar{}
	copy(orderScalar.value[:], groupOrderBytes[:internalScalarSize])
	lP := g.curve.ScalarMult(&orderScalar.value, point)
	lPElem := &Element{point: lP}
	if !lPElem.IsIdentity() {
		return nil, frost.NewParameterError("data", "point not in prime-order subgroup", frost.ErrDeserializationFailed)
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
// Per RFC 9591, this function rejects scalars >= group order rather than reducing them.
func (g *Group) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != ScalarSize {
		return nil, frost.NewParameterError("data", "invalid scalar encoding length", frost.ErrDeserializationFailed)
	}

	// Convert little-endian bytes to big.Int for range check
	bigEndian := reverseBytes(data[:internalScalarSize])
	value := new(big.Int).SetBytes(bigEndian)

	// Reject scalars >= group order (canonical check per RFC 9591)
	if value.Cmp(groupOrder) >= 0 {
		return nil, frost.NewParameterError("data", "scalar value >= group order", frost.ErrDeserializationFailed)
	}

	// Create goldilocks.Scalar from valid bytes
	var scalar goldilocks.Scalar
	copy(scalar[:], data[:internalScalarSize])

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
	return "ed448"
}

// ByteOrder returns the native byte order for Ed448 scalar serialization.
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

// NewElement creates a new Element wrapping a goldilocks.Point.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(point *goldilocks.Point) *Element {
	return &Element{point: point}
}

// NewScalar creates a new Scalar from a big.Int value.
// This is used by ciphersuites to create scalars.
func NewScalar(value *big.Int) *Scalar {
	// Reduce value modulo group order
	reduced := new(big.Int).Mod(value, groupOrder)
	// Convert to goldilocks.Scalar (little-endian)
	var scalar goldilocks.Scalar
	bytes := reduced.Bytes()
	littleEndian := reverseBytes(bytes)
	copy(scalar[:], littleEndian)
	return &Scalar{value: scalar}
}

// NewScalarFromBytes creates a new Scalar from little-endian bytes.
// This is primarily used by the ciphersuite for hash-to-scalar operations.
// Uses constant-time reduction via goldilocks.Scalar.FromBytes.
func NewScalarFromBytes(data []byte) *Scalar {
	var scalar goldilocks.Scalar
	scalar.FromBytes(data)
	return &Scalar{value: scalar}
}
