// Package secp256k1 implements the FROST group interface using the secp256k1 group.
//
// secp256k1 is based on the Bitcoin/blockchain curve, providing:
// - 128-bit security level
// - SEC 2 v2.0 compliant operations
// - Compatible with Bitcoin and Ethereum signatures
//
// This implementation uses github.com/decred/dcrd/dcrec/secp256k1/v4 for the
// underlying cryptographic primitives.
package secp256k1

import (
	"crypto/rand"
	"io"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

const (
	// ElementSize is the byte length of a serialized group element (SEC1 compressed format).
	ElementSize = 33

	// ScalarSize is the byte length of a serialized scalar.
	ScalarSize = 32
)

var (
	// curveOrder is the order of the secp256k1 group (N parameter from SEC 2)
	curveOrder = secp.S256().N
)

// Element wraps a secp256k1 Jacobian point to implement the group.Element interface.
type Element struct {
	point secp.JacobianPoint
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)

	var result secp.JacobianPoint
	secp.AddNonConst(&e.point, &otherElem.point, &result)

	return &Element{point: result}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	// For elliptic curves, negation is (x, -y, z)
	var result secp.JacobianPoint
	result.X.Set(&e.point.X)
	result.Y.Set(&e.point.Y).Negate(1).Normalize()
	result.Z.Set(&e.point.Z)

	return &Element{point: result}
}

// IsIdentity returns true if this element is the identity element (point at infinity).
func (e *Element) IsIdentity() bool {
	// In Jacobian coordinates, the point at infinity has Z = 0
	return e.point.Z.IsZero()
}

// Equal returns true if this element equals another element.
func (e *Element) Equal(other group.Element) bool {
	otherElem := other.(*Element)

	// Handle identity cases
	if e.IsIdentity() && otherElem.IsIdentity() {
		return true
	}
	if e.IsIdentity() || otherElem.IsIdentity() {
		return false
	}

	// Convert to affine coordinates for comparison
	var p1, p2 secp.JacobianPoint
	p1.Set(&e.point)
	p2.Set(&otherElem.point)

	p1.ToAffine()
	p2.ToAffine()

	return p1.X.Equals(&p2.X) && p1.Y.Equals(&p2.Y)
}

// Bytes returns the canonical byte representation of this element (SEC1 compressed format).
func (e *Element) Bytes() []byte {
	if e.IsIdentity() {
		// Return a fixed-length zero array for identity
		return make([]byte, ElementSize)
	}

	// Convert to affine coordinates
	var affine secp.JacobianPoint
	affine.Set(&e.point)
	affine.ToAffine()

	// Serialize as compressed public key
	pubKey := secp.NewPublicKey(&affine.X, &affine.Y)
	return pubKey.SerializeCompressed()
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	var result secp.JacobianPoint
	result.Set(&e.point)
	return &Element{point: result}
}

// Scalar wraps a ModNScalar to implement the group.Scalar interface.
type Scalar struct {
	value secp.ModNScalar
}

// Add returns the sum of this scalar and another scalar modulo the group order.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result secp.ModNScalar
	result.Add2(&s.value, &otherScalar.value)
	return &Scalar{value: result}
}

// Sub returns the difference of this scalar and another scalar modulo the group order.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result secp.ModNScalar
	// result = s - other = s + (-other)
	var negOther secp.ModNScalar
	negOther.NegateVal(&otherScalar.value)
	result.Add2(&s.value, &negOther)
	return &Scalar{value: result}
}

// Mul returns the product of this scalar and another scalar modulo the group order.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	var result secp.ModNScalar
	result.Mul2(&s.value, &otherScalar.value)
	return &Scalar{value: result}
}

// Inv returns the multiplicative inverse of this scalar modulo the group order.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	var result secp.ModNScalar
	result.InverseValNonConst(&s.value)
	return &Scalar{value: result}, nil
}

// Negate returns the additive inverse of this scalar modulo the group order.
func (s *Scalar) Negate() group.Scalar {
	var result secp.ModNScalar
	result.NegateVal(&s.value)
	return &Scalar{value: result}
}

// IsZero returns true if this scalar is zero.
func (s *Scalar) IsZero() bool {
	return s.value.IsZero()
}

// Equal returns true if this scalar equals another scalar.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.value.Equals(&otherScalar.value)
}

// Bytes returns the canonical byte representation of this scalar (big-endian).
func (s *Scalar) Bytes() []byte {
	bytes := s.value.Bytes()
	return bytes[:]
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	var result secp.ModNScalar
	result.Set(&s.value)
	return &Scalar{value: result}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)

	// Convert to bytes for comparison (big-endian)
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

// Group implements the FROST group interface for secp256k1.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new secp256k1 group.
func NewGroup() *Group {
	// Create generator from secp256k1 base point
	// Use scalar 1 to get the generator point (1 * G = G)
	var one secp.ModNScalar
	one.SetInt(1)
	var generator secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&one, &generator)

	// Identity element (point at infinity)
	var identity secp.JacobianPoint
	// Point at infinity has Z = 0
	identity.X.SetInt(0)
	identity.Y.SetInt(0)
	identity.Z.SetInt(0)

	return &Group{
		generator: &Element{point: generator},
		identity:  &Element{point: identity},
	}
}

// Order returns the order of the group.
func (g *Group) Order() []byte {
	orderBytes := curveOrder.Bytes()
	// Ensure it's 32 bytes
	if len(orderBytes) < ScalarSize {
		padded := make([]byte, ScalarSize)
		copy(padded[ScalarSize-len(orderBytes):], orderBytes)
		return padded
	}
	return orderBytes[:]
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
	var zero secp.ModNScalar
	zero.SetInt(0)
	return &Scalar{value: zero}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return g.identity.Copy()
}

// RandomScalar generates a random scalar in the field [0, order-1].
func (g *Group) RandomScalar() (group.Scalar, error) {
	return randomScalar(rand.Reader)
}

// randomScalar generates a random scalar using the provided random source.
func randomScalar(random io.Reader) (group.Scalar, error) {
	var scalar secp.ModNScalar
	var buf [32]byte

	for {
		_, err := io.ReadFull(random, buf[:])
		if err != nil {
			return nil, frost.NewParameterError("random", "failed to generate random bytes", err)
		}

		// Try to set the scalar from the random bytes
		// This will reduce modulo N automatically
		overflow := scalar.SetByteSlice(buf[:])

		// If no overflow and not zero, we have a valid scalar
		if !overflow && !scalar.IsZero() {
			return &Scalar{value: scalar}, nil
		}
	}
}

// ScalarMult performs scalar multiplication between an element and a scalar.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	// Handle zero scalar or identity element
	if scal.IsZero() || elem.IsIdentity() {
		return g.identity.Copy()
	}

	var result secp.JacobianPoint
	secp.ScalarMultNonConst(&scal.value, &elem.point, &result)

	return &Element{point: result}
}

// ScalarBaseMult performs scalar multiplication with the generator.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	// Handle zero scalar
	if scal.IsZero() {
		return g.identity.Copy()
	}

	var result secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&scal.value, &result)

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

	// Parse the compressed public key
	pubKey, err := secp.ParsePubKey(data)
	if err != nil {
		return nil, frost.NewParameterError("data", "invalid compressed point encoding", frost.ErrDeserializationFailed)
	}

	// Convert to Jacobian coordinates
	var point secp.JacobianPoint
	pubKey.AsJacobian(&point)

	// Create the element
	result := &Element{point: point}

	// Check if the decoded element is the identity
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

	var scalar secp.ModNScalar
	overflow := scalar.SetByteSlice(data)

	// Check if the value overflowed (was >= order)
	if overflow {
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

// NewElement creates a new Element wrapping a Jacobian point.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(point secp.JacobianPoint) *Element {
	return &Element{point: point}
}

// NewScalar creates a new Scalar wrapping a ModNScalar value.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalar(value secp.ModNScalar) *Scalar {
	return &Scalar{value: value}
}
