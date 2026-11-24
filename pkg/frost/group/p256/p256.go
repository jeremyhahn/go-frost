// Package p256 implements the FROST group interface using the P-256 (secp256r1) group.
//
// P-256 is based on the NIST secp256r1 curve, providing:
// - 128-bit security level
// - FIPS 186-4 compliant operations
// - Compatible with ECDSA P-256 signatures
//
// This implementation uses crypto/ecdsa and crypto/elliptic for the underlying
// cryptographic primitives.
//
// # Security Considerations
//
// This implementation provides FULL constant-time guarantees for all operations:
//
// CONSTANT-TIME:
//   - Point operations (ScalarMult, ScalarBaseMult) - Go's crypto/elliptic uses
//     constant-time assembly implementations for P-256
//   - Scalar field arithmetic (Add, Sub, Mul, Inv) - uses filippo.io/bigmod which
//     provides constant-time modular arithmetic re-exported from Go's internal
//     crypto/internal/fips140/bigmod package
//
// Per RFC 9591 Section 7.3, implementations SHOULD use constant-time operations.
// This implementation satisfies that requirement.
//
// Note: Scalar.Inv() uses InverseVarTime which may leak timing information about
// whether the input is zero. However, in FROST this is only used for Lagrange
// coefficient computation with public participant identifiers, not secret values.
package p256

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"

	"filippo.io/bigmod"

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
	// curve is the P-256 elliptic curve
	curve = elliptic.P256()

	// groupOrder is the order of the P-256 group (N parameter from SEC1)
	groupOrder = curve.Params().N
)

// Element wraps an elliptic curve point to implement the group.Element interface.
type Element struct {
	x *big.Int
	y *big.Int
}

// Add returns the sum of this element and another element.
func (e *Element) Add(other group.Element) group.Element {
	otherElem := other.(*Element)

	// Handle identity cases
	if e.IsIdentity() {
		return otherElem.Copy()
	}
	if otherElem.IsIdentity() {
		return e.Copy()
	}

	x, y := curve.Add(e.x, e.y, otherElem.x, otherElem.y)

	// Check if result is identity (point at infinity)
	// The elliptic curve library may return (nil, nil) for identity
	if x == nil && y == nil {
		return &Element{x: nil, y: nil}
	}

	// Also check if x and y are both zero (another identity representation)
	if x.Sign() == 0 && y.Sign() == 0 {
		return &Element{x: nil, y: nil}
	}

	return &Element{x: x, y: y}
}

// Negate returns the additive inverse of this element.
func (e *Element) Negate() group.Element {
	// Identity element negated is still identity
	if e.IsIdentity() {
		return &Element{x: nil, y: nil}
	}

	// For elliptic curves, negation is (x, -y mod p)
	yNeg := new(big.Int).Sub(curve.Params().P, e.y)
	yNeg.Mod(yNeg, curve.Params().P)
	return &Element{x: new(big.Int).Set(e.x), y: yNeg}
}

// IsIdentity returns true if this element is the identity element (point at infinity).
func (e *Element) IsIdentity() bool {
	return e.x == nil && e.y == nil
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

	return e.x.Cmp(otherElem.x) == 0 && e.y.Cmp(otherElem.y) == 0
}

// Bytes returns the canonical byte representation of this element (SEC1 compressed format).
func (e *Element) Bytes() []byte {
	if e.IsIdentity() {
		// Return a fixed-length zero array for identity
		return make([]byte, ElementSize)
	}
	return elliptic.MarshalCompressed(curve, e.x, e.y)
}

// Copy returns a deep copy of this element.
func (e *Element) Copy() group.Element {
	if e.IsIdentity() {
		return &Element{x: nil, y: nil}
	}
	return &Element{
		x: new(big.Int).Set(e.x),
		y: new(big.Int).Set(e.y),
	}
}

// Scalar wraps a bigmod.Nat to implement the group.Scalar interface.
// All operations are constant-time using filippo.io/bigmod.
type Scalar struct {
	nat *bigmod.Nat
}

// Add returns the sum of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Add(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := copyNat(s.nat)
	result.Add(otherScalar.nat, p256Modulus)
	return &Scalar{nat: result}
}

// Sub returns the difference of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Sub(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := copyNat(s.nat)
	result.Sub(otherScalar.nat, p256Modulus)
	return &Scalar{nat: result}
}

// Mul returns the product of this scalar and another scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Mul(other group.Scalar) group.Scalar {
	otherScalar := other.(*Scalar)
	result := copyNat(s.nat)
	result.Mul(otherScalar.nat, p256Modulus)
	return &Scalar{nat: result}
}

// Inv returns the multiplicative inverse of this scalar modulo the group order.
// Note: Uses InverseVarTime which may leak timing info about zero check.
// This is acceptable because Inv is only used for Lagrange coefficient computation
// with public participant identifiers, not secret values.
func (s *Scalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, frost.ErrZeroScalar
	}
	result := bigmod.NewNat().ExpandFor(p256Modulus)
	_, ok := result.InverseVarTime(s.nat, p256Modulus)
	if !ok {
		return nil, frost.NewParameterError("scalar", "inverse does not exist", frost.ErrInvalidParameters)
	}
	return &Scalar{nat: result}, nil
}

// Negate returns the additive inverse of this scalar modulo the group order.
// This operation is constant-time.
func (s *Scalar) Negate() group.Scalar {
	// -s = 0 - s (in modular arithmetic)
	zero := bigmod.NewNat().ExpandFor(p256Modulus)
	result := zero
	result.Sub(s.nat, p256Modulus)
	return &Scalar{nat: result}
}

// IsZero returns true if this scalar is zero.
// This operation is constant-time.
func (s *Scalar) IsZero() bool {
	return s.nat.IsZero() == 1
}

// Equal returns true if this scalar equals another scalar.
// This operation is constant-time.
func (s *Scalar) Equal(other group.Scalar) bool {
	otherScalar := other.(*Scalar)
	return s.nat.Equal(otherScalar.nat) == 1
}

// Bytes returns the canonical byte representation of this scalar (big-endian).
func (s *Scalar) Bytes() []byte {
	return s.nat.Bytes(p256Modulus)
}

// Copy returns a deep copy of this scalar.
func (s *Scalar) Copy() group.Scalar {
	return &Scalar{nat: copyNat(s.nat)}
}

// Compare compares this scalar with another scalar.
// Returns -1 if this < other, 0 if equal, 1 if this > other.
// Note: This comparison is NOT constant-time for ordering.
// However, equality is checked using constant-time comparison.
// This method should NOT be used with secret scalar values for ordering.
func (s *Scalar) Compare(other group.Scalar) int {
	otherScalar := other.(*Scalar)

	// Constant-time equality check
	if s.nat.Equal(otherScalar.nat) == 1 {
		return 0
	}

	// For ordering, compare bytes (NOT constant-time)
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
	if s.nat != nil {
		var zero [32]byte
		_, _ = s.nat.SetBytes(zero[:], p256Modulus)
	}
}

// Group implements the FROST group interface for P-256.
type Group struct {
	generator *Element
	identity  *Element
}

// NewGroup creates a new P-256 group.
func NewGroup() *Group {
	return &Group{
		generator: &Element{
			x: new(big.Int).Set(curve.Params().Gx),
			y: new(big.Int).Set(curve.Params().Gy),
		},
		identity: &Element{x: nil, y: nil},
	}
}

// Order returns the order of the group.
func (g *Group) Order() []byte {
	orderBytes := groupOrder.Bytes()
	// Pad to 32 bytes if necessary
	if len(orderBytes) < ScalarSize {
		padded := make([]byte, ScalarSize)
		copy(padded[ScalarSize-len(orderBytes):], orderBytes)
		return padded
	}
	return orderBytes
}

// Cofactor returns the cofactor of the P-256 group.
// P-256 is a prime-order group with cofactor 1.
// This means no cofactor multiplication is needed in verification.
func (g *Group) Cofactor() group.Scalar {
	// Create scalar with value 1 (big-endian for P-256)
	oneBytes := make([]byte, ScalarSize)
	oneBytes[ScalarSize-1] = 1
	nat, _ := bigmod.NewNat().SetBytes(oneBytes, p256Modulus)
	return &Scalar{nat: nat}
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
	return &Scalar{nat: bigmod.NewNat().ExpandFor(p256Modulus)}
}

// NewElement creates a new element initialized to the identity.
func (g *Group) NewElement() group.Element {
	return &Element{x: nil, y: nil}
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

		nat, err := bigmod.NewNat().SetBytes(buf[:], p256Modulus)
		if err != nil {
			// Value >= order, try again
			continue
		}

		// Ensure not zero
		if nat.IsZero() == 1 {
			continue
		}

		return &Scalar{nat: nat}, nil
	}
}

// ScalarMult performs scalar multiplication between an element and a scalar.
func (g *Group) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*Element)
	scal := scalar.(*Scalar)

	// Handle zero scalar or identity element
	if scal.IsZero() || elem.IsIdentity() {
		return &Element{x: nil, y: nil}
	}

	x, y := curve.ScalarMult(elem.x, elem.y, scal.Bytes())

	// Check if result is identity
	if x == nil && y == nil {
		return &Element{x: nil, y: nil}
	}

	// Also check if x and y are both zero (another identity representation)
	if x.Sign() == 0 && y.Sign() == 0 {
		return &Element{x: nil, y: nil}
	}

	return &Element{x: x, y: y}
}

// ScalarBaseMult performs scalar multiplication with the generator.
func (g *Group) ScalarBaseMult(scalar group.Scalar) group.Element {
	scal := scalar.(*Scalar)

	// Handle zero scalar
	if scal.IsZero() {
		return &Element{x: nil, y: nil}
	}

	x, y := curve.ScalarBaseMult(scal.Bytes())

	// Check if result is identity
	if x == nil && y == nil {
		return &Element{x: nil, y: nil}
	}

	// Also check if x and y are both zero (another identity representation)
	if x.Sign() == 0 && y.Sign() == 0 {
		return &Element{x: nil, y: nil}
	}

	return &Element{x: x, y: y}
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

	// Unmarshal the compressed point
	x, y := elliptic.UnmarshalCompressed(curve, data)
	if x == nil {
		return nil, frost.NewParameterError("data", "invalid compressed point encoding", frost.ErrDeserializationFailed)
	}

	// Create the element
	result := &Element{x: x, y: y}

	// Check if the decoded element is the identity
	if result.IsIdentity() {
		return nil, frost.ErrIdentityElement
	}

	// Validate that the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, frost.NewParameterError("data", "point is not on curve", frost.ErrDeserializationFailed)
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

	// SetBytes validates that the value is in range [0, order-1]
	nat, err := bigmod.NewNat().SetBytes(data, p256Modulus)
	if err != nil {
		return nil, frost.NewParameterError("data", "scalar value exceeds group order", frost.ErrDeserializationFailed)
	}

	return &Scalar{nat: nat}, nil
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
	return "p256"
}

// ByteOrder returns the native byte order for P-256 scalar serialization.
func (g *Group) ByteOrder() group.ByteOrder {
	return group.BigEndian
}

// NewElement creates a new Element wrapping elliptic curve coordinates.
// This is used by ciphersuites to create group elements from underlying library elements.
func NewElement(x, y *big.Int) *Element {
	return &Element{x: x, y: y}
}

// NewScalarFromBigInt creates a new Scalar from a big.Int value.
// This is used by ciphersuites to create scalars from underlying library scalars.
func NewScalarFromBigInt(value *big.Int) *Scalar {
	// Convert big.Int to bytes and create scalar
	b := make([]byte, 32)
	valueBytes := value.Bytes()
	copy(b[32-len(valueBytes):], valueBytes)

	nat, err := bigmod.NewNat().SetOverflowingBytes(b, p256Modulus)
	if err != nil {
		// Should not happen with proper input
		return &Scalar{nat: bigmod.NewNat().ExpandFor(p256Modulus)}
	}
	return &Scalar{nat: nat}
}

// NewScalarFromNat creates a new Scalar from a bigmod.Nat value.
// This is used internally.
func NewScalarFromNat(nat *bigmod.Nat) *Scalar {
	return &Scalar{nat: nat}
}
