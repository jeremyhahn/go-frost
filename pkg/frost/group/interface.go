// Package group defines the prime-order group interface required for FROST.
//
// FROST depends on an abelian group of prime order p. The group operation is
// addition (+) with identity element I. This package defines the abstract
// interface that all group implementations must satisfy.
package group

// Element represents an element of the prime-order group G.
// Elements support addition, negation, and scalar multiplication.
type Element interface {
	// Add returns the sum of this element and another element.
	// For elements A and B: A.Add(B) = A + B
	Add(other Element) Element

	// Negate returns the additive inverse of this element.
	// For element A: A.Negate() = -A such that A + (-A) = I
	Negate() Element

	// IsIdentity returns true if this element is the identity element I.
	IsIdentity() bool

	// Equal returns true if this element equals another element.
	Equal(other Element) bool

	// Bytes returns the canonical byte representation of this element.
	// This must be a fixed-length encoding specific to the group.
	Bytes() []byte

	// Copy returns a deep copy of this element.
	Copy() Element
}

// Scalar represents a scalar value in GF(p), where p is the group order.
// Scalars support addition, subtraction, multiplication, and division.
// All operations are performed modulo the group order p.
type Scalar interface {
	// Add returns the sum of this scalar and another scalar modulo p.
	Add(other Scalar) Scalar

	// Sub returns the difference of this scalar and another scalar modulo p.
	Sub(other Scalar) Scalar

	// Mul returns the product of this scalar and another scalar modulo p.
	Mul(other Scalar) Scalar

	// Inv returns the multiplicative inverse of this scalar modulo p.
	// Returns an error if the scalar is zero.
	Inv() (Scalar, error)

	// Negate returns the additive inverse of this scalar modulo p.
	Negate() Scalar

	// IsZero returns true if this scalar is zero.
	IsZero() bool

	// Equal returns true if this scalar equals another scalar.
	Equal(other Scalar) bool

	// Bytes returns the canonical byte representation of this scalar.
	// This must be a fixed-length encoding specific to the group.
	Bytes() []byte

	// Copy returns a deep copy of this scalar.
	Copy() Scalar

	// Compare compares this scalar with another scalar.
	// Returns -1 if this < other, 0 if equal, 1 if this > other.
	// Uses the least nonnegative representation modulo p.
	Compare(other Scalar) int
}

// Group represents a prime-order group G with its operations.
// This interface defines all operations required by the FROST protocol.
type Group interface {
	// Order returns the order of the group (i.e., p).
	Order() []byte

	// Identity returns the identity element of the group (i.e., I).
	Identity() Element

	// Generator returns the fixed generator element of the group (i.e., B).
	Generator() Element

	// NewScalar creates a new scalar from a byte slice.
	// Returns an error if the byte slice does not represent a valid scalar.
	NewScalar() Scalar

	// NewElement creates a new element initialized to the identity.
	NewElement() Element

	// RandomScalar generates a random scalar in GF(p).
	// The scalar is sampled uniformly at random from [0, p-1].
	RandomScalar() (Scalar, error)

	// ScalarMult performs scalar multiplication between an element and a scalar.
	// Returns A * k where A is an element and k is a scalar.
	ScalarMult(element Element, scalar Scalar) Element

	// ScalarBaseMult performs scalar multiplication between a scalar and the generator.
	// Returns B * k where B is the generator and k is a scalar.
	ScalarBaseMult(scalar Scalar) Element

	// SerializeElement encodes an element to its canonical byte representation.
	// Returns an error if the element is the identity element.
	SerializeElement(element Element) ([]byte, error)

	// DeserializeElement decodes a byte slice to an element.
	// Returns an error if:
	// - The byte slice is not a valid element encoding
	// - The resulting element is the identity element
	DeserializeElement(data []byte) (Element, error)

	// SerializeScalar encodes a scalar to its canonical byte representation.
	SerializeScalar(scalar Scalar) []byte

	// DeserializeScalar decodes a byte slice to a scalar.
	// Returns an error if the byte slice is not a valid scalar encoding.
	DeserializeScalar(data []byte) (Scalar, error)

	// ElementLength returns the byte length of a serialized element.
	ElementLength() int

	// ScalarLength returns the byte length of a serialized scalar.
	ScalarLength() int

	// Name returns a human-readable name for this group (e.g., "ristretto255").
	Name() string
}
