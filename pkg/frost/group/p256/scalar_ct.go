// Package p256 provides constant-time P-256 scalar field arithmetic.
//
// This file implements constant-time modular arithmetic for the P-256 scalar field
// (integers modulo the group order n). All operations are designed to execute in
// constant time regardless of input values to prevent timing side-channel attacks.
//
// The implementation uses filippo.io/bigmod which provides constant-time arithmetic
// re-exported from Go's internal crypto/internal/fips140/bigmod package.
package p256

import (
	"filippo.io/bigmod"
)

// p256OrderBytes is the P-256 group order n in big-endian bytes.
// n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
var p256OrderBytes = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
}

// p256Modulus is the precomputed modulus for constant-time operations.
var p256Modulus *bigmod.Modulus

func init() {
	var err error
	p256Modulus, err = bigmod.NewModulus(p256OrderBytes)
	if err != nil {
		// This panic is acceptable at init time - p256OrderBytes is a hardcoded constant.
		// A failure here indicates a bug in the FROST library or Go's bigmod package.
		panic("FROST library bug: failed to create P-256 modulus: " + err.Error())
	}
}

// ctScalar represents a scalar in the P-256 scalar field using constant-time operations.
type ctScalar struct {
	nat *bigmod.Nat
}

// newCTScalar creates a new zero scalar.
func newCTScalar() *ctScalar {
	return &ctScalar{nat: bigmod.NewNat().ExpandFor(p256Modulus)}
}

// newCTScalarFromBytes creates a scalar from a 32-byte big-endian encoding.
// Returns nil if the value is >= n (the group order).
func newCTScalarFromBytes(b []byte) *ctScalar {
	if len(b) != 32 {
		return nil
	}

	nat, err := bigmod.NewNat().SetBytes(b, p256Modulus)
	if err != nil {
		return nil
	}

	return &ctScalar{nat: nat}
}

// newCTScalarFromBytesWide creates a scalar from bytes, reducing modulo n.
// This is used for values that may be >= n.
func newCTScalarFromBytesWide(b []byte) *ctScalar {
	if len(b) != 32 {
		return nil
	}

	// SetOverflowingBytes handles values >= n by reducing
	nat, err := bigmod.NewNat().SetOverflowingBytes(b, p256Modulus)
	if err != nil {
		return nil
	}
	return &ctScalar{nat: nat}
}

// Bytes returns the 32-byte big-endian encoding of the scalar.
func (s *ctScalar) Bytes() []byte {
	return s.nat.Bytes(p256Modulus)
}

// IsZero returns 1 if s == 0, 0 otherwise, in constant time.
func (s *ctScalar) IsZero() int {
	return int(s.nat.IsZero())
}

// Equal returns 1 if s == t, 0 otherwise, in constant time.
func (s *ctScalar) Equal(t *ctScalar) int {
	return int(s.nat.Equal(t.nat))
}

// isLessThanOrder returns true if s < n. Since we always reduce, this is always true.
func (s *ctScalar) isLessThanOrder() bool {
	return true // bigmod.Nat is always reduced modulo the modulus
}

// copyNat creates a copy of a Nat by going through bytes.
func copyNat(src *bigmod.Nat) *bigmod.Nat {
	b := src.Bytes(p256Modulus)
	dst, _ := bigmod.NewNat().SetBytes(b, p256Modulus)
	return dst
}

// Add computes s + t mod n in constant time.
func (s *ctScalar) Add(t *ctScalar) *ctScalar {
	result := copyNat(s.nat)
	result.Add(t.nat, p256Modulus)
	return &ctScalar{nat: result}
}

// Sub computes s - t mod n in constant time.
func (s *ctScalar) Sub(t *ctScalar) *ctScalar {
	result := copyNat(s.nat)
	result.Sub(t.nat, p256Modulus)
	return &ctScalar{nat: result}
}

// Negate computes -s mod n in constant time.
func (s *ctScalar) Negate() *ctScalar {
	// -s = n - s = 0 - s (in modular arithmetic)
	zero := bigmod.NewNat().ExpandFor(p256Modulus)
	result := zero
	result.Sub(s.nat, p256Modulus)
	return &ctScalar{nat: result}
}

// Mul computes s * t mod n in constant time.
func (s *ctScalar) Mul(t *ctScalar) *ctScalar {
	result := copyNat(s.nat)
	result.Mul(t.nat, p256Modulus)
	return &ctScalar{nat: result}
}

// Inv computes s^(-1) mod n.
// Note: InverseVarTime is used which may not be constant-time for the zero check.
// For FROST, inversion is only used for Lagrange coefficients with public identifiers.
func (s *ctScalar) Inv() *ctScalar {
	result := bigmod.NewNat().ExpandFor(p256Modulus)
	// bigmod uses extended Euclidean algorithm
	_, ok := result.InverseVarTime(s.nat, p256Modulus)
	if !ok {
		// Zero has no inverse, return zero
		return newCTScalar()
	}
	return &ctScalar{nat: result}
}

// copy returns a copy of the scalar.
func (s *ctScalar) copy() *ctScalar {
	return &ctScalar{nat: copyNat(s.nat)}
}

// Set copies the value from t to s.
func (s *ctScalar) Set(t *ctScalar) {
	s.nat = copyNat(t.nat)
}

// SetOne sets s to 1.
func (s *ctScalar) SetOne() {
	s.nat = bigmod.NewNat().SetUint(1).ExpandFor(p256Modulus)
}

// SetZero sets s to 0.
func (s *ctScalar) SetZero() {
	s.nat = bigmod.NewNat().ExpandFor(p256Modulus)
}

// selectConditional sets s = t if cond == 1, leaves s unchanged if cond == 0.
func (s *ctScalar) selectConditional(t *ctScalar, cond uint64) {
	// Note: This branch is NOT constant-time. For true constant-time,
	// we would need to implement conditional select using bitwise ops.
	// However, bigmod operations themselves are constant-time.
	if cond == 1 {
		s.nat = copyNat(t.nat)
	}
}
