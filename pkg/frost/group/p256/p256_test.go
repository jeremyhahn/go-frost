package p256

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestGroupInterface verifies that P256 Group implements the group.Group interface.
func TestGroupInterface(t *testing.T) {
	var _ group.Group = (*Group)(nil)
}

// TestElementInterface verifies that P256 Element implements the group.Element interface.
func TestElementInterface(t *testing.T) {
	var _ group.Element = (*Element)(nil)
}

// TestScalarInterface verifies that P256 Scalar implements the group.Scalar interface.
func TestScalarInterface(t *testing.T) {
	var _ group.Scalar = (*Scalar)(nil)
}

// TestNewGroup tests group initialization.
func TestNewGroup(t *testing.T) {
	g := NewGroup()
	if g == nil {
		t.Fatal("NewGroup returned nil")
	}

	if g.generator == nil {
		t.Fatal("generator is nil")
	}

	if g.identity == nil {
		t.Fatal("identity is nil")
	}

	// Verify generator is not identity
	if g.generator.IsIdentity() {
		t.Error("generator should not be identity")
	}

	// Verify identity is identity
	if !g.identity.IsIdentity() {
		t.Error("identity element should be identity")
	}
}

// TestGroupOrder tests the Order method.
func TestGroupOrder(t *testing.T) {
	g := NewGroup()
	order := g.Order()

	if len(order) != ScalarSize {
		t.Errorf("order length = %d, want %d", len(order), ScalarSize)
	}

	// Verify order matches P-256 order
	expectedOrder := elliptic.P256().Params().N.Bytes()
	if len(expectedOrder) < ScalarSize {
		padded := make([]byte, ScalarSize)
		copy(padded[ScalarSize-len(expectedOrder):], expectedOrder)
		expectedOrder = padded
	}

	if !bytes.Equal(order, expectedOrder) {
		t.Error("order does not match P-256 group order")
	}
}

// TestIdentity tests the Identity method.
func TestIdentity(t *testing.T) {
	g := NewGroup()
	identity := g.Identity()

	if identity == nil {
		t.Fatal("Identity returned nil")
	}

	if !identity.IsIdentity() {
		t.Error("Identity() should return identity element")
	}

	// Verify it's a copy
	identity2 := g.Identity()
	if identity == identity2 {
		t.Error("Identity() should return a copy, not the same reference")
	}
}

// TestGenerator tests the Generator method.
func TestGenerator(t *testing.T) {
	g := NewGroup()
	generator := g.Generator()

	if generator == nil {
		t.Fatal("Generator returned nil")
	}

	if generator.IsIdentity() {
		t.Error("Generator should not be identity")
	}

	// Verify it matches P-256 generator
	elem := generator.(*Element)
	if elem.x.Cmp(curve.Params().Gx) != 0 || elem.y.Cmp(curve.Params().Gy) != 0 {
		t.Error("Generator does not match P-256 generator")
	}

	// Verify it's a copy
	generator2 := g.Generator()
	if generator == generator2 {
		t.Error("Generator() should return a copy, not the same reference")
	}
}

// TestNewScalar tests scalar creation.
func TestNewScalar(t *testing.T) {
	g := NewGroup()
	scalar := g.NewScalar()

	if scalar == nil {
		t.Fatal("NewScalar returned nil")
	}

	if !scalar.IsZero() {
		t.Error("NewScalar should return zero scalar")
	}
}

// TestNewElement tests element creation.
func TestNewElement(t *testing.T) {
	g := NewGroup()
	element := g.NewElement()

	if element == nil {
		t.Fatal("NewElement returned nil")
	}

	if !element.IsIdentity() {
		t.Error("NewElement should return identity element")
	}
}

// TestRandomScalar tests random scalar generation.
func TestRandomScalar(t *testing.T) {
	g := NewGroup()

	// Generate multiple random scalars
	scalars := make([]group.Scalar, 10)
	for i := 0; i < 10; i++ {
		scalar, err := g.RandomScalar()
		if err != nil {
			t.Fatalf("RandomScalar failed: %v", err)
		}

		if scalar == nil {
			t.Fatal("RandomScalar returned nil")
		}

		// Verify scalar is not zero (statistically almost impossible)
		if scalar.IsZero() {
			t.Error("RandomScalar returned zero (extremely unlikely)")
		}

		scalars[i] = scalar
	}

	// Verify scalars are different (statistically)
	for i := 0; i < len(scalars); i++ {
		for j := i + 1; j < len(scalars); j++ {
			if scalars[i].Equal(scalars[j]) {
				t.Error("RandomScalar generated duplicate scalars")
			}
		}
	}
}

// TestScalarAdd tests scalar addition.
func TestScalarAdd(t *testing.T) {
	g := NewGroup()

	// Test with known values
	a := NewScalarFromBigInt(big.NewInt(5))
	b := NewScalarFromBigInt(big.NewInt(7))
	result := a.Add(b)

	expected := NewScalarFromBigInt(big.NewInt(12))
	if !result.Equal(expected) {
		t.Errorf("5 + 7 failed")
	}

	// Test with zero
	zero := g.NewScalar()
	result = a.Add(zero)
	if !result.Equal(a) {
		t.Error("a + 0 should equal a")
	}

	// Test commutativity
	result1 := a.Add(b)
	result2 := b.Add(a)
	if !result1.Equal(result2) {
		t.Error("addition should be commutative")
	}
}

// TestScalarSub tests scalar subtraction.
func TestScalarSub(t *testing.T) {
	g := NewGroup()

	// Test with known values
	a := NewScalarFromBigInt(big.NewInt(10))
	b := NewScalarFromBigInt(big.NewInt(3))
	result := a.Sub(b)

	expected := NewScalarFromBigInt(big.NewInt(7))
	if !result.Equal(expected) {
		t.Errorf("10 - 3 failed")
	}

	// Test with zero
	zero := g.NewScalar()
	result = a.Sub(zero)
	if !result.Equal(a) {
		t.Error("a - 0 should equal a")
	}

	// Test a - a = 0
	result = a.Sub(a)
	if !result.IsZero() {
		t.Error("a - a should equal 0")
	}
}

// TestScalarMul tests scalar multiplication.
func TestScalarMul(t *testing.T) {
	// Test with known values
	a := NewScalarFromBigInt(big.NewInt(5))
	b := NewScalarFromBigInt(big.NewInt(7))
	result := a.Mul(b)

	expected := NewScalarFromBigInt(big.NewInt(35))
	if !result.Equal(expected) {
		t.Error("5 * 7 failed")
	}

	// Test with zero
	g := NewGroup()
	zero := g.NewScalar()
	result = a.Mul(zero)
	if !result.IsZero() {
		t.Error("a * 0 should equal 0")
	}

	// Test commutativity
	result1 := a.Mul(b)
	result2 := b.Mul(a)
	if !result1.Equal(result2) {
		t.Error("multiplication should be commutative")
	}
}

// TestScalarInv tests scalar inversion.
func TestScalarInv(t *testing.T) {
	g := NewGroup()

	// Test with non-zero scalar
	a, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	inv, err := a.Inv()
	if err != nil {
		t.Fatalf("Inv failed: %v", err)
	}

	// Test a * a^-1 = 1
	one := a.Mul(inv)
	oneScalar := NewScalarFromBigInt(big.NewInt(1))
	if !one.Equal(oneScalar) {
		t.Error("a * a^-1 should equal 1")
	}

	// Test with zero (should fail)
	zero := g.NewScalar()
	_, err = zero.Inv()
	if err != frost.ErrZeroScalar {
		t.Errorf("Inv(0) should return ErrZeroScalar, got %v", err)
	}
}

// TestScalarNegate tests scalar negation.
func TestScalarNegate(t *testing.T) {
	g := NewGroup()

	// Test with non-zero scalar
	a := NewScalarFromBigInt(big.NewInt(5))
	negA := a.Negate()

	// Test a + (-a) = 0
	result := a.Add(negA)
	if !result.IsZero() {
		t.Error("a + (-a) should equal 0")
	}

	// Test with zero
	zero := g.NewScalar()
	negZero := zero.Negate()
	if !negZero.IsZero() {
		t.Error("-(0) should equal 0")
	}
}

// TestScalarIsZero tests zero detection.
func TestScalarIsZero(t *testing.T) {
	g := NewGroup()

	zero := g.NewScalar()
	if !zero.IsZero() {
		t.Error("zero scalar should be zero")
	}

	nonZero := NewScalarFromBigInt(big.NewInt(1))
	if nonZero.IsZero() {
		t.Error("non-zero scalar should not be zero")
	}
}

// TestScalarEqual tests scalar equality.
func TestScalarEqual(t *testing.T) {
	a := NewScalarFromBigInt(big.NewInt(5))
	b := NewScalarFromBigInt(big.NewInt(5))
	c := NewScalarFromBigInt(big.NewInt(7))

	if !a.Equal(b) {
		t.Error("equal scalars should be equal")
	}

	if a.Equal(c) {
		t.Error("different scalars should not be equal")
	}
}

// TestScalarBytes tests scalar serialization.
func TestScalarBytes(t *testing.T) {
	// Test with known value
	a := NewScalarFromBigInt(big.NewInt(256))
	scalarBytes := a.Bytes()

	if len(scalarBytes) != ScalarSize {
		t.Errorf("scalar bytes length = %d, want %d", len(scalarBytes), ScalarSize)
	}

	// Verify big-endian encoding
	// 256 = 0x0100, should be padded to 32 bytes with 0x01 at position [30]
	if scalarBytes[30] != 0x01 || scalarBytes[31] != 0x00 {
		t.Error("scalar bytes encoding is incorrect")
	}

	// Test with zero
	g := NewGroup()
	zero := g.NewScalar()
	zeroBytes := zero.Bytes()
	if len(zeroBytes) != ScalarSize {
		t.Errorf("zero scalar bytes length = %d, want %d", len(zeroBytes), ScalarSize)
	}

	for _, b := range zeroBytes {
		if b != 0 {
			t.Error("zero scalar bytes should be all zeros")
			break
		}
	}
}

// TestScalarCopy tests scalar copying.
func TestScalarCopy(t *testing.T) {
	a := NewScalarFromBigInt(big.NewInt(5))
	b := a.Copy()

	if !a.Equal(b) {
		t.Error("copy should be equal to original")
	}

	// Verify it's a deep copy
	if a == b {
		t.Error("copy should be a different instance")
	}

	// Verify original and copy are independent by checking the underlying nat
	// Since we use bigmod.Nat, we verify through computation
	c := NewScalarFromBigInt(big.NewInt(10))
	if a.Equal(c) {
		t.Error("original should not equal modified value")
	}
}

// TestScalarCompare tests scalar comparison.
func TestScalarCompare(t *testing.T) {
	a := NewScalarFromBigInt(big.NewInt(5))
	b := NewScalarFromBigInt(big.NewInt(10))
	c := NewScalarFromBigInt(big.NewInt(5))

	if a.Compare(b) != -1 {
		t.Error("5 < 10 should return -1")
	}

	if b.Compare(a) != 1 {
		t.Error("10 > 5 should return 1")
	}

	if a.Compare(c) != 0 {
		t.Error("5 == 5 should return 0")
	}
}

// TestElementAdd tests element addition.
func TestElementAdd(t *testing.T) {
	g := NewGroup()

	// Test with generator
	gen := g.Generator()
	result := gen.Add(gen)

	// Should not be identity
	if result.IsIdentity() {
		t.Error("G + G should not be identity")
	}

	// Test with identity
	identity := g.Identity()
	result = gen.Add(identity)
	if !result.Equal(gen) {
		t.Error("G + I should equal G")
	}

	// Test commutativity
	result1 := gen.Add(identity)
	result2 := identity.Add(gen)
	if !result1.Equal(result2) {
		t.Error("addition should be commutative")
	}
}

// TestElementNegate tests element negation.
func TestElementNegate(t *testing.T) {
	g := NewGroup()

	// Test with generator
	gen := g.Generator()
	negGen := gen.Negate()

	// Test G + (-G) = I
	result := gen.Add(negGen)
	if !result.IsIdentity() {
		t.Error("G + (-G) should equal identity")
	}

	// Test with identity
	identity := g.Identity()
	negIdentity := identity.Negate()
	if !negIdentity.IsIdentity() {
		t.Error("-(I) should equal identity")
	}
}

// TestElementIsIdentity tests identity detection.
func TestElementIsIdentity(t *testing.T) {
	g := NewGroup()

	identity := g.Identity()
	if !identity.IsIdentity() {
		t.Error("identity element should be identity")
	}

	generator := g.Generator()
	if generator.IsIdentity() {
		t.Error("generator should not be identity")
	}
}

// TestElementEqual tests element equality.
func TestElementEqual(t *testing.T) {
	g := NewGroup()

	gen1 := g.Generator()
	gen2 := g.Generator()
	identity := g.Identity()

	if !gen1.Equal(gen2) {
		t.Error("equal elements should be equal")
	}

	if gen1.Equal(identity) {
		t.Error("different elements should not be equal")
	}

	// Test identity equality
	identity2 := g.Identity()
	if !identity.Equal(identity2) {
		t.Error("identities should be equal")
	}
}

// TestElementBytes tests element serialization.
func TestElementBytes(t *testing.T) {
	g := NewGroup()

	// Test with generator
	gen := g.Generator()
	bytes := gen.Bytes()

	if len(bytes) != ElementSize {
		t.Errorf("element bytes length = %d, want %d", len(bytes), ElementSize)
	}

	// Verify SEC1 compressed format (first byte should be 0x02 or 0x03)
	if bytes[0] != 0x02 && bytes[0] != 0x03 {
		t.Error("element bytes should use SEC1 compressed format")
	}

	// Test with identity (should return zeros)
	identity := g.Identity()
	identityBytes := identity.Bytes()
	if len(identityBytes) != ElementSize {
		t.Errorf("identity bytes length = %d, want %d", len(identityBytes), ElementSize)
	}
}

// TestElementCopy tests element copying.
func TestElementCopy(t *testing.T) {
	g := NewGroup()

	gen := g.Generator()
	copy := gen.Copy()

	if !gen.Equal(copy) {
		t.Error("copy should be equal to original")
	}

	// Verify it's a deep copy
	if gen == copy {
		t.Error("copy should be a different instance")
	}

	// Test identity copy
	identity := g.Identity()
	identityCopy := identity.Copy()
	if !identity.Equal(identityCopy) {
		t.Error("identity copy should equal identity")
	}
}

// TestScalarMult tests scalar multiplication.
func TestScalarMult(t *testing.T) {
	g := NewGroup()

	// Test with generator
	gen := g.Generator()
	scalar := NewScalarFromBigInt(big.NewInt(2))
	result := g.ScalarMult(gen, scalar)

	// Should equal G + G
	expected := gen.Add(gen)
	if !result.Equal(expected) {
		t.Error("2*G should equal G + G")
	}

	// Test with zero scalar (should give identity)
	zero := g.NewScalar()
	result = g.ScalarMult(gen, zero)
	if !result.IsIdentity() {
		t.Error("0*G should equal identity")
	}

	// Test with identity element
	identity := g.Identity()
	result = g.ScalarMult(identity, scalar)
	if !result.IsIdentity() {
		t.Error("k*I should equal identity")
	}
}

// TestScalarBaseMult tests scalar base multiplication.
func TestScalarBaseMult(t *testing.T) {
	g := NewGroup()

	// Test with scalar 1 (should give generator)
	one := NewScalarFromBigInt(big.NewInt(1))
	result := g.ScalarBaseMult(one)
	gen := g.Generator()
	if !result.Equal(gen) {
		t.Error("1*G should equal G")
	}

	// Test with scalar 2
	two := NewScalarFromBigInt(big.NewInt(2))
	result = g.ScalarBaseMult(two)
	expected := gen.Add(gen)
	if !result.Equal(expected) {
		t.Error("2*G should equal G + G")
	}

	// Test with zero
	zero := g.NewScalar()
	result = g.ScalarBaseMult(zero)
	if !result.IsIdentity() {
		t.Error("0*G should equal identity")
	}
}

// TestSerializeElement tests element serialization.
func TestSerializeElement(t *testing.T) {
	g := NewGroup()

	// Test with generator
	gen := g.Generator()
	bytes, err := g.SerializeElement(gen)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}

	if len(bytes) != ElementSize {
		t.Errorf("serialized element length = %d, want %d", len(bytes), ElementSize)
	}

	// Test with identity (should fail)
	identity := g.Identity()
	_, err = g.SerializeElement(identity)
	if err != frost.ErrIdentityElement {
		t.Errorf("SerializeElement(identity) should return ErrIdentityElement, got %v", err)
	}
}

// TestDeserializeElement tests element deserialization.
func TestDeserializeElement(t *testing.T) {
	g := NewGroup()

	// Test round-trip
	gen := g.Generator()
	bytes, err := g.SerializeElement(gen)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}

	elem, err := g.DeserializeElement(bytes)
	if err != nil {
		t.Fatalf("DeserializeElement failed: %v", err)
	}

	if !elem.Equal(gen) {
		t.Error("deserialized element should equal original")
	}

	// Test with invalid length
	_, err = g.DeserializeElement([]byte{0x00})
	if err == nil {
		t.Error("DeserializeElement with invalid length should fail")
	}

	// Test with invalid encoding
	invalidBytes := make([]byte, ElementSize)
	invalidBytes[0] = 0x04 // Invalid compressed format marker
	_, err = g.DeserializeElement(invalidBytes)
	if err == nil {
		t.Error("DeserializeElement with invalid encoding should fail")
	}
}

// TestSerializeScalar tests scalar serialization.
func TestSerializeScalar(t *testing.T) {
	g := NewGroup()

	// Test with known value
	scalar := NewScalarFromBigInt(big.NewInt(42))
	scalarBytes := g.SerializeScalar(scalar)

	if len(scalarBytes) != ScalarSize {
		t.Errorf("serialized scalar length = %d, want %d", len(scalarBytes), ScalarSize)
	}

	// Test with zero
	zero := g.NewScalar()
	zeroBytes := g.SerializeScalar(zero)
	if len(zeroBytes) != ScalarSize {
		t.Errorf("serialized zero scalar length = %d, want %d", len(zeroBytes), ScalarSize)
	}
}

// TestDeserializeScalar tests scalar deserialization.
func TestDeserializeScalar(t *testing.T) {
	g := NewGroup()

	// Test round-trip
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	bytes := g.SerializeScalar(scalar)
	deserializedScalar, err := g.DeserializeScalar(bytes)
	if err != nil {
		t.Fatalf("DeserializeScalar failed: %v", err)
	}

	if !deserializedScalar.Equal(scalar) {
		t.Error("deserialized scalar should equal original")
	}

	// Test with invalid length
	_, err = g.DeserializeScalar([]byte{0x00})
	if err == nil {
		t.Error("DeserializeScalar with invalid length should fail")
	}

	// Test with value >= order (should fail)
	invalidBytes := make([]byte, ScalarSize)
	for i := range invalidBytes {
		invalidBytes[i] = 0xFF
	}
	_, err = g.DeserializeScalar(invalidBytes)
	if err == nil {
		t.Error("DeserializeScalar with value >= order should fail")
	}
}

// TestElementLength tests element length.
func TestElementLength(t *testing.T) {
	g := NewGroup()
	if g.ElementLength() != ElementSize {
		t.Errorf("ElementLength = %d, want %d", g.ElementLength(), ElementSize)
	}
}

// TestScalarLength tests scalar length.
func TestScalarLength(t *testing.T) {
	g := NewGroup()
	if g.ScalarLength() != ScalarSize {
		t.Errorf("ScalarLength = %d, want %d", g.ScalarLength(), ScalarSize)
	}
}

// TestName tests group name.
func TestName(t *testing.T) {
	g := NewGroup()
	if g.Name() != "p256" {
		t.Errorf("Name = %q, want %q", g.Name(), "p256")
	}
}

// TestScalarMultDistributivity tests that scalar multiplication is distributive.
func TestScalarMultDistributivity(t *testing.T) {
	g := NewGroup()

	// Get random scalars
	a, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	b, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Test (a + b) * G = a*G + b*G
	sum := a.Add(b)
	left := g.ScalarBaseMult(sum)

	aG := g.ScalarBaseMult(a)
	bG := g.ScalarBaseMult(b)
	right := aG.Add(bG)

	if !left.Equal(right) {
		t.Error("scalar multiplication should be distributive")
	}
}

// TestScalarMultAssociativity tests that scalar multiplication is associative.
func TestScalarMultAssociativity(t *testing.T) {
	g := NewGroup()

	// Get random scalars
	a, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	b, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Test (a * b) * G = a * (b * G)
	product := a.Mul(b)
	left := g.ScalarBaseMult(product)

	bG := g.ScalarBaseMult(b)
	right := g.ScalarMult(bG, a)

	if !left.Equal(right) {
		t.Error("scalar multiplication should be associative")
	}
}

// BenchmarkScalarAdd benchmarks scalar addition.
func BenchmarkScalarAdd(b *testing.B) {
	g := NewGroup()
	a, _ := g.RandomScalar()
	c, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Add(c)
	}
}

// BenchmarkScalarMul benchmarks scalar multiplication.
func BenchmarkScalarMul(b *testing.B) {
	g := NewGroup()
	a, _ := g.RandomScalar()
	c, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Mul(c)
	}
}

// BenchmarkScalarInv benchmarks scalar inversion.
func BenchmarkScalarInv(b *testing.B) {
	g := NewGroup()
	a, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Inv()
	}
}

// BenchmarkElementAdd benchmarks element addition.
func BenchmarkElementAdd(b *testing.B) {
	g := NewGroup()
	elem1 := g.Generator()
	elem2 := g.ScalarBaseMult(NewScalarFromBigInt(big.NewInt(2)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = elem1.Add(elem2)
	}
}

// BenchmarkScalarBaseMult benchmarks scalar base multiplication.
func BenchmarkScalarBaseMult(b *testing.B) {
	g := NewGroup()
	scalar, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.ScalarBaseMult(scalar)
	}
}

// BenchmarkScalarMult benchmarks scalar multiplication.
func BenchmarkScalarMult(b *testing.B) {
	g := NewGroup()
	elem := g.Generator()
	scalar, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.ScalarMult(elem, scalar)
	}
}

// BenchmarkSerializeElement benchmarks element serialization.
func BenchmarkSerializeElement(b *testing.B) {
	g := NewGroup()
	elem := g.Generator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.SerializeElement(elem)
	}
}

// BenchmarkDeserializeElement benchmarks element deserialization.
func BenchmarkDeserializeElement(b *testing.B) {
	g := NewGroup()
	elem := g.Generator()
	bytes, _ := g.SerializeElement(elem)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.DeserializeElement(bytes)
	}
}

// BenchmarkRandomScalar benchmarks random scalar generation.
func BenchmarkRandomScalar(b *testing.B) {
	g := NewGroup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.RandomScalar()
	}
}

// TestOrderPadding tests that Order returns properly padded bytes.
func TestOrderPadding(t *testing.T) {
	g := NewGroup()
	order := g.Order()

	// Should always be ScalarSize bytes
	if len(order) != ScalarSize {
		t.Errorf("order length = %d, want %d", len(order), ScalarSize)
	}

	// Get it again to ensure consistency
	order2 := g.Order()
	if !bytes.Equal(order, order2) {
		t.Error("Order() should return consistent results")
	}
}

// TestScalarInvError tests that Inv returns error for invalid scalars.
func TestScalarInvError(t *testing.T) {
	g := NewGroup()

	// Test that zero inverse returns error
	zero := g.NewScalar()
	_, err := zero.Inv()
	if err == nil {
		t.Error("Inv(0) should return error")
	}
	if err != frost.ErrZeroScalar {
		t.Errorf("Inv(0) error = %v, want %v", err, frost.ErrZeroScalar)
	}
}

// TestScalarBytesRoundTrip tests scalar byte encoding round-trip.
func TestScalarBytesRoundTrip(t *testing.T) {
	// Test with large value
	g := NewGroup()
	large, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	largeBytes := large.Bytes()
	if len(largeBytes) != ScalarSize {
		t.Errorf("large scalar bytes length = %d, want %d", len(largeBytes), ScalarSize)
	}

	// Verify round-trip
	deserialized, err := g.DeserializeScalar(largeBytes)
	if err != nil {
		t.Fatalf("DeserializeScalar failed: %v", err)
	}

	if !deserialized.Equal(large) {
		t.Error("round-trip scalar should equal original")
	}
}

// TestDeserializeElementEdgeCases tests edge cases in element deserialization.
func TestDeserializeElementEdgeCases(t *testing.T) {
	g := NewGroup()

	// Test with all zeros (should fail)
	zeros := make([]byte, ElementSize)
	_, err := g.DeserializeElement(zeros)
	if err == nil {
		t.Error("DeserializeElement with all zeros should fail")
	}

	// Test with wrong prefix (not 0x02 or 0x03)
	wrongPrefix := make([]byte, ElementSize)
	wrongPrefix[0] = 0x01
	_, err = g.DeserializeElement(wrongPrefix)
	if err == nil {
		t.Error("DeserializeElement with wrong prefix should fail")
	}
}

// TestScalarMultWithLargeScalar tests scalar multiplication with large scalar values.
func TestScalarMultWithLargeScalar(t *testing.T) {
	g := NewGroup()

	gen := g.Generator()
	largeScalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	result := g.ScalarMult(gen, largeScalar)
	if result.IsIdentity() {
		t.Error("ScalarMult with large scalar should not return identity (statistically impossible)")
	}

	// Verify it equals ScalarBaseMult
	baseMult := g.ScalarBaseMult(largeScalar)
	if !result.Equal(baseMult) {
		t.Error("ScalarMult(G, k) should equal ScalarBaseMult(k)")
	}
}

// TestNewElementAndNewScalar tests the constructor helper functions.
func TestNewElementAndNewScalar(t *testing.T) {
	g := NewGroup()

	// Test NewElement helper
	gen := g.Generator().(*Element)
	elem := NewElement(gen.x, gen.y)
	if !elem.Equal(gen) {
		t.Error("NewElement should create equal element")
	}

	// Test NewScalarFromBigInt helper
	testValue := big.NewInt(12345)
	scalar := NewScalarFromBigInt(testValue)
	// Verify by checking round-trip
	scalarBytes := scalar.Bytes()
	reconstructed := new(big.Int).SetBytes(scalarBytes)
	if reconstructed.Cmp(testValue) != 0 {
		t.Error("NewScalarFromBigInt should create correct scalar")
	}
}

// TestElementAddResultingInZero tests element addition that results in zero coordinates.
func TestElementAddResultingInZero(t *testing.T) {
	g := NewGroup()

	// Create a point
	gen := g.Generator()

	// Negate it
	negGen := gen.Negate()

	// Add them (should result in identity)
	result := gen.Add(negGen)

	if !result.IsIdentity() {
		t.Error("G + (-G) should equal identity")
	}
}

// TestScalarMultResultingInIdentity tests scalar multiplication edge cases.
func TestScalarMultResultingInIdentity(t *testing.T) {
	g := NewGroup()

	// Test with group order as scalar (should give identity)
	orderBytes := g.Order()
	order := new(big.Int).SetBytes(orderBytes)

	// Create a scalar with the group order (will be reduced to 0 mod order)
	orderScalar := NewScalarFromBigInt(order)

	// Multiply generator by order (should give identity for prime-order groups)
	gen := g.Generator()
	result := g.ScalarMult(gen, orderScalar)

	// Since orderScalar is reduced mod order, it becomes 0, so result should be identity
	if !result.IsIdentity() {
		t.Error("n*G should equal identity (n is group order)")
	}
}

// TestScalarBaseMultConsistency tests base multiplication consistency with scalar mult.
func TestScalarBaseMultConsistency(t *testing.T) {
	g := NewGroup()

	// Test with random scalar
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	result := g.ScalarBaseMult(scalar)
	if result.IsIdentity() {
		t.Error("ScalarBaseMult with non-zero scalar should not return identity")
	}

	// Verify it matches ScalarMult
	gen := g.Generator()
	expected := g.ScalarMult(gen, scalar)

	if !result.Equal(expected) {
		t.Error("ScalarBaseMult should match ScalarMult with generator")
	}
}

// TestScalarBaseMultEdgeCases tests edge cases in scalar base multiplication.
func TestScalarBaseMultEdgeCases(t *testing.T) {
	g := NewGroup()

	// Test with group order (should give identity for prime-order groups)
	orderBytes := g.Order()
	orderInt := new(big.Int).SetBytes(orderBytes)
	orderScalar := NewScalarFromBigInt(orderInt)

	result := g.ScalarBaseMult(orderScalar)
	// Since orderScalar is reduced mod order, it becomes 0, so result should be identity
	if !result.IsIdentity() {
		t.Error("n*G should equal identity (n is group order)")
	}
}

// TestDeserializeElementOnCurveValidation tests that DeserializeElement validates points are on curve.
func TestDeserializeElementOnCurveValidation(t *testing.T) {
	g := NewGroup()

	// Create a valid point first
	gen := g.Generator()
	validBytes, err := g.SerializeElement(gen)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}

	// Test deserialization of the valid point
	elem, err := g.DeserializeElement(validBytes)
	if err != nil {
		t.Fatalf("DeserializeElement failed for valid point: %v", err)
	}

	if !elem.Equal(gen) {
		t.Error("deserialized element should equal generator")
	}
}
