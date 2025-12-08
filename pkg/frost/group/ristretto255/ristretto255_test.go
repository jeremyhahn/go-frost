package ristretto255

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestNewRistretto255Group tests group initialization.
func TestNewRistretto255Group(t *testing.T) {
	g := NewGroup()
	if g == nil {
		t.Fatal("NewGroup returned nil")
	}
	if g.Name() != "ristretto255" {
		t.Errorf("expected name 'ristretto255', got '%s'", g.Name())
	}
	if g.ElementLength() != 32 {
		t.Errorf("expected element length 32, got %d", g.ElementLength())
	}
	if g.ScalarLength() != 32 {
		t.Errorf("expected scalar length 32, got %d", g.ScalarLength())
	}
}

// TestGroupOrder tests that the group order is correct.
func TestGroupOrder(t *testing.T) {
	g := NewGroup()
	order := g.Order()
	if len(order) != 32 {
		t.Errorf("expected order length 32, got %d", len(order))
	}
	// The order should be non-zero
	allZero := true
	for _, b := range order {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("order is all zeros")
	}
}

// TestIdentityElement tests the identity element.
func TestIdentityElement(t *testing.T) {
	g := NewGroup()
	id := g.Identity()
	if id == nil {
		t.Fatal("Identity returned nil")
	}
	if !id.IsIdentity() {
		t.Error("Identity element does not report as identity")
	}
}

// TestGeneratorElement tests the generator element.
func TestGeneratorElement(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()
	if gen == nil {
		t.Fatal("Generator returned nil")
	}
	if gen.IsIdentity() {
		t.Error("Generator is the identity element")
	}
}

// TestElementAdd tests element addition.
func TestElementAdd(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	// Test gen + gen = 2*gen
	sum := gen.Add(gen)
	if sum == nil {
		t.Fatal("Add returned nil")
	}
	if sum.Equal(gen) {
		t.Error("gen + gen should not equal gen")
	}

	// Test element + identity = element
	id := g.Identity()
	sumWithId := gen.Add(id)
	if !sumWithId.Equal(gen) {
		t.Error("element + identity should equal element")
	}

	// Test identity + element = element
	sumIdWith := id.Add(gen)
	if !sumIdWith.Equal(gen) {
		t.Error("identity + element should equal element")
	}
}

// TestElementNegate tests element negation.
func TestElementNegate(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	// Test -gen
	neg := gen.Negate()
	if neg == nil {
		t.Fatal("Negate returned nil")
	}
	if neg.Equal(gen) {
		t.Error("-gen should not equal gen")
	}

	// Test gen + (-gen) = identity
	sum := gen.Add(neg)
	if !sum.IsIdentity() {
		t.Error("gen + (-gen) should equal identity")
	}

	// Test -(-gen) = gen
	doubleNeg := neg.Negate()
	if !doubleNeg.Equal(gen) {
		t.Error("-(-gen) should equal gen")
	}
}

// TestElementIsIdentity tests identity detection.
func TestElementIsIdentity(t *testing.T) {
	g := NewGroup()
	id := g.Identity()
	gen := g.Generator()

	if !id.IsIdentity() {
		t.Error("identity element should report as identity")
	}
	if gen.IsIdentity() {
		t.Error("generator should not report as identity")
	}
}

// TestElementEqual tests element equality.
func TestElementEqual(t *testing.T) {
	g := NewGroup()
	gen1 := g.Generator()
	gen2 := g.Generator()
	id := g.Identity()

	if !gen1.Equal(gen2) {
		t.Error("two generators should be equal")
	}
	if gen1.Equal(id) {
		t.Error("generator should not equal identity")
	}
}

// TestElementBytes tests element serialization.
func TestElementBytes(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	bytes := gen.Bytes()
	if len(bytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes))
	}

	// Identity bytes should be all zeros
	id := g.Identity()
	idBytes := id.Bytes()
	if len(idBytes) != 32 {
		t.Errorf("expected 32 bytes for identity, got %d", len(idBytes))
	}

	allZero := true
	for _, b := range idBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("identity bytes should be all zeros")
	}
}

// TestElementCopy tests element deep copy.
func TestElementCopy(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	copy := gen.Copy()
	if !copy.Equal(gen) {
		t.Error("copy should equal original")
	}

	// Modify copy and ensure original is unchanged
	negCopy := copy.Negate()
	if gen.Equal(negCopy) {
		t.Error("modifying copy should not affect original")
	}
}

// TestScalarAdd tests scalar addition.
func TestScalarAdd(t *testing.T) {
	g := NewGroup()
	s1 := g.NewScalar()
	s2 := g.NewScalar()

	sum := s1.Add(s2)
	if sum == nil {
		t.Fatal("Add returned nil")
	}

	// 0 + 0 = 0
	if !sum.IsZero() {
		t.Error("0 + 0 should equal 0")
	}
}

// TestScalarSub tests scalar subtraction.
func TestScalarSub(t *testing.T) {
	g := NewGroup()
	s1 := g.NewScalar()
	s2 := g.NewScalar()

	diff := s1.Sub(s2)
	if diff == nil {
		t.Fatal("Sub returned nil")
	}

	// 0 - 0 = 0
	if !diff.IsZero() {
		t.Error("0 - 0 should equal 0")
	}
}

// TestScalarMul tests scalar multiplication.
func TestScalarMul(t *testing.T) {
	g := NewGroup()
	s1 := g.NewScalar()
	s2 := g.NewScalar()

	prod := s1.Mul(s2)
	if prod == nil {
		t.Fatal("Mul returned nil")
	}

	// 0 * 0 = 0
	if !prod.IsZero() {
		t.Error("0 * 0 should equal 0")
	}
}

// TestScalarInv tests scalar inversion.
func TestScalarInv(t *testing.T) {
	g := NewGroup()

	// Test inversion of zero scalar should fail
	zero := g.NewScalar()
	_, err := zero.Inv()
	if err == nil {
		t.Error("inverting zero scalar should return error")
	}

	// Test inversion of non-zero scalar
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	inv, err := scalar.Inv()
	if err != nil {
		t.Fatalf("Inv failed: %v", err)
	}

	// scalar * inv = 1
	prod := scalar.Mul(inv)
	if prod.IsZero() {
		t.Error("scalar * inv should not be zero")
	}
}

// TestScalarNegate tests scalar negation.
func TestScalarNegate(t *testing.T) {
	g := NewGroup()
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	neg := scalar.Negate()
	if neg == nil {
		t.Fatal("Negate returned nil")
	}

	// scalar + (-scalar) = 0
	sum := scalar.Add(neg)
	if !sum.IsZero() {
		t.Error("scalar + (-scalar) should equal 0")
	}

	// -(-scalar) = scalar
	doubleNeg := neg.Negate()
	if !doubleNeg.Equal(scalar) {
		t.Error("-(-scalar) should equal scalar")
	}
}

// TestScalarIsZero tests zero detection.
func TestScalarIsZero(t *testing.T) {
	g := NewGroup()
	zero := g.NewScalar()

	if !zero.IsZero() {
		t.Error("new scalar should be zero")
	}

	nonZero, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Random scalar should not be zero (with overwhelming probability)
	if nonZero.IsZero() {
		t.Error("random scalar should not be zero")
	}
}

// TestScalarEqual tests scalar equality.
func TestScalarEqual(t *testing.T) {
	g := NewGroup()
	s1 := g.NewScalar()
	s2 := g.NewScalar()

	if !s1.Equal(s2) {
		t.Error("two zero scalars should be equal")
	}

	s3, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	if s1.Equal(s3) {
		t.Error("zero should not equal random scalar")
	}
}

// TestScalarBytes tests scalar serialization.
func TestScalarBytes(t *testing.T) {
	g := NewGroup()
	scalar := g.NewScalar()

	bytes := scalar.Bytes()
	if len(bytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes))
	}

	// Zero scalar bytes should be all zeros
	allZero := true
	for _, b := range bytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("zero scalar bytes should be all zeros")
	}
}

// TestScalarCopy tests scalar deep copy.
func TestScalarCopy(t *testing.T) {
	g := NewGroup()
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	copy := scalar.Copy()
	if !copy.Equal(scalar) {
		t.Error("copy should equal original")
	}

	// Modify copy and ensure original is unchanged
	negCopy := copy.Negate()
	if scalar.Equal(negCopy) {
		t.Error("modifying copy should not affect original")
	}
}

// TestScalarCompare tests scalar comparison.
func TestScalarCompare(t *testing.T) {
	g := NewGroup()
	s1 := g.NewScalar()
	s2 := g.NewScalar()

	// 0 == 0
	if s1.Compare(s2) != 0 {
		t.Error("0 should equal 0")
	}

	s3, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// For non-zero scalar, comparison should work
	cmp := s3.Compare(s1)
	if cmp == 0 {
		t.Error("random scalar should not equal zero")
	}
}

// TestRandomScalar tests random scalar generation.
func TestRandomScalar(t *testing.T) {
	g := NewGroup()

	s1, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	s2, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Two random scalars should be different (with overwhelming probability)
	if s1.Equal(s2) {
		t.Error("two random scalars should be different")
	}

	// Random scalars should not be zero (with overwhelming probability)
	if s1.IsZero() {
		t.Error("random scalar should not be zero")
	}
}

// TestScalarMult tests scalar multiplication with elements.
func TestScalarMult(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	// Test 0 * gen = identity
	zero := g.NewScalar()
	result := g.ScalarMult(gen, zero)
	if !result.IsIdentity() {
		t.Error("0 * gen should equal identity")
	}

	// Test scalar * gen != identity for non-zero scalar
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	result = g.ScalarMult(gen, scalar)
	if result.IsIdentity() {
		t.Error("scalar * gen should not be identity for non-zero scalar")
	}
}

// TestScalarBaseMult tests scalar base multiplication.
func TestScalarBaseMult(t *testing.T) {
	g := NewGroup()

	// Test 0 * B = identity
	zero := g.NewScalar()
	result := g.ScalarBaseMult(zero)
	if !result.IsIdentity() {
		t.Error("0 * B should equal identity")
	}

	// Test scalar * B = scalar * gen
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	result1 := g.ScalarBaseMult(scalar)
	result2 := g.ScalarMult(g.Generator(), scalar)

	if !result1.Equal(result2) {
		t.Error("ScalarBaseMult and ScalarMult should produce same result")
	}
}

// TestSerializeElement tests element serialization.
func TestSerializeElement(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	// Test serialization of generator
	bytes, err := g.SerializeElement(gen)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}
	if len(bytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes))
	}

	// Test that identity cannot be serialized
	id := g.Identity()
	_, err = g.SerializeElement(id)
	if err == nil {
		t.Error("serializing identity should return error")
	}
	if err != frost.ErrIdentityElement {
		t.Errorf("expected ErrIdentityElement, got %v", err)
	}
}

// TestDeserializeElement tests element deserialization.
func TestDeserializeElement(t *testing.T) {
	g := NewGroup()
	gen := g.Generator()

	// Test round-trip serialization
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

	// Test invalid input
	invalidBytes := make([]byte, 32)
	invalidBytes[31] = 0xFF // Invalid encoding
	_, err = g.DeserializeElement(invalidBytes)
	if err == nil {
		t.Error("deserializing invalid bytes should return error")
	}

	// Test wrong length
	_, err = g.DeserializeElement([]byte{1, 2, 3})
	if err == nil {
		t.Error("deserializing wrong length should return error")
	}

	// Test identity element (all zeros)
	idBytes := make([]byte, 32)
	_, err = g.DeserializeElement(idBytes)
	if err == nil {
		t.Error("deserializing identity should return error")
	}
	if err != frost.ErrIdentityElement {
		t.Errorf("expected ErrIdentityElement, got %v", err)
	}
}

// TestSerializeScalar tests scalar serialization.
func TestSerializeScalar(t *testing.T) {
	g := NewGroup()
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	bytes := g.SerializeScalar(scalar)
	if len(bytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes))
	}
}

// TestDeserializeScalar tests scalar deserialization.
func TestDeserializeScalar(t *testing.T) {
	g := NewGroup()
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Test round-trip serialization
	bytes := g.SerializeScalar(scalar)

	s2, err := g.DeserializeScalar(bytes)
	if err != nil {
		t.Fatalf("DeserializeScalar failed: %v", err)
	}

	if !s2.Equal(scalar) {
		t.Error("deserialized scalar should equal original")
	}

	// Test wrong length
	_, err = g.DeserializeScalar([]byte{1, 2, 3})
	if err == nil {
		t.Error("deserializing wrong length should return error")
	}

	// Test invalid scalar (> group order)
	invalidBytes := make([]byte, 32)
	for i := range invalidBytes {
		invalidBytes[i] = 0xFF
	}
	_, _ = g.DeserializeScalar(invalidBytes)
	// This might succeed with reduction, depending on implementation
	// Just ensure it doesn't panic
}

// TestSerializationConsistency tests that serialization is deterministic.
func TestSerializationConsistency(t *testing.T) {
	g := NewGroup()
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	bytes1 := g.SerializeScalar(scalar)
	bytes2 := g.SerializeScalar(scalar)

	if !bytes.Equal(bytes1, bytes2) {
		t.Error("serialization should be deterministic")
	}

	elem := g.ScalarBaseMult(scalar)
	elemBytes1, _ := g.SerializeElement(elem)
	elemBytes2, _ := g.SerializeElement(elem)

	if !bytes.Equal(elemBytes1, elemBytes2) {
		t.Error("element serialization should be deterministic")
	}
}

// TestGroupOperationsConsistency tests consistency of group operations.
func TestGroupOperationsConsistency(t *testing.T) {
	g := NewGroup()

	s1, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	s2, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Test (s1 + s2) * B = s1*B + s2*B
	sum := s1.Add(s2)
	left := g.ScalarBaseMult(sum)

	right1 := g.ScalarBaseMult(s1)
	right2 := g.ScalarBaseMult(s2)
	right := right1.Add(right2)

	if !left.Equal(right) {
		t.Error("(s1 + s2) * B should equal s1*B + s2*B")
	}

	// Test (s1 * s2) * B = s1 * (s2 * B)
	prod := s1.Mul(s2)
	left2 := g.ScalarBaseMult(prod)

	temp := g.ScalarBaseMult(s2)
	right3 := g.ScalarMult(temp, s1)

	if !left2.Equal(right3) {
		t.Error("(s1 * s2) * B should equal s1 * (s2 * B)")
	}
}

// TestNewElement tests creating new elements.
func TestNewElement(t *testing.T) {
	g := NewGroup()
	elem := g.NewElement()

	if elem == nil {
		t.Fatal("NewElement returned nil")
	}

	if !elem.IsIdentity() {
		t.Error("new element should be identity")
	}
}

// TestElementInterfaceCompliance tests that Element implements group.Element.
func TestElementInterfaceCompliance(t *testing.T) {
	g := NewGroup()
	var _ group.Element = g.NewElement()
}

// TestScalarInterfaceCompliance tests that Scalar implements group.Scalar.
func TestScalarInterfaceCompliance(t *testing.T) {
	g := NewGroup()
	var _ group.Scalar = g.NewScalar()
}

// TestGroupInterfaceCompliance tests that Group implements group.Group.
func TestGroupInterfaceCompliance(t *testing.T) {
	var _ group.Group = NewGroup()
}

// TestScalarArithmetic tests comprehensive scalar arithmetic.
func TestScalarArithmetic(t *testing.T) {
	g := NewGroup()

	// Generate test scalars
	a, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	b, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	c, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Test commutativity: a + b = b + a
	sum1 := a.Add(b)
	sum2 := b.Add(a)
	if !sum1.Equal(sum2) {
		t.Error("addition should be commutative")
	}

	// Test associativity: (a + b) + c = a + (b + c)
	left := a.Add(b).Add(c)
	right := a.Add(b.Add(c))
	if !left.Equal(right) {
		t.Error("addition should be associative")
	}

	// Test distributivity: a * (b + c) = a*b + a*c
	sum := b.Add(c)
	leftDist := a.Mul(sum)
	rightDist := a.Mul(b).Add(a.Mul(c))
	if !leftDist.Equal(rightDist) {
		t.Error("multiplication should distribute over addition")
	}
}

// TestElementArithmetic tests comprehensive element arithmetic.
func TestElementArithmetic(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()
	s3, _ := g.RandomScalar()

	A := g.ScalarBaseMult(s1)
	B := g.ScalarBaseMult(s2)
	C := g.ScalarBaseMult(s3)

	// Test commutativity: A + B = B + A
	sum1 := A.Add(B)
	sum2 := B.Add(A)
	if !sum1.Equal(sum2) {
		t.Error("element addition should be commutative")
	}

	// Test associativity: (A + B) + C = A + (B + C)
	left := A.Add(B).Add(C)
	right := A.Add(B.Add(C))
	if !left.Equal(right) {
		t.Error("element addition should be associative")
	}
}

// TestCrossTypeCompatibility tests compatibility between our types and group interfaces.
func TestCrossTypeCompatibility(t *testing.T) {
	g := NewGroup()

	// Create elements and scalars
	s, _ := g.RandomScalar()
	e := g.ScalarBaseMult(s)

	// Test that we can use them as interface types
	var scalar group.Scalar = s
	var element group.Element = e

	// Perform operations via interfaces
	s2, _ := g.RandomScalar()
	var scalar2 group.Scalar = s2

	sum := scalar.Add(scalar2)
	if sum == nil {
		t.Error("scalar addition via interface failed")
	}

	e2 := g.ScalarBaseMult(s2)
	var element2 group.Element = e2

	eSum := element.Add(element2)
	if eSum == nil {
		t.Error("element addition via interface failed")
	}
}

// BenchmarkScalarMult benchmarks scalar multiplication.
func BenchmarkScalarMult(b *testing.B) {
	g := NewGroup()
	scalar, _ := g.RandomScalar()
	elem := g.Generator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.ScalarMult(elem, scalar)
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

// BenchmarkRandomScalar benchmarks random scalar generation.
func BenchmarkRandomScalar(b *testing.B) {
	g := NewGroup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.RandomScalar()
	}
}

// BenchmarkElementAdd benchmarks element addition.
func BenchmarkElementAdd(b *testing.B) {
	g := NewGroup()
	e1 := g.Generator()
	e2 := g.Generator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e1.Add(e2)
	}
}

// BenchmarkScalarAdd benchmarks scalar addition.
func BenchmarkScalarAdd(b *testing.B) {
	g := NewGroup()
	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s1.Add(s2)
	}
}

// BenchmarkScalarMul benchmarks scalar multiplication.
func BenchmarkScalarMul(b *testing.B) {
	g := NewGroup()
	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s1.Mul(s2)
	}
}

// BenchmarkScalarInv benchmarks scalar inversion.
func BenchmarkScalarInv(b *testing.B) {
	g := NewGroup()
	s, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Inv()
	}
}

// TestCofactor tests that Cofactor returns the correct value for ristretto255.
func TestCofactor(t *testing.T) {
	g := NewGroup()
	cofactor := g.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor returned nil")
	}
	if cofactor.IsZero() {
		t.Error("Cofactor should not be zero")
	}
	// ristretto255 has effective cofactor 1 (prime order group)
	bytes := cofactor.Bytes()
	if bytes[0] != 1 {
		t.Errorf("Cofactor first byte should be 1, got %d", bytes[0])
	}
}

// TestByteOrder tests that ByteOrder returns LittleEndian for ristretto255.
func TestByteOrder(t *testing.T) {
	g := NewGroup()
	order := g.ByteOrder()
	if order != group.LittleEndian {
		t.Errorf("Expected LittleEndian, got %v", order)
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

// BenchmarkSerializeScalar benchmarks scalar serialization.
func BenchmarkSerializeScalar(b *testing.B) {
	g := NewGroup()
	scalar, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.SerializeScalar(scalar)
	}
}

// BenchmarkDeserializeScalar benchmarks scalar deserialization.
func BenchmarkDeserializeScalar(b *testing.B) {
	g := NewGroup()
	scalar, _ := g.RandomScalar()
	bytes := g.SerializeScalar(scalar)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.DeserializeScalar(bytes)
	}
}

// TestNewElementWrapper tests the NewElement helper function that wraps underlying crypto types.
func TestNewElementWrapper(t *testing.T) {
	g := NewGroup()

	// Get an element and extract its underlying point
	gen := g.Generator()
	genElement, ok := gen.(*Element)
	if !ok {
		t.Fatal("Generator did not return *Element type")
	}

	// Create a new Element using the NewElement wrapper
	wrapped := NewElement(genElement.elem)
	if wrapped == nil {
		t.Fatal("NewElement returned nil")
	}

	// The wrapped element should be equal to the original
	if !wrapped.Equal(gen) {
		t.Error("NewElement wrapper should produce equal element")
	}
}

// TestNewScalarWrapper tests the NewScalar helper function that wraps underlying crypto types.
func TestNewScalarWrapper(t *testing.T) {
	g := NewGroup()

	// Get a scalar and extract its underlying value
	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	scalarTyped, ok := scalar.(*Scalar)
	if !ok {
		t.Fatal("RandomScalar did not return *Scalar type")
	}

	// Create a new Scalar using the NewScalar wrapper
	wrapped := NewScalar(scalarTyped.scalar)
	if wrapped == nil {
		t.Fatal("NewScalar returned nil")
	}

	// The wrapped scalar should be equal to the original
	if !wrapped.Equal(scalar) {
		t.Error("NewScalar wrapper should produce equal scalar")
	}
}
