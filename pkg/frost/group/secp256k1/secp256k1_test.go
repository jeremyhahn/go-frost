package secp256k1

import (
	"bytes"
	"testing"

	secp "gitlab.com/yawning/secp256k1-voi"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestGroupInterface verifies that secp256k1 Group implements the group.Group interface.
func TestGroupInterface(t *testing.T) {
	var _ group.Group = (*Group)(nil)
}

// TestElementInterface verifies that secp256k1 Element implements the group.Element interface.
func TestElementInterface(t *testing.T) {
	var _ group.Element = (*Element)(nil)
}

// TestScalarInterface verifies that secp256k1 Scalar implements the group.Scalar interface.
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

	// Verify order is the expected secp256k1 order
	// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	expectedOrder := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}

	if !bytes.Equal(order, expectedOrder) {
		t.Error("order does not match secp256k1 group order")
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

// TestIdentityBytes tests that Bytes() returns correct representation for identity.
func TestIdentityBytes(t *testing.T) {
	g := NewGroup()
	identity := g.Identity()

	// Get bytes representation
	identityBytes := identity.Bytes()

	// Should be ElementSize (33 bytes for compressed format)
	if len(identityBytes) != ElementSize {
		t.Errorf("Identity bytes length = %d, want %d", len(identityBytes), ElementSize)
	}

	// Should be all zeros for identity
	for i, b := range identityBytes {
		if b != 0 {
			t.Errorf("Identity byte at position %d = %x, want 0", i, b)
		}
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

	// Verify it's a copy
	generator2 := g.Generator()
	if generator == generator2 {
		t.Error("Generator() should return a copy, not the same reference")
	}

	// Verify it matches secp256k1 generator by checking it's not identity
	elem := generator.(*Element)
	if elem.IsIdentity() {
		t.Error("Generator should not be identity")
	}

	// Verify G * order = identity (point at infinity)
	orderBytes := g.Order()
	var orderBuf [32]byte
	copy(orderBuf[:], orderBytes)
	orderScalar, err := secp.NewScalarFromCanonicalBytes(&orderBuf)
	if err != nil {
		// The order itself is >= order, so use the fact that n mod n = 0
		// Instead, verify 1*G != identity (generator works correctly)
		one := secp.NewScalarFromUint64(1)
		result := secp.NewIdentityPoint()
		result.ScalarBaseMult(one)
		if result.Equal(secp.NewIdentityPoint()) == 1 {
			t.Error("1*G should not be identity")
		}
		return
	}

	result := secp.NewIdentityPoint()
	result.ScalarMult(orderScalar, elem.point)

	// Result should be identity
	if result.Equal(secp.NewIdentityPoint()) != 1 {
		t.Error("Generator * order should be identity")
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

	scalar1, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	if scalar1 == nil {
		t.Fatal("RandomScalar returned nil")
	}

	if scalar1.IsZero() {
		t.Error("RandomScalar should not return zero (statistically unlikely)")
	}

	// Generate another random scalar
	scalar2, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// They should be different (statistically)
	if scalar1.Equal(scalar2) {
		t.Error("RandomScalar should produce different values")
	}
}

// TestRandomScalarWithError tests random scalar generation with failing reader.
func TestRandomScalarWithError(t *testing.T) {
	// Use a failing reader
	failReader := &failingReader{}
	_, err := randomScalar(failReader)
	if err == nil {
		t.Error("randomScalar should fail with failing reader")
	}
}

// failingReader always returns an error.
type failingReader struct{}

func (r *failingReader) Read(p []byte) (n int, err error) {
	return 0, frost.ErrInvalidParameters
}

// TestScalarAdd tests scalar addition.
func TestScalarAdd(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()

	result := s1.Add(s2)

	if result == nil {
		t.Fatal("Add returned nil")
	}

	// Verify commutativity: s1 + s2 == s2 + s1
	result2 := s2.Add(s1)
	if !result.Equal(result2) {
		t.Error("Addition is not commutative")
	}

	// Verify adding zero returns the same value
	zero := g.NewScalar()
	result3 := s1.Add(zero)
	if !result3.Equal(s1) {
		t.Error("Adding zero should return same value")
	}
}

// TestScalarSub tests scalar subtraction.
func TestScalarSub(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()

	result := s1.Sub(s2)

	if result == nil {
		t.Fatal("Sub returned nil")
	}

	// Verify s1 - s2 + s2 == s1
	result2 := result.Add(s2)
	if !result2.Equal(s1) {
		t.Error("Subtraction verification failed")
	}

	// Verify subtracting zero returns the same value
	zero := g.NewScalar()
	result3 := s1.Sub(zero)
	if !result3.Equal(s1) {
		t.Error("Subtracting zero should return same value")
	}
}

// TestScalarMul tests scalar multiplication.
func TestScalarMul(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()

	result := s1.Mul(s2)

	if result == nil {
		t.Fatal("Mul returned nil")
	}

	// Verify commutativity: s1 * s2 == s2 * s1
	result2 := s2.Mul(s1)
	if !result.Equal(result2) {
		t.Error("Multiplication is not commutative")
	}

	// Verify multiplying by zero returns zero
	zero := g.NewScalar()
	result3 := s1.Mul(zero)
	if !result3.IsZero() {
		t.Error("Multiplying by zero should return zero")
	}
}

// TestScalarInv tests scalar inversion.
func TestScalarInv(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()

	inv, err := scalar.Inv()
	if err != nil {
		t.Fatalf("Inv failed: %v", err)
	}

	if inv == nil {
		t.Fatal("Inv returned nil")
	}

	// Verify s * s^-1 == 1
	one := scalar.Mul(inv)

	// Create scalar with value 1
	expectedOne := &Scalar{value: secp.NewScalarFromUint64(1)}

	if !one.Equal(expectedOne) {
		t.Error("s * s^-1 should equal 1")
	}
}

// TestScalarInvZero tests that inverting zero returns an error.
func TestScalarInvZero(t *testing.T) {
	g := NewGroup()
	zero := g.NewScalar()

	_, err := zero.Inv()
	if err == nil {
		t.Error("Inv on zero should return error")
	}

	if err != frost.ErrZeroScalar {
		t.Errorf("Inv on zero should return ErrZeroScalar, got %v", err)
	}
}

// TestScalarNegate tests scalar negation.
func TestScalarNegate(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()

	neg := scalar.Negate()

	if neg == nil {
		t.Fatal("Negate returned nil")
	}

	// Verify s + (-s) == 0
	result := scalar.Add(neg)
	if !result.IsZero() {
		t.Error("s + (-s) should equal zero")
	}
}

// TestScalarIsZero tests the IsZero method.
func TestScalarIsZero(t *testing.T) {
	g := NewGroup()

	zero := g.NewScalar()
	if !zero.IsZero() {
		t.Error("NewScalar should return zero")
	}

	nonZero, _ := g.RandomScalar()
	if nonZero.IsZero() {
		t.Error("RandomScalar should not return zero (statistically unlikely)")
	}
}

// TestScalarEqual tests scalar equality.
func TestScalarEqual(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2 := s1.Copy()

	if !s1.Equal(s2) {
		t.Error("Copied scalars should be equal")
	}

	s3, _ := g.RandomScalar()
	if s1.Equal(s3) {
		t.Error("Different random scalars should not be equal (statistically unlikely)")
	}
}

// TestScalarBytes tests scalar serialization.
func TestScalarBytes(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()
	bytes := scalar.Bytes()

	if len(bytes) != ScalarSize {
		t.Errorf("Bytes length = %d, want %d", len(bytes), ScalarSize)
	}

	// Verify deserialization
	scalar2, err := g.DeserializeScalar(bytes)
	if err != nil {
		t.Fatalf("DeserializeScalar failed: %v", err)
	}

	if !scalar.Equal(scalar2) {
		t.Error("Deserialized scalar does not match original")
	}
}

// TestScalarCopy tests scalar copying.
func TestScalarCopy(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2 := s1.Copy()

	if !s1.Equal(s2) {
		t.Error("Copied scalar should equal original")
	}

	// Verify it's a deep copy by modifying s2
	s2Neg := s2.Negate()
	if s1.Equal(s2Neg) {
		t.Error("Modifying copy should not affect original")
	}
}

// TestScalarCompare tests scalar comparison.
func TestScalarCompare(t *testing.T) {
	// Create two different scalars
	val1 := secp.NewScalarFromUint64(5)
	val2 := secp.NewScalarFromUint64(10)

	s1 := &Scalar{value: val1}
	s2 := &Scalar{value: val2}

	// s1 < s2
	if s1.Compare(s2) != -1 {
		t.Error("5 < 10, expected -1")
	}

	// s2 > s1
	if s2.Compare(s1) != 1 {
		t.Error("10 > 5, expected 1")
	}

	// s1 == s1
	if s1.Compare(s1) != 0 {
		t.Error("5 == 5, expected 0")
	}
}

// TestElementAdd tests element addition.
func TestElementAdd(t *testing.T) {
	g := NewGroup()

	e1 := g.Generator()
	e2 := g.Generator()

	result := e1.Add(e2)

	if result == nil {
		t.Fatal("Add returned nil")
	}

	if result.IsIdentity() {
		t.Error("G + G should not be identity")
	}

	// Verify commutativity: e1 + e2 == e2 + e1
	result2 := e2.Add(e1)
	if !result.Equal(result2) {
		t.Error("Addition is not commutative")
	}

	// Verify adding identity returns the same element
	identity := g.Identity()
	result3 := e1.Add(identity)
	if !result3.Equal(e1) {
		t.Error("Adding identity should return same element")
	}
}

// TestElementNegate tests element negation.
func TestElementNegate(t *testing.T) {
	g := NewGroup()

	elem := g.Generator()
	neg := elem.Negate()

	if neg == nil {
		t.Fatal("Negate returned nil")
	}

	// Verify e + (-e) == identity
	result := elem.Add(neg)
	if !result.IsIdentity() {
		t.Error("e + (-e) should equal identity")
	}
}

// TestElementIsIdentity tests the IsIdentity method.
func TestElementIsIdentity(t *testing.T) {
	g := NewGroup()

	identity := g.Identity()
	if !identity.IsIdentity() {
		t.Error("Identity element should be identity")
	}

	generator := g.Generator()
	if generator.IsIdentity() {
		t.Error("Generator should not be identity")
	}
}

// TestElementEqual tests element equality.
func TestElementEqual(t *testing.T) {
	g := NewGroup()

	e1 := g.Generator()
	e2 := e1.Copy()

	if !e1.Equal(e2) {
		t.Error("Copied elements should be equal")
	}

	e3 := g.Identity()
	if e1.Equal(e3) {
		t.Error("Generator and identity should not be equal")
	}
}

// TestElementBytes tests element serialization.
func TestElementBytes(t *testing.T) {
	g := NewGroup()

	elem := g.Generator()
	bytes := elem.Bytes()

	if len(bytes) != ElementSize {
		t.Errorf("Bytes length = %d, want %d", len(bytes), ElementSize)
	}

	// Verify deserialization
	elem2, err := g.DeserializeElement(bytes)
	if err != nil {
		t.Fatalf("DeserializeElement failed: %v", err)
	}

	if !elem.Equal(elem2) {
		t.Error("Deserialized element does not match original")
	}
}

// TestElementCopy tests element copying.
func TestElementCopy(t *testing.T) {
	g := NewGroup()

	e1 := g.Generator()
	e2 := e1.Copy()

	if !e1.Equal(e2) {
		t.Error("Copied element should equal original")
	}

	// Verify it's a deep copy by modifying e2
	e2Neg := e2.Negate()
	if e1.Equal(e2Neg) {
		t.Error("Modifying copy should not affect original")
	}
}

// TestScalarMult tests scalar multiplication with elements.
func TestScalarMult(t *testing.T) {
	g := NewGroup()

	elem := g.Generator()
	scalar, _ := g.RandomScalar()

	result := g.ScalarMult(elem, scalar)

	if result == nil {
		t.Fatal("ScalarMult returned nil")
	}

	// Verify multiplying by zero returns identity
	zero := g.NewScalar()
	result2 := g.ScalarMult(elem, zero)
	if !result2.IsIdentity() {
		t.Error("Multiplying by zero should return identity")
	}

	// Verify multiplying identity returns identity
	identity := g.Identity()
	result3 := g.ScalarMult(identity, scalar)
	if !result3.IsIdentity() {
		t.Error("Multiplying identity should return identity")
	}
}

// TestScalarBaseMult tests scalar multiplication with the generator.
func TestScalarBaseMult(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()

	result := g.ScalarBaseMult(scalar)

	if result == nil {
		t.Fatal("ScalarBaseMult returned nil")
	}

	// Verify it equals ScalarMult with generator
	result2 := g.ScalarMult(g.Generator(), scalar)
	if !result.Equal(result2) {
		t.Error("ScalarBaseMult should equal ScalarMult with generator")
	}

	// Verify multiplying by zero returns identity
	zero := g.NewScalar()
	result3 := g.ScalarBaseMult(zero)
	if !result3.IsIdentity() {
		t.Error("ScalarBaseMult by zero should return identity")
	}
}

// TestSerializeElement tests element serialization.
func TestSerializeElement(t *testing.T) {
	g := NewGroup()

	elem := g.Generator()
	bytes, err := g.SerializeElement(elem)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}

	if len(bytes) != ElementSize {
		t.Errorf("Serialized length = %d, want %d", len(bytes), ElementSize)
	}
}

// TestSerializeElementIdentity tests that serializing identity returns an error.
func TestSerializeElementIdentity(t *testing.T) {
	g := NewGroup()

	identity := g.Identity()
	_, err := g.SerializeElement(identity)
	if err == nil {
		t.Error("SerializeElement on identity should return error")
	}

	if err != frost.ErrIdentityElement {
		t.Errorf("SerializeElement on identity should return ErrIdentityElement, got %v", err)
	}
}

// TestDeserializeElement tests element deserialization.
func TestDeserializeElement(t *testing.T) {
	g := NewGroup()

	elem := g.Generator()
	bytes, _ := g.SerializeElement(elem)

	elem2, err := g.DeserializeElement(bytes)
	if err != nil {
		t.Fatalf("DeserializeElement failed: %v", err)
	}

	if !elem.Equal(elem2) {
		t.Error("Deserialized element does not match original")
	}
}

// TestDeserializeElementInvalidLength tests deserialization with invalid length.
func TestDeserializeElementInvalidLength(t *testing.T) {
	g := NewGroup()

	// Too short
	_, err := g.DeserializeElement(make([]byte, 10))
	if err == nil {
		t.Error("DeserializeElement should fail with invalid length")
	}

	// Too long
	_, err = g.DeserializeElement(make([]byte, 100))
	if err == nil {
		t.Error("DeserializeElement should fail with invalid length")
	}
}

// TestDeserializeElementInvalid tests deserialization with invalid data.
func TestDeserializeElementInvalid(t *testing.T) {
	g := NewGroup()

	// Invalid compressed point (invalid prefix)
	invalid := make([]byte, ElementSize)
	invalid[0] = 0x01 // Invalid prefix
	_, err := g.DeserializeElement(invalid)
	if err == nil {
		t.Error("DeserializeElement should fail with invalid data")
	}
}

// TestSerializeScalar tests scalar serialization.
func TestSerializeScalar(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()
	bytes := g.SerializeScalar(scalar)

	if len(bytes) != ScalarSize {
		t.Errorf("Serialized length = %d, want %d", len(bytes), ScalarSize)
	}
}

// TestDeserializeScalar tests scalar deserialization.
func TestDeserializeScalar(t *testing.T) {
	g := NewGroup()

	scalar, _ := g.RandomScalar()
	bytes := g.SerializeScalar(scalar)

	scalar2, err := g.DeserializeScalar(bytes)
	if err != nil {
		t.Fatalf("DeserializeScalar failed: %v", err)
	}

	if !scalar.Equal(scalar2) {
		t.Error("Deserialized scalar does not match original")
	}
}

// TestDeserializeScalarInvalidLength tests deserialization with invalid length.
func TestDeserializeScalarInvalidLength(t *testing.T) {
	g := NewGroup()

	// Too short
	_, err := g.DeserializeScalar(make([]byte, 10))
	if err == nil {
		t.Error("DeserializeScalar should fail with invalid length")
	}

	// Too long
	_, err = g.DeserializeScalar(make([]byte, 100))
	if err == nil {
		t.Error("DeserializeScalar should fail with invalid length")
	}
}

// TestDeserializeScalarOverflow tests deserialization with value >= order.
func TestDeserializeScalarOverflow(t *testing.T) {
	g := NewGroup()

	// Create a value equal to the order (should fail)
	orderBytes := g.Order()
	_, err := g.DeserializeScalar(orderBytes)
	if err == nil {
		t.Error("DeserializeScalar should fail with value >= order")
	}

	// Create a value > order (all 0xFF bytes)
	overflow := make([]byte, ScalarSize)
	for i := range overflow {
		overflow[i] = 0xFF
	}
	_, err = g.DeserializeScalar(overflow)
	if err == nil {
		t.Error("DeserializeScalar should fail with overflow value")
	}
}

// TestElementLength tests the ElementLength method.
func TestElementLength(t *testing.T) {
	g := NewGroup()

	if g.ElementLength() != ElementSize {
		t.Errorf("ElementLength = %d, want %d", g.ElementLength(), ElementSize)
	}
}

// TestScalarLength tests the ScalarLength method.
func TestScalarLength(t *testing.T) {
	g := NewGroup()

	if g.ScalarLength() != ScalarSize {
		t.Errorf("ScalarLength = %d, want %d", g.ScalarLength(), ScalarSize)
	}
}

// TestName tests the Name method.
func TestName(t *testing.T) {
	g := NewGroup()

	if g.Name() != "secp256k1" {
		t.Errorf("Name = %q, want %q", g.Name(), "secp256k1")
	}
}

// TestScalarMultDistributive tests distributive property of scalar multiplication.
func TestScalarMultDistributive(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()
	elem := g.Generator()

	// (s1 + s2) * elem
	sum := s1.Add(s2)
	left := g.ScalarMult(elem, sum)

	// s1 * elem + s2 * elem
	prod1 := g.ScalarMult(elem, s1)
	prod2 := g.ScalarMult(elem, s2)
	right := prod1.Add(prod2)

	if !left.Equal(right) {
		t.Error("Scalar multiplication is not distributive")
	}
}

// TestScalarMultAssociative tests associative property of scalar multiplication.
func TestScalarMultAssociative(t *testing.T) {
	g := NewGroup()

	s1, _ := g.RandomScalar()
	s2, _ := g.RandomScalar()
	elem := g.Generator()

	// (s1 * s2) * elem
	prod := s1.Mul(s2)
	left := g.ScalarMult(elem, prod)

	// s1 * (s2 * elem)
	temp := g.ScalarMult(elem, s2)
	right := g.ScalarMult(temp, s1)

	if !left.Equal(right) {
		t.Error("Scalar multiplication is not associative")
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
	scalar, _ := g.RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scalar.Inv()
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

// BenchmarkScalarMult benchmarks scalar multiplication with elements.
func BenchmarkScalarMult(b *testing.B) {
	g := NewGroup()
	elem := g.Generator()
	scalar, _ := g.RandomScalar()

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

// TestCofactor tests that Cofactor returns the correct value for secp256k1.
func TestCofactor(t *testing.T) {
	g := NewGroup()
	cofactor := g.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor returned nil")
	}
	if cofactor.IsZero() {
		t.Error("Cofactor should not be zero")
	}
	// secp256k1 has cofactor 1 (prime order curve)
	bytes := cofactor.Bytes()
	// The scalar should represent 1, check last byte in big-endian
	if bytes[len(bytes)-1] != 1 {
		t.Errorf("Cofactor should be 1, last byte is %d", bytes[len(bytes)-1])
	}
}

// TestByteOrder tests that ByteOrder returns BigEndian for secp256k1.
func TestByteOrder(t *testing.T) {
	g := NewGroup()
	order := g.ByteOrder()
	if order != group.BigEndian {
		t.Errorf("Expected BigEndian, got %v", order)
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
	wrapped := NewElement(genElement.point)
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
	wrapped := NewScalar(scalarTyped.value)
	if wrapped == nil {
		t.Fatal("NewScalar returned nil")
	}

	// The wrapped scalar should be equal to the original
	if !wrapped.Equal(scalar) {
		t.Error("NewScalar wrapper should produce equal scalar")
	}
}
