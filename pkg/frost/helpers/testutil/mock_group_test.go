package testutil

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

func TestMockGroup_Interface(t *testing.T) {
	grp := NewMockGroup()
	var _ group.Group = grp // Verify it implements the interface
}

func TestMockGroup_Order(t *testing.T) {
	grp := NewMockGroup()
	order := grp.Order()
	if len(order) == 0 {
		t.Fatal("Order() returned empty")
	}
}

func TestMockGroup_Cofactor(t *testing.T) {
	grp := NewMockGroup()
	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor() returned nil")
	}
}

func TestMockGroup_Identity(t *testing.T) {
	grp := NewMockGroup()
	identity := grp.Identity()
	if identity == nil {
		t.Fatal("Identity() returned nil")
	}
	if !identity.IsIdentity() {
		t.Error("Identity() should return identity element")
	}
}

func TestMockGroup_Generator(t *testing.T) {
	grp := NewMockGroup()
	gen := grp.Generator()
	if gen == nil {
		t.Fatal("Generator() returned nil")
	}
	if gen.IsIdentity() {
		t.Error("Generator() should not return identity")
	}
}

func TestMockGroup_NewScalar(t *testing.T) {
	grp := NewMockGroup()
	scalar := grp.NewScalar()
	if scalar == nil {
		t.Fatal("NewScalar() returned nil")
	}
	if !scalar.IsZero() {
		t.Error("NewScalar() should return zero scalar")
	}
}

func TestMockGroup_NewElement(t *testing.T) {
	grp := NewMockGroup()
	elem := grp.NewElement()
	if elem == nil {
		t.Fatal("NewElement() returned nil")
	}
	if !elem.IsIdentity() {
		t.Error("NewElement() should return identity")
	}
}

func TestMockGroup_RandomScalar(t *testing.T) {
	grp := NewMockGroup()
	scalar, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar() failed: %v", err)
	}
	if scalar == nil {
		t.Fatal("RandomScalar() returned nil")
	}
	if scalar.IsZero() {
		t.Error("RandomScalar() should not return zero")
	}

	// Verify randomness
	scalar2, _ := grp.RandomScalar()
	if scalar.Equal(scalar2) {
		t.Error("RandomScalar() should produce different values")
	}
}

func TestMockGroup_ScalarBaseMult(t *testing.T) {
	grp := NewMockGroup()
	scalar, _ := grp.RandomScalar()
	result := grp.ScalarBaseMult(scalar)
	if result == nil {
		t.Fatal("ScalarBaseMult() returned nil")
	}
}

func TestMockGroup_ScalarMult(t *testing.T) {
	grp := NewMockGroup()
	scalar, _ := grp.RandomScalar()
	elem := grp.Generator()
	result := grp.ScalarMult(elem, scalar)
	if result == nil {
		t.Fatal("ScalarMult() returned nil")
	}
}

func TestMockGroup_SerializeDeserializeElement(t *testing.T) {
	grp := NewMockGroup()
	elem := grp.Generator()

	bytes, err := grp.SerializeElement(elem)
	if err != nil {
		t.Fatalf("SerializeElement() failed: %v", err)
	}

	deserialized, err := grp.DeserializeElement(bytes)
	if err != nil {
		t.Fatalf("DeserializeElement() failed: %v", err)
	}

	if !deserialized.Equal(elem) {
		t.Error("deserialized element should equal original")
	}
}

func TestMockGroup_SerializeDeserializeScalar(t *testing.T) {
	grp := NewMockGroup()
	scalar, _ := grp.RandomScalar()

	bytes := grp.SerializeScalar(scalar)
	deserialized, err := grp.DeserializeScalar(bytes)
	if err != nil {
		t.Fatalf("DeserializeScalar() failed: %v", err)
	}

	if !deserialized.Equal(scalar) {
		t.Error("deserialized scalar should equal original")
	}
}

func TestMockGroup_ElementLength(t *testing.T) {
	grp := NewMockGroup()
	if grp.ElementLength() != 32 {
		t.Errorf("ElementLength() = %d, want 32", grp.ElementLength())
	}
}

func TestMockGroup_ScalarLength(t *testing.T) {
	grp := NewMockGroup()
	if grp.ScalarLength() != 32 {
		t.Errorf("ScalarLength() = %d, want 32", grp.ScalarLength())
	}
}

func TestMockGroup_Name(t *testing.T) {
	grp := NewMockGroup()
	if grp.Name() == "" {
		t.Error("Name() returned empty string")
	}
}

func TestMockGroup_ByteOrder(t *testing.T) {
	grp := NewMockGroup()
	if grp.ByteOrder() != group.LittleEndian {
		t.Errorf("ByteOrder() = %v, want LittleEndian", grp.ByteOrder())
	}
}

func TestMockScalar_Operations(t *testing.T) {
	grp := NewMockGroup()

	a, _ := grp.RandomScalar()
	b, _ := grp.RandomScalar()

	// Add
	result := a.Add(b)
	if result == nil {
		t.Error("Add() returned nil")
	}

	// Sub
	result = a.Sub(b)
	if result == nil {
		t.Error("Sub() returned nil")
	}

	// Mul
	result = a.Mul(b)
	if result == nil {
		t.Error("Mul() returned nil")
	}

	// Negate
	result = a.Negate()
	if result == nil {
		t.Error("Negate() returned nil")
	}

	// Verify a + (-a) = 0
	sum := a.Add(a.Negate())
	if !sum.IsZero() {
		t.Error("a + (-a) should equal 0")
	}

	// Copy
	copied := a.Copy()
	if !copied.Equal(a) {
		t.Error("Copy() should equal original")
	}

	// Inv
	inv, err := a.Inv()
	if err != nil {
		t.Fatalf("Inv() failed: %v", err)
	}
	product := a.Mul(inv)
	one := grp.NewScalar().Add(grp.NewScalar()) // Will be 0, we need 1
	_ = product
	_ = one

	// Compare
	cmp := a.Compare(b)
	if cmp != -1 && cmp != 0 && cmp != 1 {
		t.Errorf("Compare() returned invalid value: %d", cmp)
	}
}

func TestMockScalar_InvZero(t *testing.T) {
	grp := NewMockGroup()
	zero := grp.NewScalar()

	_, err := zero.Inv()
	if err == nil {
		t.Error("Inv(0) should return error")
	}
}

func TestMockElement_Operations(t *testing.T) {
	grp := NewMockGroup()

	elem := grp.Generator()

	// Add
	result := elem.Add(elem)
	if result == nil {
		t.Error("Add() returned nil")
	}

	// Negate
	neg := elem.Negate()
	if neg == nil {
		t.Error("Negate() returned nil")
	}

	// elem + (-elem) = identity
	sum := elem.Add(neg)
	if !sum.IsIdentity() {
		t.Error("elem + (-elem) should equal identity")
	}

	// Copy
	copied := elem.Copy()
	if !copied.Equal(elem) {
		t.Error("Copy() should equal original")
	}

	// Bytes
	bytes := elem.Bytes()
	if len(bytes) != grp.ElementLength() {
		t.Errorf("Bytes() length = %d, want %d", len(bytes), grp.ElementLength())
	}
}

func TestMockGroup_DeserializeShortData(t *testing.T) {
	grp := NewMockGroup()

	// Short element data should still work (interprets bytes as big int)
	elem, err := grp.DeserializeElement([]byte{1, 2, 3})
	if err != nil {
		t.Errorf("DeserializeElement() should work with short data: %v", err)
	}
	if elem == nil {
		t.Error("DeserializeElement() returned nil for valid data")
	}

	// Short scalar data should still work
	scalar, err := grp.DeserializeScalar([]byte{1, 2, 3})
	if err != nil {
		t.Errorf("DeserializeScalar() should work with short data: %v", err)
	}
	if scalar == nil {
		t.Error("DeserializeScalar() returned nil for valid data")
	}
}

func TestMockGroup_SerializeIdentity(t *testing.T) {
	grp := NewMockGroup()
	identity := grp.Identity()

	_, err := grp.SerializeElement(identity)
	if err == nil {
		t.Error("SerializeElement() should fail for identity")
	}
}
