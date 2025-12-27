package testutil

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

func TestMockCiphersuite_ID(t *testing.T) {
	suite := NewMockCiphersuite()
	id := suite.ID()
	if id != "FROST-MOCK-SHA512-v1" {
		t.Errorf("ID() = %q, want %q", id, "FROST-MOCK-SHA512-v1")
	}
}

func TestMockCiphersuite_Group(t *testing.T) {
	suite := NewMockCiphersuite()
	grp := suite.Group()
	if grp == nil {
		t.Fatal("Group() returned nil")
	}
	var _ group.Group = grp // Verify it implements the interface
}

func TestMockCiphersuite_H1(t *testing.T) {
	suite := NewMockCiphersuite()
	scalar := suite.H1([]byte("test data"))
	if scalar == nil {
		t.Fatal("H1() returned nil")
	}
	if scalar.IsZero() {
		t.Error("H1() should not return zero scalar")
	}
}

func TestMockCiphersuite_H2(t *testing.T) {
	suite := NewMockCiphersuite()
	scalar := suite.H2([]byte("test data"))
	if scalar == nil {
		t.Fatal("H2() returned nil")
	}
	if scalar.IsZero() {
		t.Error("H2() should not return zero scalar")
	}
}

func TestMockCiphersuite_H3(t *testing.T) {
	suite := NewMockCiphersuite()
	scalar := suite.H3([]byte("test data"))
	if scalar == nil {
		t.Fatal("H3() returned nil")
	}
	if scalar.IsZero() {
		t.Error("H3() should not return zero scalar")
	}
}

func TestMockCiphersuite_H4(t *testing.T) {
	suite := NewMockCiphersuite()
	hash := suite.H4([]byte("test message"))
	if len(hash) == 0 {
		t.Fatal("H4() returned empty")
	}
}

func TestMockCiphersuite_H5(t *testing.T) {
	suite := NewMockCiphersuite()
	hash := suite.H5([]byte("test data"))
	if len(hash) == 0 {
		t.Fatal("H5() returned empty")
	}
}

func TestMockCiphersuite_HDKG(t *testing.T) {
	suite := NewMockCiphersuite()
	scalar := suite.HDKG([]byte("test data"))
	if scalar == nil {
		t.Fatal("HDKG() returned nil")
	}
	if scalar.IsZero() {
		t.Error("HDKG() should not return zero scalar")
	}
}

func TestMockCiphersuite_HID(t *testing.T) {
	suite := NewMockCiphersuite()
	scalar := suite.HID([]byte("test data"))
	if scalar == nil {
		t.Fatal("HID() returned nil")
	}
	if scalar.IsZero() {
		t.Error("HID() should not return zero scalar")
	}
}

func TestMockCiphersuite_Hash(t *testing.T) {
	suite := NewMockCiphersuite()
	hash := suite.Hash([]byte("test data"))
	if len(hash) == 0 {
		t.Fatal("Hash() returned empty")
	}
}

func TestMockCiphersuite_VerifySignature(t *testing.T) {
	suite := NewMockCiphersuite()
	grp := suite.Group()
	publicKey := grp.Generator()

	// Test with valid 64-byte signature
	validSig := make([]byte, 64)
	for i := range validSig {
		validSig[i] = byte(i)
	}

	err := suite.VerifySignature([]byte("test"), validSig, publicKey)
	if err != nil {
		t.Errorf("VerifySignature failed for valid signature: %v", err)
	}

	// Test with invalid signature (wrong length)
	invalidSig := make([]byte, 32)
	err = suite.VerifySignature([]byte("test"), invalidSig, publicKey)
	if err == nil {
		t.Error("VerifySignature should fail for invalid signature length")
	}
}

func TestMockCiphersuite_HashToCurve(t *testing.T) {
	suite := NewMockCiphersuite()
	elem, err := suite.HashToCurve([]byte("test data"))
	if err != nil {
		t.Fatalf("HashToCurve() failed: %v", err)
	}
	if elem == nil {
		t.Fatal("HashToCurve() returned nil")
	}
	if elem.IsIdentity() {
		t.Error("HashToCurve() should not return identity")
	}
}

func TestMockCiphersuite_Name(t *testing.T) {
	suite := NewMockCiphersuite()
	name := suite.Name()
	if name == "" {
		t.Error("Name() returned empty string")
	}
}

func TestMockCiphersuite_ContextString(t *testing.T) {
	suite := NewMockCiphersuite()
	ctx := suite.ContextString()
	if ctx != "FROST-MOCK-SHA512-v1" {
		t.Errorf("ContextString() = %q, want %q", ctx, "FROST-MOCK-SHA512-v1")
	}
}
