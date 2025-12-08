package frost_test

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

func TestDeriveIdentifier_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	data := []byte("test data for identifier derivation")
	id, err := frost.DeriveIdentifier(data, suite)
	if err != nil {
		t.Fatalf("DeriveIdentifier failed: %v", err)
	}

	// Verify non-zero
	if id == 0 {
		t.Error("Derived identifier should not be zero")
	}
}

func TestDeriveIdentifier_BigEndian(t *testing.T) {
	// P256 uses BigEndian byte order
	suite := p256_sha256.New()

	data := []byte("test data for big endian identifier derivation")
	id, err := frost.DeriveIdentifier(data, suite)
	if err != nil {
		t.Fatalf("DeriveIdentifier failed: %v", err)
	}

	// Verify non-zero
	if id == 0 {
		t.Error("Derived identifier should not be zero")
	}

	// Verify deterministic
	id2, err := frost.DeriveIdentifier(data, suite)
	if err != nil {
		t.Fatalf("DeriveIdentifier failed: %v", err)
	}
	if id != id2 {
		t.Error("DeriveIdentifier should be deterministic")
	}
}

func TestDeriveIdentifier_Deterministic(t *testing.T) {
	suite := ristretto255_sha512.New()

	data := []byte("deterministic test data")

	// Derive twice
	id1, err := frost.DeriveIdentifier(data, suite)
	if err != nil {
		t.Fatalf("DeriveIdentifier failed: %v", err)
	}

	id2, err := frost.DeriveIdentifier(data, suite)
	if err != nil {
		t.Fatalf("DeriveIdentifier failed: %v", err)
	}

	// Should be identical
	if id1 != id2 {
		t.Errorf("Same data should produce same identifier: got %d and %d", id1, id2)
	}
}

func TestDeriveIdentifier_DifferentData(t *testing.T) {
	suite := ristretto255_sha512.New()

	data1 := []byte("data one")
	data2 := []byte("data two")

	id1, _ := frost.DeriveIdentifier(data1, suite)
	id2, _ := frost.DeriveIdentifier(data2, suite)

	// Different data should (very likely) produce different identifiers
	if id1 == id2 {
		t.Error("Different data should produce different identifiers")
	}
}

func TestDeriveIdentifier_EmptyData(t *testing.T) {
	suite := ristretto255_sha512.New()

	_, err := frost.DeriveIdentifier([]byte{}, suite)
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestDeriveIdentifier_NilData(t *testing.T) {
	suite := ristretto255_sha512.New()

	_, err := frost.DeriveIdentifier(nil, suite)
	if err == nil {
		t.Error("Expected error for nil data")
	}
}

func TestDeriveIdentifierFromString_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	id, err := frost.DeriveIdentifierFromString("participant@example.com", suite)
	if err != nil {
		t.Fatalf("DeriveIdentifierFromString failed: %v", err)
	}

	if id == 0 {
		t.Error("Derived identifier should not be zero")
	}
}

func TestDeriveIdentifierFromString_Deterministic(t *testing.T) {
	suite := ristretto255_sha512.New()

	s := "user-identifier-123"

	id1, _ := frost.DeriveIdentifierFromString(s, suite)
	id2, _ := frost.DeriveIdentifierFromString(s, suite)

	if id1 != id2 {
		t.Error("Same string should produce same identifier")
	}
}

func TestMustDeriveIdentifier_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Should not panic
	id := frost.MustDeriveIdentifier([]byte("test"), suite)

	if id == 0 {
		t.Error("MustDeriveIdentifier should return non-zero identifier")
	}
}

func TestMustDeriveIdentifier_Panic(t *testing.T) {
	suite := ristretto255_sha512.New()

	defer func() {
		if r := recover(); r == nil {
			t.Error("MustDeriveIdentifier should panic on empty data")
		}
	}()

	// Should panic
	frost.MustDeriveIdentifier([]byte{}, suite)
}

func TestIdentifier_Serialize(t *testing.T) {
	id := frost.Identifier(0x12345678)
	data := id.Serialize()

	if len(data) != 4 {
		t.Errorf("Serialized identifier should be 4 bytes, got %d", len(data))
	}

	// Verify big-endian encoding
	if data[0] != 0x12 || data[1] != 0x34 || data[2] != 0x56 || data[3] != 0x78 {
		t.Errorf("Serialized identifier has wrong bytes: %x", data)
	}
}

func TestIdentifier_SerializeDeserialize(t *testing.T) {
	original := frost.Identifier(42)

	data := original.Serialize()
	deserialized, err := frost.DeserializeIdentifier(data)
	if err != nil {
		t.Fatalf("DeserializeIdentifier failed: %v", err)
	}

	if deserialized != original {
		t.Errorf("Round-trip failed: expected %d, got %d", original, deserialized)
	}
}

func TestDeserializeIdentifier_InvalidLength(t *testing.T) {
	// Too short
	_, err := frost.DeserializeIdentifier([]byte{0x01, 0x02})
	if err == nil {
		t.Error("Expected error for short data")
	}

	// Too long
	_, err = frost.DeserializeIdentifier([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	if err == nil {
		t.Error("Expected error for long data")
	}
}

func TestDeserializeIdentifier_ZeroValue(t *testing.T) {
	// Zero identifier should fail
	_, err := frost.DeserializeIdentifier([]byte{0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("Expected error for zero identifier")
	}
}

func TestIdentifier_IsValid(t *testing.T) {
	// Valid identifier
	id := frost.Identifier(1)
	if !id.IsValid() {
		t.Error("Identifier 1 should be valid")
	}

	// Invalid identifier (zero)
	zeroID := frost.Identifier(0)
	if zeroID.IsValid() {
		t.Error("Identifier 0 should not be valid")
	}
}

func TestIdentifier_MultipleValues(t *testing.T) {
	testCases := []frost.Identifier{
		1,
		100,
		1000,
		0xFFFFFFFF, // Max uint32
	}

	for _, id := range testCases {
		data := id.Serialize()
		deserialized, err := frost.DeserializeIdentifier(data)
		if err != nil {
			t.Errorf("DeserializeIdentifier failed for %d: %v", id, err)
			continue
		}

		if deserialized != id {
			t.Errorf("Round-trip failed for %d: got %d", id, deserialized)
		}
	}
}
