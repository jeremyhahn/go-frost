package helpers

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestCommitmentListEncoder_Encode_Success(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a commitment list with 2 participants
	commitmentList := make(frost.CommitmentList, 2)

	// Participant 1
	hiding1, _ := grp.RandomScalar()
	binding1, _ := grp.RandomScalar()
	commitmentList[0] = frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding1),
		BindingNonceCommitment: grp.ScalarBaseMult(binding1),
	}

	// Participant 2
	hiding2, _ := grp.RandomScalar()
	binding2, _ := grp.RandomScalar()
	commitmentList[1] = frost.SigningCommitments{
		Identifier:             2,
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding2),
		BindingNonceCommitment: grp.ScalarBaseMult(binding2),
	}

	// Encode the commitment list
	encoded, err := encoder.Encode(commitmentList)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	// Verify encoded is not nil
	if encoded == nil {
		t.Fatal("Encode() returned nil")
	}

	// Verify encoded has the expected length
	// Each commitment: identifier (scalar) + hiding (element) + binding (element)
	scalarLen := grp.ScalarLength()
	elemLen := grp.ElementLength()
	expectedLen := len(commitmentList) * (scalarLen + 2*elemLen)

	if len(encoded) != expectedLen {
		t.Errorf("Encode() length = %d, want %d", len(encoded), expectedLen)
	}
}

func TestCommitmentListEncoder_Encode_EmptyList(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Empty commitment list
	commitmentList := make(frost.CommitmentList, 0)

	// Should return empty bytes, not error
	encoded, err := encoder.Encode(commitmentList)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	if len(encoded) != 0 {
		t.Errorf("Encode() of empty list should return empty bytes, got %d bytes", len(encoded))
	}
}

func TestCommitmentListEncoder_Encode_Deterministic(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a commitment list
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	// Encode twice
	encoded1, err := encoder.Encode(commitmentList)
	if err != nil {
		t.Fatalf("First Encode() error = %v", err)
	}

	encoded2, err := encoder.Encode(commitmentList)
	if err != nil {
		t.Fatalf("Second Encode() error = %v", err)
	}

	// Should produce identical output
	if !bytes.Equal(encoded1, encoded2) {
		t.Error("Encode() is not deterministic")
	}
}

func TestCommitmentListEncoder_GetParticipants_Success(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a commitment list with 3 participants
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             3,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             5,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	// Get participants
	participants := encoder.GetParticipants(commitmentList)

	// Verify count
	if len(participants) != 3 {
		t.Fatalf("GetParticipants() count = %d, want 3", len(participants))
	}

	// Verify identifiers
	expected := []frost.Identifier{1, 3, 5}
	for i, id := range participants {
		if id != expected[i] {
			t.Errorf("GetParticipants()[%d] = %d, want %d", i, id, expected[i])
		}
	}
}

func TestCommitmentListEncoder_GetParticipants_EmptyList(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	participants := encoder.GetParticipants(frost.CommitmentList{})

	if len(participants) != 0 {
		t.Errorf("GetParticipants() of empty list should return empty slice, got %d", len(participants))
	}
}

func TestCommitmentListEncoder_ValidateCommitmentList_Valid(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a sorted commitment list
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             3,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	// Should validate successfully
	err := encoder.ValidateCommitmentList(commitmentList)
	if err != nil {
		t.Errorf("ValidateCommitmentList() error = %v, want nil", err)
	}
}

func TestCommitmentListEncoder_ValidateCommitmentList_Empty(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Empty list should return error
	err := encoder.ValidateCommitmentList(frost.CommitmentList{})
	if err == nil {
		t.Error("ValidateCommitmentList() expected error for empty list")
	}
}

func TestCommitmentListEncoder_ValidateCommitmentList_Unsorted(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create an unsorted commitment list
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             3,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	// Should return error for unsorted list
	err := encoder.ValidateCommitmentList(commitmentList)
	if err == nil {
		t.Error("ValidateCommitmentList() expected error for unsorted list")
	}
}

func TestCommitmentListEncoder_ValidateCommitmentList_Duplicates(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a list with duplicate identifiers
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	// Should return error for duplicates
	err := encoder.ValidateCommitmentList(commitmentList)
	if err == nil {
		t.Error("ValidateCommitmentList() expected error for duplicate identifiers")
	}
}

func TestCommitmentListEncoder_ValidateCommitmentList_SingleItem(t *testing.T) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Single item list should be valid
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	err := encoder.ValidateCommitmentList(commitmentList)
	if err != nil {
		t.Errorf("ValidateCommitmentList() error = %v, want nil for single item", err)
	}
}

// BenchmarkEncode benchmarks commitment list encoding
func BenchmarkEncode(b *testing.B) {
	grp := testutil.NewMockGroup()
	encoder := NewCommitmentListEncoder(grp)

	// Create a commitment list with 5 participants
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := make(frost.CommitmentList, 5)
	for i := 0; i < 5; i++ {
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Encode(commitmentList)
	}
}

// Tests for IdentifierToScalar function

func TestIdentifierToScalar_LittleEndianGroups(t *testing.T) {
	// Test groups that use little-endian encoding: ed25519, ed448, ristretto255
	testCases := []struct {
		name       string
		groupName  string
		identifier frost.Identifier
		// First 4 bytes should be little-endian encoding of identifier
	}{
		{"ed25519_id_1", "ed25519", 1},
		{"ed25519_id_256", "ed25519", 256},
		{"ed25519_id_65536", "ed25519", 65536},
		{"ristretto255_id_1", "ristretto255", 1},
		{"ristretto255_id_42", "ristretto255", 42},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := testutil.NewMockGroupWithName(tc.groupName)
			scalar, err := IdentifierToScalar(grp, tc.identifier)
			if err != nil {
				t.Fatalf("IdentifierToScalar() error = %v", err)
			}

			// Get bytes and verify little-endian encoding
			bytes := scalar.Bytes()
			idVal := uint32(tc.identifier)

			// Little-endian: least significant byte first
			if bytes[0] != byte(idVal) {
				t.Errorf("byte[0] = %d, want %d (little-endian LSB)", bytes[0], byte(idVal))
			}
			if bytes[1] != byte(idVal>>8) {
				t.Errorf("byte[1] = %d, want %d", bytes[1], byte(idVal>>8))
			}
			if bytes[2] != byte(idVal>>16) {
				t.Errorf("byte[2] = %d, want %d", bytes[2], byte(idVal>>16))
			}
			if bytes[3] != byte(idVal>>24) {
				t.Errorf("byte[3] = %d, want %d", bytes[3], byte(idVal>>24))
			}
		})
	}
}

func TestIdentifierToScalar_BigEndianGroups(t *testing.T) {
	// Test groups that use big-endian encoding: p256, secp256k1
	testCases := []struct {
		name       string
		groupName  string
		identifier frost.Identifier
	}{
		{"p256_id_1", "p256", 1},
		{"p256_id_256", "p256", 256},
		{"p256_id_65536", "p256", 65536},
		{"secp256k1_id_1", "secp256k1", 1},
		{"secp256k1_id_42", "secp256k1", 42},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := testutil.NewMockGroupWithName(tc.groupName)
			scalar, err := IdentifierToScalar(grp, tc.identifier)
			if err != nil {
				t.Fatalf("IdentifierToScalar() error = %v", err)
			}

			// Get bytes and verify big-endian encoding
			bytes := scalar.Bytes()
			scalarLen := grp.ScalarLength()
			idVal := uint32(tc.identifier)

			// Big-endian: most significant byte first, value at end
			if bytes[scalarLen-1] != byte(idVal) {
				t.Errorf("byte[%d] = %d, want %d (big-endian LSB)", scalarLen-1, bytes[scalarLen-1], byte(idVal))
			}
			if bytes[scalarLen-2] != byte(idVal>>8) {
				t.Errorf("byte[%d] = %d, want %d", scalarLen-2, bytes[scalarLen-2], byte(idVal>>8))
			}
			if bytes[scalarLen-3] != byte(idVal>>16) {
				t.Errorf("byte[%d] = %d, want %d", scalarLen-3, bytes[scalarLen-3], byte(idVal>>16))
			}
			if bytes[scalarLen-4] != byte(idVal>>24) {
				t.Errorf("byte[%d] = %d, want %d", scalarLen-4, bytes[scalarLen-4], byte(idVal>>24))
			}
		})
	}
}

func TestIdentifierToScalar_Deterministic(t *testing.T) {
	grp := testutil.NewMockGroup()
	identifier := frost.Identifier(42)

	// Call twice with same identifier
	scalar1, err := IdentifierToScalar(grp, identifier)
	if err != nil {
		t.Fatalf("First IdentifierToScalar() error = %v", err)
	}

	scalar2, err := IdentifierToScalar(grp, identifier)
	if err != nil {
		t.Fatalf("Second IdentifierToScalar() error = %v", err)
	}

	// Results should be identical
	if !scalar1.Equal(scalar2) {
		t.Error("IdentifierToScalar() is not deterministic")
	}
}

func TestIdentifierToScalar_DifferentIdentifiers(t *testing.T) {
	grp := testutil.NewMockGroup()

	// Different identifiers should produce different scalars
	scalar1, err := IdentifierToScalar(grp, frost.Identifier(1))
	if err != nil {
		t.Fatalf("IdentifierToScalar(1) error = %v", err)
	}

	scalar2, err := IdentifierToScalar(grp, frost.Identifier(2))
	if err != nil {
		t.Fatalf("IdentifierToScalar(2) error = %v", err)
	}

	scalar3, err := IdentifierToScalar(grp, frost.Identifier(100))
	if err != nil {
		t.Fatalf("IdentifierToScalar(100) error = %v", err)
	}

	if scalar1.Equal(scalar2) {
		t.Error("Identifier 1 and 2 produced equal scalars")
	}
	if scalar1.Equal(scalar3) {
		t.Error("Identifier 1 and 100 produced equal scalars")
	}
	if scalar2.Equal(scalar3) {
		t.Error("Identifier 2 and 100 produced equal scalars")
	}
}

func TestIdentifierToScalar_EdgeCases(t *testing.T) {
	grp := testutil.NewMockGroup()

	testCases := []struct {
		name       string
		identifier frost.Identifier
	}{
		{"identifier_1", frost.Identifier(1)},
		{"identifier_255", frost.Identifier(255)},
		{"identifier_256", frost.Identifier(256)},
		{"identifier_65535", frost.Identifier(65535)},
		{"identifier_65536", frost.Identifier(65536)},
		{"identifier_max_uint16", frost.Identifier(0xFFFF)},
		{"identifier_large", frost.Identifier(0x12345678)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scalar, err := IdentifierToScalar(grp, tc.identifier)
			if err != nil {
				t.Fatalf("IdentifierToScalar(%d) error = %v", tc.identifier, err)
			}
			if scalar == nil {
				t.Fatalf("IdentifierToScalar(%d) returned nil", tc.identifier)
			}
			if scalar.IsZero() && tc.identifier != 0 {
				t.Errorf("IdentifierToScalar(%d) returned zero scalar for non-zero identifier", tc.identifier)
			}
		})
	}
}

func TestIdentifierToScalar_NotZero(t *testing.T) {
	// Valid participant identifiers should never produce zero scalars
	grp := testutil.NewMockGroup()

	for id := frost.Identifier(1); id <= 100; id++ {
		scalar, err := IdentifierToScalar(grp, id)
		if err != nil {
			t.Fatalf("IdentifierToScalar(%d) error = %v", id, err)
		}
		if scalar.IsZero() {
			t.Errorf("IdentifierToScalar(%d) produced zero scalar", id)
		}
	}
}

// BenchmarkIdentifierToScalar benchmarks identifier to scalar conversion
func BenchmarkIdentifierToScalar(b *testing.B) {
	grp := testutil.NewMockGroup()
	identifier := frost.Identifier(42)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IdentifierToScalar(grp, identifier)
	}
}
