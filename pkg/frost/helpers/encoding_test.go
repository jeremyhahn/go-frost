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
