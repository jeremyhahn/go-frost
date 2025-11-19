package helpers

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestGroupCommitmentComputer_Compute_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewGroupCommitmentComputer(grp)

	// Create commitment list and binding factors
	hiding1, _ := grp.RandomScalar()
	binding1, _ := grp.RandomScalar()
	hiding2, _ := grp.RandomScalar()
	binding2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding1),
			BindingNonceCommitment: grp.ScalarBaseMult(binding1),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding2),
			BindingNonceCommitment: grp.ScalarBaseMult(binding2),
		},
	}

	bf1, _ := grp.RandomScalar()
	bf2, _ := grp.RandomScalar()
	bindingFactors := frost.BindingFactorList{
		{Identifier: 1, BindingFactor: bf1},
		{Identifier: 2, BindingFactor: bf2},
	}

	// Compute group commitment
	groupCommitment, err := computer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	if groupCommitment == nil {
		t.Fatal("Compute() returned nil")
	}

	if groupCommitment.IsIdentity() {
		t.Error("Compute() returned identity element")
	}
}

func TestGroupCommitmentComputer_Compute_Deterministic(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewGroupCommitmentComputer(grp)

	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	bf, _ := grp.RandomScalar()
	bindingFactors := frost.BindingFactorList{
		{Identifier: 1, BindingFactor: bf},
	}

	// Compute twice
	gc1, err := computer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	gc2, err := computer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Should produce identical group commitment
	if !gc1.Equal(gc2) {
		t.Error("Compute() is not deterministic")
	}
}

func TestGroupCommitmentComputer_Compute_EmptyList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewGroupCommitmentComputer(grp)

	// Empty commitment list should return error
	_, err := computer.Compute(frost.CommitmentList{}, frost.BindingFactorList{})
	if err == nil {
		t.Error("Compute() expected error for empty commitment list")
	}
}

func TestGroupCommitmentComputer_Compute_MismatchedLists(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewGroupCommitmentComputer(grp)

	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		},
	}

	bf, _ := grp.RandomScalar()
	bindingFactors := frost.BindingFactorList{
		{Identifier: 999, BindingFactor: bf}, // Wrong identifier
	}

	// Should return error for mismatched identifiers
	_, err := computer.Compute(commitmentList, bindingFactors)
	if err == nil {
		t.Error("Compute() expected error for mismatched binding factors")
	}
}

func BenchmarkComputeGroupCommitment(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewGroupCommitmentComputer(grp)

	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()

	commitmentList := make(frost.CommitmentList, 5)
	bindingFactors := make(frost.BindingFactorList, 5)

	for i := 0; i < 5; i++ {
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		}
		bf, _ := grp.RandomScalar()
		bindingFactors[i] = frost.BindingFactor{
			Identifier:    frost.Identifier(i + 1),
			BindingFactor: bf,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computer.Compute(commitmentList, bindingFactors)
	}
}
