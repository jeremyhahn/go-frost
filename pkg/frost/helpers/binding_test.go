package helpers

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestBindingFactorComputer_Compute_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	// Create group public key
	secret, _ := suite.Group().RandomScalar()
	groupPublicKey := suite.Group().ScalarBaseMult(secret)

	// Create commitment list
	hiding, _ := suite.Group().RandomScalar()
	binding, _ := suite.Group().RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hiding),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(binding),
		},
		{
			Identifier:             2,
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hiding),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(binding),
		},
	}

	msg := []byte("test message")

	// Compute binding factors
	bindingFactors, err := computer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	// Verify we got binding factors for all participants
	if len(bindingFactors) != len(commitmentList) {
		t.Errorf("Compute() returned %d binding factors, want %d", len(bindingFactors), len(commitmentList))
	}

	// Verify binding factors are not nil or zero
	for i, bf := range bindingFactors {
		if bf.BindingFactor == nil {
			t.Errorf("binding factor[%d] is nil", i)
		}
		if bf.BindingFactor.IsZero() {
			t.Errorf("binding factor[%d] is zero", i)
		}
	}
}

func TestBindingFactorComputer_Compute_Deterministic(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	secret, _ := suite.Group().RandomScalar()
	groupPublicKey := suite.Group().ScalarBaseMult(secret)

	hiding, _ := suite.Group().RandomScalar()
	binding, _ := suite.Group().RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hiding),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(binding),
		},
	}

	msg := []byte("test message")

	// Compute twice
	bf1, err := computer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	bf2, err := computer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Should produce identical binding factors
	if !bf1[0].BindingFactor.Equal(bf2[0].BindingFactor) {
		t.Error("Compute() is not deterministic")
	}
}

func TestBindingFactorComputer_Compute_DifferentMessages(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	secret, _ := suite.Group().RandomScalar()
	groupPublicKey := suite.Group().ScalarBaseMult(secret)

	hiding, _ := suite.Group().RandomScalar()
	binding, _ := suite.Group().RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             1,
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hiding),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(binding),
		},
	}

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	bf1, err := computer.Compute(groupPublicKey, commitmentList, msg1)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	bf2, err := computer.Compute(groupPublicKey, commitmentList, msg2)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Binding factors should differ for different messages
	if bf1[0].BindingFactor.Equal(bf2[0].BindingFactor) {
		t.Error("Compute() produced same binding factor for different messages")
	}
}

func TestBindingFactorComputer_GetBindingFactor_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	// Create binding factor list
	bf1, _ := suite.Group().RandomScalar()
	bf2, _ := suite.Group().RandomScalar()

	bindingFactors := frost.BindingFactorList{
		{Identifier: 1, BindingFactor: bf1},
		{Identifier: 2, BindingFactor: bf2},
	}

	// Get binding factor for participant 1
	factor, err := computer.GetBindingFactor(bindingFactors, 1)
	if err != nil {
		t.Fatalf("GetBindingFactor() error = %v", err)
	}

	if !factor.Equal(bf1) {
		t.Error("GetBindingFactor() returned wrong binding factor")
	}
}

func TestBindingFactorComputer_GetBindingFactor_NotFound(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	bf1, _ := suite.Group().RandomScalar()
	bindingFactors := frost.BindingFactorList{
		{Identifier: 1, BindingFactor: bf1},
	}

	// Try to get binding factor for non-existent participant
	_, err := computer.GetBindingFactor(bindingFactors, 999)
	if err == nil {
		t.Error("GetBindingFactor() expected error for non-existent participant")
	}
}

func BenchmarkComputeBindingFactors(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	computer := NewBindingFactorComputer(suite)

	secret, _ := suite.Group().RandomScalar()
	groupPublicKey := suite.Group().ScalarBaseMult(secret)

	hiding, _ := suite.Group().RandomScalar()
	binding, _ := suite.Group().RandomScalar()

	commitmentList := make(frost.CommitmentList, 5)
	for i := 0; i < 5; i++ {
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hiding),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(binding),
		}
	}

	msg := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computer.Compute(groupPublicKey, commitmentList, msg)
	}
}
