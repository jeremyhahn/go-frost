package helpers

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestChallengeComputer_Compute_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	// Create group commitment and public key
	secret, _ := grp.RandomScalar()
	groupCommitment := grp.ScalarBaseMult(secret)
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")

	// Compute challenge
	challenge, err := computer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	if challenge == nil {
		t.Fatal("Compute() returned nil")
	}

	if challenge.IsZero() {
		t.Error("Compute() returned zero challenge")
	}
}

func TestChallengeComputer_Compute_Deterministic(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret, _ := grp.RandomScalar()
	groupCommitment := grp.ScalarBaseMult(secret)
	groupPublicKey := grp.ScalarBaseMult(secret)
	msg := []byte("test message")

	// Compute twice
	c1, err := computer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	c2, err := computer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Should produce identical challenge
	if !c1.Equal(c2) {
		t.Error("Compute() is not deterministic")
	}
}

func TestChallengeComputer_Compute_DifferentMessages(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret, _ := grp.RandomScalar()
	groupCommitment := grp.ScalarBaseMult(secret)
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")

	c1, err := computer.Compute(groupCommitment, groupPublicKey, msg1)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	c2, err := computer.Compute(groupCommitment, groupPublicKey, msg2)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Challenges should differ for different messages
	if c1.Equal(c2) {
		t.Error("Compute() produced same challenge for different messages")
	}
}

func TestChallengeComputer_Compute_DifferentCommitments(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret1, _ := grp.RandomScalar()
	secret2, _ := grp.RandomScalar()
	groupCommitment1 := grp.ScalarBaseMult(secret1)
	groupCommitment2 := grp.ScalarBaseMult(secret2)
	groupPublicKey := grp.ScalarBaseMult(secret1)
	msg := []byte("test message")

	c1, err := computer.Compute(groupCommitment1, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("First Compute() error = %v", err)
	}

	c2, err := computer.Compute(groupCommitment2, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Second Compute() error = %v", err)
	}

	// Challenges should differ for different commitments
	if c1.Equal(c2) {
		t.Error("Compute() produced same challenge for different commitments")
	}
}

func TestChallengeComputer_Compute_NilCommitment(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)
	msg := []byte("test message")

	// Nil group commitment should return error
	_, err := computer.Compute(nil, groupPublicKey, msg)
	if err == nil {
		t.Error("Compute() expected error for nil group commitment")
	}
}

func TestChallengeComputer_Compute_NilPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret, _ := grp.RandomScalar()
	groupCommitment := grp.ScalarBaseMult(secret)
	msg := []byte("test message")

	// Nil public key should return error
	_, err := computer.Compute(groupCommitment, nil, msg)
	if err == nil {
		t.Error("Compute() expected error for nil public key")
	}
}

func BenchmarkComputeChallenge(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	computer := NewChallengeComputer(suite)

	secret, _ := grp.RandomScalar()
	groupCommitment := grp.ScalarBaseMult(secret)
	groupPublicKey := grp.ScalarBaseMult(secret)
	msg := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computer.Compute(groupCommitment, groupPublicKey, msg)
	}
}
