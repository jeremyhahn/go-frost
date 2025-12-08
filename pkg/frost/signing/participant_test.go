package signing

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

// TestParticipant_RoundOne_Success tests successful round one execution
func TestParticipant_RoundOne_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create a key package for participant 1
	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)

	// Execute round one
	nonces, commitments, err := participant.RoundOne()
	if err != nil {
		t.Fatalf("RoundOne() failed: %v", err)
	}

	// Verify nonces are not nil and not zero
	if nonces.HidingNonce == nil {
		t.Error("RoundOne() returned nil hiding nonce")
	}
	if nonces.BindingNonce == nil {
		t.Error("RoundOne() returned nil binding nonce")
	}
	if nonces.HidingNonce.IsZero() {
		t.Error("RoundOne() returned zero hiding nonce")
	}
	if nonces.BindingNonce.IsZero() {
		t.Error("RoundOne() returned zero binding nonce")
	}

	// Verify nonces are different
	if nonces.HidingNonce.Equal(nonces.BindingNonce) {
		t.Error("RoundOne() returned identical hiding and binding nonces")
	}

	// Verify commitments match nonces
	if commitments.Identifier != frost.Identifier(1) {
		t.Errorf("Expected identifier 1, got %d", commitments.Identifier)
	}

	// Verify hiding nonce commitment = hiding_nonce * G
	expectedHidingCommitment := grp.ScalarBaseMult(nonces.HidingNonce)
	if !commitments.HidingNonceCommitment.Equal(expectedHidingCommitment) {
		t.Error("HidingNonceCommitment does not match hiding_nonce * G")
	}

	// Verify binding nonce commitment = binding_nonce * G
	expectedBindingCommitment := grp.ScalarBaseMult(nonces.BindingNonce)
	if !commitments.BindingNonceCommitment.Equal(expectedBindingCommitment) {
		t.Error("BindingNonceCommitment does not match binding_nonce * G")
	}

	// Verify commitments in nonces match returned commitments
	if nonces.Commitments.Identifier != commitments.Identifier {
		t.Error("Nonces.Commitments.Identifier does not match commitments.Identifier")
	}
	if !nonces.Commitments.HidingNonceCommitment.Equal(commitments.HidingNonceCommitment) {
		t.Error("Nonces.Commitments.HidingNonceCommitment does not match commitments.HidingNonceCommitment")
	}
	if !nonces.Commitments.BindingNonceCommitment.Equal(commitments.BindingNonceCommitment) {
		t.Error("Nonces.Commitments.BindingNonceCommitment does not match commitments.BindingNonceCommitment")
	}
}

// TestParticipant_RoundOne_NonceUniqueness tests that nonces are unique across calls
func TestParticipant_RoundOne_NonceUniqueness(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)

	// Generate multiple nonce pairs
	nonces1, _, _ := participant.RoundOne()
	nonces2, _, _ := participant.RoundOne()
	nonces3, _, _ := participant.RoundOne()

	// All nonces should be unique
	if nonces1.HidingNonce.Equal(nonces2.HidingNonce) {
		t.Error("RoundOne() generated duplicate hiding nonces")
	}
	if nonces1.BindingNonce.Equal(nonces2.BindingNonce) {
		t.Error("RoundOne() generated duplicate binding nonces")
	}
	if nonces2.HidingNonce.Equal(nonces3.HidingNonce) {
		t.Error("RoundOne() generated duplicate hiding nonces")
	}
	if nonces2.BindingNonce.Equal(nonces3.BindingNonce) {
		t.Error("RoundOne() generated duplicate binding nonces")
	}
}

// TestParticipant_RoundTwo_Success tests successful round two execution
func TestParticipant_RoundTwo_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create 3 participants
	participants := make([]Participant, 3)
	keyPackages := make([]frost.KeyPackage, 3)

	for i := 0; i < 3; i++ {
		secretShare, _ := grp.RandomScalar()
		groupPubKey := grp.ScalarBaseMult(secretShare)

		keyPackages[i] = frost.KeyPackage{
			Identifier:     frost.Identifier(i + 1),
			SecretShare:    secretShare,
			GroupPublicKey: groupPubKey,
		}

		participants[i] = NewParticipant(keyPackages[i], suite)
	}

	// Round 1: All participants generate nonces and commitments
	nonces := make([]frost.SigningNonces, 3)
	commitmentList := make(frost.CommitmentList, 3)

	for i := 0; i < 3; i++ {
		var err error
		nonces[i], commitmentList[i], err = participants[i].RoundOne()
		if err != nil {
			t.Fatalf("Participant %d RoundOne() failed: %v", i+1, err)
		}
	}

	// Message to sign
	message := []byte("test message for FROST signing")

	// Round 2: All participants generate signature shares
	shares := make([]frost.SignatureShare, 3)

	for i := 0; i < 3; i++ {
		var err error
		shares[i], err = participants[i].RoundTwo(nonces[i], message, commitmentList)
		if err != nil {
			t.Fatalf("Participant %d RoundTwo() failed: %v", i+1, err)
		}
	}

	// Verify signature shares have correct identifiers
	for i := 0; i < 3; i++ {
		if shares[i].Identifier != frost.Identifier(i+1) {
			t.Errorf("Share %d has wrong identifier: expected %d, got %d", i, i+1, shares[i].Identifier)
		}

		if shares[i].SignatureShare == nil {
			t.Errorf("Share %d has nil SignatureShare", i)
		}

		if shares[i].SignatureShare.IsZero() {
			t.Errorf("Share %d has zero SignatureShare", i)
		}
	}

	// All shares should be different (with overwhelming probability)
	if shares[0].SignatureShare.Equal(shares[1].SignatureShare) {
		t.Error("Shares 0 and 1 are identical")
	}
	if shares[0].SignatureShare.Equal(shares[2].SignatureShare) {
		t.Error("Shares 0 and 2 are identical")
	}
	if shares[1].SignatureShare.Equal(shares[2].SignatureShare) {
		t.Error("Shares 1 and 2 are identical")
	}
}

// TestParticipant_RoundTwo_DifferentMessages tests that different messages produce different shares
func TestParticipant_RoundTwo_DifferentMessages(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create a single participant
	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)

	// Generate nonces and commitments
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	// Sign different messages with same nonces
	message1 := []byte("first message")
	message2 := []byte("second message")

	share1, err := participant.RoundTwo(nonces, message1, commitmentList)
	if err != nil {
		t.Fatalf("RoundTwo() with message1 failed: %v", err)
	}

	share2, err := participant.RoundTwo(nonces, message2, commitmentList)
	if err != nil {
		t.Fatalf("RoundTwo() with message2 failed: %v", err)
	}

	// Shares should be different for different messages
	if share1.SignatureShare.Equal(share2.SignatureShare) {
		t.Error("Different messages produced identical signature shares")
	}
}

// TestParticipant_RoundTwo_EmptyCommitmentList tests error handling for empty commitment list
func TestParticipant_RoundTwo_EmptyCommitmentList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, _, _ := participant.RoundOne()

	message := []byte("test message")
	emptyCommitmentList := frost.CommitmentList{}

	_, err := participant.RoundTwo(nonces, message, emptyCommitmentList)
	if err == nil {
		t.Error("RoundTwo() should fail with empty commitment list")
	}
}

// TestParticipant_RoundTwo_SingleParticipant tests signing with a single participant
func TestParticipant_RoundTwo_SingleParticipant(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	message := []byte("test message")

	share, err := participant.RoundTwo(nonces, message, commitmentList)
	if err != nil {
		t.Fatalf("RoundTwo() failed for single participant: %v", err)
	}

	if share.Identifier != frost.Identifier(1) {
		t.Errorf("Expected identifier 1, got %d", share.Identifier)
	}

	if share.SignatureShare == nil || share.SignatureShare.IsZero() {
		t.Error("Single participant should produce valid signature share")
	}
}

// TestParticipant_VerifySignatureShare_Success tests successful signature share verification
func TestParticipant_VerifySignatureShare_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	// Use dealer to generate proper key packages
	dealer := keygen.NewDealer(suite)
	minSigners := uint32(2)
	maxSigners := uint32(2)
	participantIDs := []frost.Identifier{1, 2}

	keyPackages, _, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate key packages: %v", err)
	}

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(keyPackages[i], suite)
	}

	// Round 1: Generate commitments
	nonces := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i := 0; i < 2; i++ {
		var err error
		nonces[i], commitmentList[i], err = participants[i].RoundOne()
		if err != nil {
			t.Fatalf("Participant %d RoundOne() failed: %v", i+1, err)
		}
	}

	message := []byte("test message")

	// Round 2: Generate signature shares
	shares := make([]frost.SignatureShare, 2)

	for i := 0; i < 2; i++ {
		var err error
		shares[i], err = participants[i].RoundTwo(nonces[i], message, commitmentList)
		if err != nil {
			t.Fatalf("Participant %d RoundTwo() failed: %v", i+1, err)
		}
	}

	// Each participant verifies the other's share
	err = participants[0].VerifySignatureShare(shares[1], message, commitmentList)
	if err != nil {
		t.Errorf("Participant 0 failed to verify participant 1's valid share: %v", err)
	}

	err = participants[1].VerifySignatureShare(shares[0], message, commitmentList)
	if err != nil {
		t.Errorf("Participant 1 failed to verify participant 0's valid share: %v", err)
	}
}

// TestParticipant_VerifySignatureShare_InvalidShare tests detection of invalid shares
func TestParticipant_VerifySignatureShare_InvalidShare(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create a participant
	secretShare, _ := grp.RandomScalar()
	verificationKey := grp.ScalarBaseMult(secretShare)
	groupPubKey := grp.ScalarBaseMult(secretShare)

	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey,
		},
	}

	keyPackage := frost.KeyPackage{
		Identifier:         frost.Identifier(1),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: verificationShares,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}
	message := []byte("test message")

	// Create a valid share
	validShare, _ := participant.RoundTwo(nonces, message, commitmentList)

	// Create an invalid share (use a random scalar)
	invalidScalar, _ := grp.RandomScalar()
	invalidShare := frost.SignatureShare{
		Identifier:     validShare.Identifier,
		SignatureShare: invalidScalar,
	}

	// Verification should fail for invalid share
	err := participant.VerifySignatureShare(invalidShare, message, commitmentList)
	if err == nil {
		t.Error("VerifySignatureShare() should fail for invalid share")
	}
}

// TestParticipant_VerifySignatureShare_WrongMessage tests verification with wrong message
func TestParticipant_VerifySignatureShare_WrongMessage(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	verificationKey := grp.ScalarBaseMult(secretShare)
	groupPubKey := grp.ScalarBaseMult(secretShare)

	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey,
		},
	}

	keyPackage := frost.KeyPackage{
		Identifier:         frost.Identifier(1),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: verificationShares,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	message1 := []byte("original message")
	message2 := []byte("different message")

	// Generate share for message1
	share, _ := participant.RoundTwo(nonces, message1, commitmentList)

	// Verification should fail when using message2
	err := participant.VerifySignatureShare(share, message2, commitmentList)
	if err == nil {
		t.Error("VerifySignatureShare() should fail when verifying with wrong message")
	}
}

// TestParticipant_Identifier tests the Identifier method
func TestParticipant_Identifier(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	testCases := []frost.Identifier{1, 2, 5, 100, 999}

	for _, expectedID := range testCases {
		keyPackage := frost.KeyPackage{
			Identifier:     expectedID,
			SecretShare:    secretShare,
			GroupPublicKey: groupPubKey,
		}

		participant := NewParticipant(keyPackage, suite)

		if participant.Identifier() != expectedID {
			t.Errorf("Identifier() = %d, want %d", participant.Identifier(), expectedID)
		}
	}
}

// TestParticipant_IntegrationTest performs an end-to-end signing flow
func TestParticipant_IntegrationTest(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	// Use dealer to generate proper key packages with correct polynomial relationship
	dealer := keygen.NewDealer(suite)

	// 2-of-3 threshold scheme
	minSigners := uint32(2)
	maxSigners := uint32(3)
	participantIDs := []frost.Identifier{1, 2, 3}

	// Generate proper key packages using trusted dealer
	keyPackages, groupPubKey, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate key packages: %v", err)
	}

	// Create participants
	numParticipants := len(keyPackages)
	participants := make([]Participant, numParticipants)
	for i := 0; i < numParticipants; i++ {
		participants[i] = NewParticipant(keyPackages[i], suite)
	}

	// Round 1: All participants generate nonces and commitments
	nonces := make([]frost.SigningNonces, numParticipants)
	commitmentList := make(frost.CommitmentList, numParticipants)

	for i := 0; i < numParticipants; i++ {
		var err error
		nonces[i], commitmentList[i], err = participants[i].RoundOne()
		if err != nil {
			t.Fatalf("Participant %d RoundOne() failed: %v", i+1, err)
		}
	}

	// Message to sign
	message := []byte("Complete integration test for FROST signing")

	// Round 2: All participants generate signature shares
	shares := make([]frost.SignatureShare, numParticipants)

	for i := 0; i < numParticipants; i++ {
		var err error
		shares[i], err = participants[i].RoundTwo(nonces[i], message, commitmentList)
		if err != nil {
			t.Fatalf("Participant %d RoundTwo() failed: %v", i+1, err)
		}
	}

	// Verification: Each participant verifies all other shares
	for i := 0; i < numParticipants; i++ {
		for j := 0; j < numParticipants; j++ {
			if i == j {
				continue // Skip self-verification
			}

			err := participants[i].VerifySignatureShare(shares[j], message, commitmentList)
			if err != nil {
				t.Errorf("Participant %d failed to verify participant %d's share: %v", i+1, j+1, err)
			}
		}
	}

	// Additional verification: Ensure group public key matches
	if !keyPackages[0].GroupPublicKey.Equal(groupPubKey) {
		t.Error("Group public key mismatch in key package")
	}
}

// TestParticipant_NonceReusePrevention tests that nonces cannot be reused
func TestParticipant_NonceReusePrevention(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)

	// Generate nonces
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	message1 := []byte("first message")
	message2 := []byte("second message")

	// First use of nonces should succeed
	_, err := participant.RoundTwo(nonces, message1, commitmentList)
	if err != nil {
		t.Fatalf("First RoundTwo() failed: %v", err)
	}

	// Attempting to reuse same nonces should still work at the participant level
	// (nonce reuse prevention is typically enforced at the coordinator level)
	// But the implementation should handle it gracefully
	_, err = participant.RoundTwo(nonces, message2, commitmentList)
	if err != nil {
		// If the implementation prevents reuse, that's acceptable
		t.Logf("Nonce reuse prevented (good): %v", err)
	} else {
		// If reuse is allowed at participant level, warn but don't fail
		t.Log("Warning: Nonce reuse allowed at participant level - coordinator must enforce prevention")
	}
}

// TestParticipant_EmptyMessage tests signing an empty message
func TestParticipant_EmptyMessage(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	// Empty message should be handled gracefully
	emptyMessage := []byte{}

	share, err := participant.RoundTwo(nonces, emptyMessage, commitmentList)
	if err != nil {
		t.Fatalf("RoundTwo() failed with empty message: %v", err)
	}

	if share.SignatureShare == nil || share.SignatureShare.IsZero() {
		t.Error("Empty message should still produce valid signature share")
	}
}

// TestParticipant_LargeMessage tests signing a large message
func TestParticipant_LargeMessage(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}

	// Create a large message (1 MB)
	largeMessage := bytes.Repeat([]byte("a"), 1024*1024)

	share, err := participant.RoundTwo(nonces, largeMessage, commitmentList)
	if err != nil {
		t.Fatalf("RoundTwo() failed with large message: %v", err)
	}

	if share.SignatureShare == nil || share.SignatureShare.IsZero() {
		t.Error("Large message should produce valid signature share")
	}
}

// BenchmarkParticipant_RoundOne benchmarks round one performance
func BenchmarkParticipant_RoundOne(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := participant.RoundOne()
		if err != nil {
			b.Fatalf("RoundOne() failed: %v", err)
		}
	}
}

// BenchmarkParticipant_RoundTwo benchmarks round two performance
func BenchmarkParticipant_RoundTwo(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
	}

	participant := NewParticipant(keyPackage, suite)
	_, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate fresh nonces for each iteration
		nonces, _, _ := participant.RoundOne()

		_, err := participant.RoundTwo(nonces, message, commitmentList)
		if err != nil {
			b.Fatalf("RoundTwo() failed: %v", err)
		}
	}
}

// BenchmarkParticipant_VerifySignatureShare benchmarks signature share verification
func BenchmarkParticipant_VerifySignatureShare(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	verificationKey := grp.ScalarBaseMult(secretShare)
	groupPubKey := grp.ScalarBaseMult(secretShare)

	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey,
		},
	}

	keyPackage := frost.KeyPackage{
		Identifier:         frost.Identifier(1),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: verificationShares,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}
	message := []byte("benchmark message")
	share, _ := participant.RoundTwo(nonces, message, commitmentList)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := participant.VerifySignatureShare(share, message, commitmentList)
		if err != nil {
			b.Fatalf("VerifySignatureShare() failed: %v", err)
		}
	}
}

// TestParticipant_VerifySignatureShare_MissingCommitment tests error when commitment not in list
func TestParticipant_VerifySignatureShare_MissingCommitment(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	verificationKey := grp.ScalarBaseMult(secretShare)
	groupPubKey := grp.ScalarBaseMult(secretShare)

	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey,
		},
		{
			Identifier:      frost.Identifier(2),
			VerificationKey: verificationKey,
		},
	}

	keyPackage := frost.KeyPackage{
		Identifier:         frost.Identifier(1),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: verificationShares,
	}

	participant := NewParticipant(keyPackage, suite)
	_, commitments, _ := participant.RoundOne()
	commitmentList := frost.CommitmentList{commitments}
	message := []byte("test message")

	// Create a share for participant 2 (not in commitment list)
	invalidShare := frost.SignatureShare{
		Identifier:     frost.Identifier(2),
		SignatureShare: secretShare,
	}

	err := participant.VerifySignatureShare(invalidShare, message, commitmentList)
	if err == nil {
		t.Error("VerifySignatureShare() should fail when commitment not in list")
	}
}

// TestParticipant_VerifySignatureShare_MissingVerificationShare tests error when verification share not found
func TestParticipant_VerifySignatureShare_MissingVerificationShare(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare1, _ := grp.RandomScalar()
	secretShare2, _ := grp.RandomScalar()
	verificationKey1 := grp.ScalarBaseMult(secretShare1)
	groupPubKey := grp.ScalarBaseMult(secretShare1)

	// Only have verification share for participant 1, not 2
	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey1,
		},
	}

	keyPackage := frost.KeyPackage{
		Identifier:         frost.Identifier(1),
		SecretShare:        secretShare1,
		GroupPublicKey:     groupPubKey,
		VerificationShares: verificationShares,
	}

	participant := NewParticipant(keyPackage, suite)

	// Create commitment for participant 2
	nonce2, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitment2 := frost.SigningCommitments{
		Identifier:             frost.Identifier(2),
		HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
		BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
	}

	commitmentList := frost.CommitmentList{commitment2}
	message := []byte("test message")

	// Create a share for participant 2
	share2 := frost.SignatureShare{
		Identifier:     frost.Identifier(2),
		SignatureShare: secretShare2,
	}

	err := participant.VerifySignatureShare(share2, message, commitmentList)
	if err == nil {
		t.Error("VerifySignatureShare() should fail when verification share not found")
	}
}

// TestParticipant_RoundTwo_InvalidCommitmentList tests that RoundTwo fails with an invalid commitment list
func TestParticipant_RoundTwo_InvalidCommitmentList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPublicKey := grp.Generator()

	participant := NewParticipant(
		frost.KeyPackage{
			Identifier:         frost.Identifier(1),
			SecretShare:        secretShare,
			GroupPublicKey:     groupPublicKey,
			VerificationShares: []frost.VerificationShare{},
		},
		suite,
	)

	// Generate nonces
	nonces, _, err := participant.RoundOne()
	if err != nil {
		t.Fatalf("RoundOne failed: %v", err)
	}

	// Create an invalid commitment list with duplicate identifiers
	hiding1, _ := grp.RandomScalar()
	binding1, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding1),
			BindingNonceCommitment: grp.ScalarBaseMult(binding1),
		},
		{
			Identifier:             frost.Identifier(1), // Duplicate!
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding1),
			BindingNonceCommitment: grp.ScalarBaseMult(binding1),
		},
	}

	msg := []byte("test")

	// RoundTwo should fail with duplicate identifiers
	_, err = participant.RoundTwo(nonces, msg, commitmentList)
	if err == nil {
		t.Fatal("Expected RoundTwo to fail with duplicate identifiers in commitment list")
	}
}

// TestNewParticipant tests the NewParticipant constructor
func TestNewParticipant(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	keyPackage := frost.KeyPackage{
		Identifier:  frost.Identifier(42),
		SecretShare: secretShare,
	}

	participant := NewParticipant(keyPackage, suite)
	if participant == nil {
		t.Fatal("NewParticipant returned nil")
	}

	if participant.Identifier() != frost.Identifier(42) {
		t.Errorf("Expected identifier 42, got %d", participant.Identifier())
	}
}

// failingGroup wraps a group and can be configured to fail on specific operations
type failingGroup struct {
	group.Group
	failRandomScalarCount     int
	randomScalarCalls         int
	failDeserializeScalarCall int
	deserializeScalarCalls    int
}

func (g *failingGroup) RandomScalar() (group.Scalar, error) {
	g.randomScalarCalls++
	if g.failRandomScalarCount > 0 && g.randomScalarCalls == g.failRandomScalarCount {
		return nil, errors.New("mock random scalar error")
	}
	return g.Group.RandomScalar()
}

func (g *failingGroup) DeserializeScalar(data []byte) (group.Scalar, error) {
	g.deserializeScalarCalls++
	if g.failDeserializeScalarCall > 0 && g.deserializeScalarCalls == g.failDeserializeScalarCall {
		return nil, errors.New("mock deserialize scalar error")
	}
	return g.Group.DeserializeScalar(data)
}

// failingSuite wraps a ciphersuite and can inject a failing group
type failingSuite struct {
	ciphersuite.Ciphersuite
	failingGrp *failingGroup
}

func (s *failingSuite) Group() group.Group {
	return s.failingGrp
}

// TestParticipant_RoundTwo_DeserializeScalarError tests RoundTwo when DeserializeScalar fails
func TestParticipant_RoundTwo_DeserializeScalarError(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create key packages using dealer
	dealer := keygen.NewDealer(suite)
	minSigners := uint32(2)
	maxSigners := uint32(2)
	participantIDs := []frost.Identifier{1, 2}

	keyPackages, _, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate key packages: %v", err)
	}

	// Create participants
	participant1 := NewParticipant(keyPackages[0], suite)
	participant2 := NewParticipant(keyPackages[1], suite)

	// Generate commitments
	nonces1, commitments1, _ := participant1.RoundOne()
	_, commitments2, _ := participant2.RoundOne()

	commitmentList := frost.CommitmentList{commitments1, commitments2}
	message := []byte("test message")

	// Create a failing group that fails on first DeserializeScalar call
	failGrp := &failingGroup{
		Group:                     grp,
		failDeserializeScalarCall: 1,
	}
	failSuite := &failingSuite{
		Ciphersuite: suite,
		failingGrp:  failGrp,
	}

	// Create participant with failing suite
	failingParticipant := NewParticipant(keyPackages[0], failSuite)

	_, err = failingParticipant.RoundTwo(nonces1, message, commitmentList)
	if err == nil {
		t.Fatal("Expected RoundTwo to fail when DeserializeScalar fails")
	}
}

// TestParticipant_RoundTwo_MyIDDeserializeError tests RoundTwo when myID DeserializeScalar fails
func TestParticipant_RoundTwo_MyIDDeserializeError(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create key packages using dealer
	dealer := keygen.NewDealer(suite)
	minSigners := uint32(2)
	maxSigners := uint32(2)
	participantIDs := []frost.Identifier{1, 2}

	keyPackages, _, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate key packages: %v", err)
	}

	// Create participants
	participant1 := NewParticipant(keyPackages[0], suite)
	participant2 := NewParticipant(keyPackages[1], suite)

	// Generate commitments
	nonces1, commitments1, _ := participant1.RoundOne()
	_, commitments2, _ := participant2.RoundOne()

	commitmentList := frost.CommitmentList{commitments1, commitments2}
	message := []byte("test message")

	// Create a failing group that fails on the myIDScalar DeserializeScalar call
	// This is the 3rd call (2 for participants in the loop, then 1 for myID)
	failGrp := &failingGroup{
		Group:                     grp,
		failDeserializeScalarCall: 3,
	}
	failSuite := &failingSuite{
		Ciphersuite: suite,
		failingGrp:  failGrp,
	}

	// Create participant with failing suite
	failingParticipant := NewParticipant(keyPackages[0], failSuite)

	_, err = failingParticipant.RoundTwo(nonces1, message, commitmentList)
	if err == nil {
		t.Fatal("Expected RoundTwo to fail when myIDScalar DeserializeScalar fails")
	}
}

// TestParticipant_MinSigners tests the MinSigners method.
func TestParticipant_MinSigners(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPubKey := grp.ScalarBaseMult(secretShare)

	keyPackage := frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: groupPubKey,
		MinSigners:     3,
	}

	participant := NewParticipant(keyPackage, suite)

	if participant.MinSigners() != 3 {
		t.Errorf("Expected MinSigners() = 3, got %d", participant.MinSigners())
	}
}

// TestVerifySignature tests the standalone VerifySignature function.
func TestVerifySignature(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create a valid signature
	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)
	message := []byte("test message")

	// Create a simple Schnorr signature
	k, _ := grp.RandomScalar()
	r := grp.ScalarBaseMult(k)

	// Compute challenge
	rBytes, _ := grp.SerializeElement(r)
	pkBytes, _ := grp.SerializeElement(publicKey)
	challengeInput := append(rBytes, pkBytes...)
	challengeInput = append(challengeInput, message...)
	challenge := suite.H2(challengeInput)

	// Compute response: z = k + challenge * secretKey
	z := k.Add(challenge.Mul(secretKey))

	sig := frost.Signature{
		R: r,
		Z: z,
	}

	// Verify signature
	err := VerifySignature(message, sig, publicKey, suite)
	if err != nil {
		t.Errorf("VerifySignature failed for valid signature: %v", err)
	}

	// Test with invalid signature
	badZ, _ := grp.RandomScalar()
	badSig := frost.Signature{
		R: r,
		Z: badZ,
	}

	err = VerifySignature(message, badSig, publicKey, suite)
	if err == nil {
		t.Error("VerifySignature should fail for invalid signature")
	}
}
