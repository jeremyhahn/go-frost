package signing

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestAggregator_Aggregate_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create test commitments for 2 participants
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	// Create signature shares
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: share2,
		},
	}

	// Aggregate
	signature, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// Verify signature structure
	if signature.R == nil {
		t.Error("Expected signature.R to be set")
	}
	if signature.Z == nil {
		t.Error("Expected signature.Z to be set")
	}

	// Verify z = sum(z_i)
	expectedZ := share1.Add(share2)
	if !signature.Z.Equal(expectedZ) {
		t.Error("Signature.Z does not equal sum of signature shares")
	}
}

func TestAggregator_Aggregate_InsufficientShares(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(3)

	agg := NewAggregator(suite, minSigners)

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create test commitments for 3 participants
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	nonce3, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()
	bindingNonce3, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
		{
			Identifier:             frost.Identifier(3),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce3),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce3),
		},
	}

	msg := []byte("test message")

	// Create only 2 signature shares (insufficient)
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: share2,
		},
	}

	// Aggregate should fail
	_, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for insufficient signature shares")
	}
	if err != frost.ErrInsufficientParticipants {
		t.Errorf("Expected ErrInsufficientParticipants, got: %v", err)
	}
}

func TestAggregator_Aggregate_EmptyCommitmentList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	commitmentList := frost.CommitmentList{}
	msg := []byte("test message")
	signatureShares := []frost.SignatureShare{}

	// Aggregate should fail
	_, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for empty commitment list")
	}
	if err != frost.ErrEmptyCommitmentList {
		t.Errorf("Expected ErrEmptyCommitmentList, got: %v", err)
	}
}

func TestAggregator_Aggregate_UnsortedCommitments(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create unsorted commitments (2, 1 instead of 1, 2)
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: share2,
		},
	}

	// Aggregate should fail
	_, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for unsorted commitment list")
	}
	if err != frost.ErrUnsortedCommitments {
		t.Errorf("Expected ErrUnsortedCommitments, got: %v", err)
	}
}

func TestAggregator_Aggregate_DuplicateParticipants(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create commitments with duplicate identifier
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(1), // Duplicate
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	// Aggregate should fail
	_, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for duplicate participants")
	}
	if err != frost.ErrDuplicateParticipant {
		t.Errorf("Expected ErrDuplicateParticipant, got: %v", err)
	}
}

func TestAggregator_Verify_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Generate keypair
	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)

	// Create valid signature
	// For a valid Schnorr signature: g^z = R + c * PublicKey
	// So z = r + c * x, where r is nonce, x is secret key, c is challenge

	r, _ := grp.RandomScalar()
	R := grp.ScalarBaseMult(r)

	msg := []byte("test message")

	// Compute challenge
	challengeComputer := helpers.NewChallengeComputer(suite)
	challenge, err := challengeComputer.Compute(R, publicKey, msg)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Compute z = r + c * x
	z := r.Add(challenge.Mul(secretKey))

	signature := frost.Signature{
		R: R,
		Z: z,
	}

	// Verify signature
	err = agg.Verify(msg, signature, publicKey)
	if err != nil {
		t.Errorf("Verify failed for valid signature: %v", err)
	}
}

func TestAggregator_Verify_InvalidSignature(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Generate keypair
	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)

	// Create invalid signature (wrong z value)
	r, _ := grp.RandomScalar()
	R := grp.ScalarBaseMult(r)
	invalidZ, _ := grp.RandomScalar() // Random value, not computed correctly

	msg := []byte("test message")

	signature := frost.Signature{
		R: R,
		Z: invalidZ,
	}

	// Verify signature should fail
	err := agg.Verify(msg, signature, publicKey)
	if err == nil {
		t.Error("Expected verification to fail for invalid signature")
	}
}

func TestAggregator_Verify_NilSignatureR(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)

	z, _ := grp.RandomScalar()
	msg := []byte("test message")

	signature := frost.Signature{
		R: nil,
		Z: z,
	}

	// Verify should fail
	err := agg.Verify(msg, signature, publicKey)
	if err == nil {
		t.Error("Expected error for nil signature R")
	}
}

func TestAggregator_Verify_NilSignatureZ(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)

	r, _ := grp.RandomScalar()
	R := grp.ScalarBaseMult(r)
	msg := []byte("test message")

	signature := frost.Signature{
		R: R,
		Z: nil,
	}

	// Verify should fail
	err := agg.Verify(msg, signature, publicKey)
	if err == nil {
		t.Error("Expected error for nil signature Z")
	}
}

func TestAggregator_Verify_NilPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	r, _ := grp.RandomScalar()
	R := grp.ScalarBaseMult(r)
	z, _ := grp.RandomScalar()
	msg := []byte("test message")

	signature := frost.Signature{
		R: R,
		Z: z,
	}

	// Verify should fail
	err := agg.Verify(msg, signature, nil)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

func TestAggregator_Aggregate_IntegrationWithHelpers(t *testing.T) {
	// This test verifies that aggregation works correctly with real helper functions
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Simulate complete signing protocol
	// 1. Generate group key
	secretKey1, _ := grp.RandomScalar()
	secretKey2, _ := grp.RandomScalar()
	publicKey1 := grp.ScalarBaseMult(secretKey1)
	publicKey2 := grp.ScalarBaseMult(secretKey2)

	// For simplicity, group public key = publicKey1 + publicKey2
	groupPublicKey := publicKey1.Add(publicKey2)

	// 2. Generate nonces and commitments
	hidingNonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	hidingNonce2, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	// 3. Compute binding factors
	bindingComputer := helpers.NewBindingFactorComputer(suite)
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("Failed to compute binding factors: %v", err)
	}

	// 4. Compute group commitment
	commitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	groupCommitment, err := commitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("Failed to compute group commitment: %v", err)
	}

	// 5. Compute challenge
	challengeComputer := helpers.NewChallengeComputer(suite)
	challenge, err := challengeComputer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// 6. Compute signature shares (simplified - no lambda calculation for this test)
	bf1, _ := bindingComputer.GetBindingFactor(bindingFactors, frost.Identifier(1))
	bf2, _ := bindingComputer.GetBindingFactor(bindingFactors, frost.Identifier(2))

	// sig_share = hiding_nonce + (binding_nonce * binding_factor) + (secret_key * challenge)
	// (simplified without lambda)
	sigShare1 := hidingNonce1.Add(bindingNonce1.Mul(bf1)).Add(secretKey1.Mul(challenge))
	sigShare2 := hidingNonce2.Add(bindingNonce2.Mul(bf2)).Add(secretKey2.Mul(challenge))

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: sigShare1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: sigShare2,
		},
	}

	// 7. Aggregate signature
	signature, err := agg.Aggregate(groupPublicKey, commitmentList, msg, signatureShares)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// 8. Verify signature structure
	if signature.R == nil || signature.Z == nil {
		t.Fatal("Signature is incomplete")
	}

	// 9. Verify group commitment matches
	if !signature.R.Equal(groupCommitment) {
		t.Error("Signature R does not match computed group commitment")
	}
}

// TestAggregatorWithVerification_Success tests successful aggregation with identifiable abort.
// This verifies that valid signature shares pass verification and aggregate correctly.
func TestAggregatorWithVerification_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// 1. Generate secret keys and verification keys
	secretKey1, _ := grp.RandomScalar()
	secretKey2, _ := grp.RandomScalar()
	verificationKey1 := grp.ScalarBaseMult(secretKey1)
	verificationKey2 := grp.ScalarBaseMult(secretKey2)
	groupPublicKey := verificationKey1.Add(verificationKey2)

	// 2. Generate nonces and commitments
	hidingNonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	hidingNonce2, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	// 3. Compute binding factors and challenge
	bindingComputer := helpers.NewBindingFactorComputer(suite)
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("Failed to compute binding factors: %v", err)
	}

	commitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	groupCommitment, err := commitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("Failed to compute group commitment: %v", err)
	}

	challengeComputer := helpers.NewChallengeComputer(suite)
	challenge, err := challengeComputer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// 4. Compute Lagrange coefficients
	polynomialHelper := helpers.NewPolynomialHelper(grp)
	participants := make([]group.Scalar, 0, len(commitmentList))
	for _, commitment := range commitmentList {
		idBytes := make([]byte, grp.ScalarLength())
		idVal := uint32(commitment.Identifier)
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idVal >> (8 * j))
		}
		scalar, _ := grp.DeserializeScalar(idBytes)
		participants = append(participants, scalar)
	}

	// 5. Compute valid signature shares
	bf1, _ := bindingComputer.GetBindingFactor(bindingFactors, frost.Identifier(1))
	lambda1, _ := polynomialHelper.DeriveInterpolatingValue(participants, participants[0])
	sigShare1 := hidingNonce1.Add(bindingNonce1.Mul(bf1)).Add(secretKey1.Mul(lambda1).Mul(challenge))

	bf2, _ := bindingComputer.GetBindingFactor(bindingFactors, frost.Identifier(2))
	lambda2, _ := polynomialHelper.DeriveInterpolatingValue(participants, participants[1])
	sigShare2 := hidingNonce2.Add(bindingNonce2.Mul(bf2)).Add(secretKey2.Mul(lambda2).Mul(challenge))

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: sigShare1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: sigShare2,
		},
	}

	// 6. Create verification shares
	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey1,
		},
		{
			Identifier:      frost.Identifier(2),
			VerificationKey: verificationKey2,
		},
	}

	// 7. Aggregate with verification
	signature, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err != nil {
		t.Fatalf("AggregateWithVerification failed: %v", err)
	}

	// 8. Verify signature structure
	if signature.R == nil || signature.Z == nil {
		t.Fatal("Signature is incomplete")
	}

	// 9. Verify signature is correct
	if !signature.R.Equal(groupCommitment) {
		t.Error("Signature R does not match computed group commitment")
	}

	expectedZ := sigShare1.Add(sigShare2)
	if !signature.Z.Equal(expectedZ) {
		t.Error("Signature Z does not equal sum of signature shares")
	}
}

// TestAggregatorWithVerification_DetectsMaliciousParticipant tests that
// identifiable abort correctly identifies a malicious participant who
// provides an invalid signature share.
func TestAggregatorWithVerification_DetectsMaliciousParticipant(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// 1. Generate secret keys and verification keys
	secretKey1, _ := grp.RandomScalar()
	secretKey2, _ := grp.RandomScalar()
	verificationKey1 := grp.ScalarBaseMult(secretKey1)
	verificationKey2 := grp.ScalarBaseMult(secretKey2)
	groupPublicKey := verificationKey1.Add(verificationKey2)

	// 2. Generate nonces and commitments
	hidingNonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	hidingNonce2, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	// 3. Compute binding factors and challenge
	bindingComputer := helpers.NewBindingFactorComputer(suite)
	bindingFactors, err := bindingComputer.Compute(groupPublicKey, commitmentList, msg)
	if err != nil {
		t.Fatalf("Failed to compute binding factors: %v", err)
	}

	commitmentComputer := helpers.NewGroupCommitmentComputer(grp)
	groupCommitment, err := commitmentComputer.Compute(commitmentList, bindingFactors)
	if err != nil {
		t.Fatalf("Failed to compute group commitment: %v", err)
	}

	challengeComputer := helpers.NewChallengeComputer(suite)
	challenge, err := challengeComputer.Compute(groupCommitment, groupPublicKey, msg)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// 4. Compute Lagrange coefficients
	polynomialHelper := helpers.NewPolynomialHelper(grp)
	participants := make([]group.Scalar, 0, len(commitmentList))
	for _, commitment := range commitmentList {
		idBytes := make([]byte, grp.ScalarLength())
		idVal := uint32(commitment.Identifier)
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idVal >> (8 * j))
		}
		scalar, _ := grp.DeserializeScalar(idBytes)
		participants = append(participants, scalar)
	}

	// 5. Participant 1: Valid signature share
	bf1, _ := bindingComputer.GetBindingFactor(bindingFactors, frost.Identifier(1))
	lambda1, _ := polynomialHelper.DeriveInterpolatingValue(participants, participants[0])
	sigShare1 := hidingNonce1.Add(bindingNonce1.Mul(bf1)).Add(secretKey1.Mul(lambda1).Mul(challenge))

	// 6. Participant 2: MALICIOUS - invalid signature share (random value)
	maliciousShare, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: sigShare1,
		},
		{
			Identifier:     frost.Identifier(2),
			SignatureShare: maliciousShare, // Invalid!
		},
	}

	// 7. Create verification shares
	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey1,
		},
		{
			Identifier:      frost.Identifier(2),
			VerificationKey: verificationKey2,
		},
	}

	// 8. Aggregate with verification should FAIL and identify participant 2
	_, err = agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for malicious participant, got nil")
	}

	// Verify error identifies participant 2 and mentions malicious behavior
	errMsg := err.Error()
	if !strings.Contains(errMsg, "participant 2") || !strings.Contains(errMsg, "signature share verification failed") {
		t.Errorf("Expected error to identify participant 2 with verification failure, got: %v", err)
	}
}

// TestAggregatorWithVerification_EmptyVerificationShares tests that
// AggregateWithVerification fails when no verification shares are provided.
func TestAggregatorWithVerification_EmptyVerificationShares(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Create minimal valid inputs
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(2), SignatureShare: share2},
	}

	// Empty verification shares
	verificationShares := []frost.VerificationShare{}

	// Should fail with parameter error
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for empty verification shares")
	}
}

// TestAggregatorWithVerification_MissingVerificationKey tests that
// AggregateWithVerification fails when a verification key is missing for
// a participant's signature share.
func TestAggregatorWithVerification_MissingVerificationKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	// Generate keys
	secretKey1, _ := grp.RandomScalar()
	verificationKey1 := grp.ScalarBaseMult(secretKey1)
	groupPublicKey := verificationKey1

	// Generate commitments
	hidingNonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	hidingNonce2, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(2), SignatureShare: share2},
	}

	// Only provide verification key for participant 1, missing for participant 2
	verificationShares := []frost.VerificationShare{
		{
			Identifier:      frost.Identifier(1),
			VerificationKey: verificationKey1,
		},
		// Missing participant 2's verification key
	}

	// Should fail when trying to verify participant 2's share
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for missing verification key")
	}
}

// TestAggregatorWithVerification_InsufficientShares tests that
// AggregateWithVerification properly checks minimum signer threshold.
func TestAggregatorWithVerification_InsufficientShares(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(3) // Require 3 signers

	agg := NewAggregator(suite, minSigners)

	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	nonce3, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()
	bindingNonce3, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
		{
			Identifier:             frost.Identifier(3),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce3),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce3),
		},
	}

	msg := []byte("test message")

	// Only provide 2 signature shares (insufficient)
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(2), SignatureShare: share2},
	}

	verificationKey1, _ := grp.RandomScalar()
	verificationKey2, _ := grp.RandomScalar()

	verificationShares := []frost.VerificationShare{
		{Identifier: frost.Identifier(1), VerificationKey: grp.ScalarBaseMult(verificationKey1)},
		{Identifier: frost.Identifier(2), VerificationKey: grp.ScalarBaseMult(verificationKey2)},
	}

	// Should fail with insufficient participants error
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for insufficient signature shares")
	}
	if err != frost.ErrInsufficientParticipants {
		t.Errorf("Expected ErrInsufficientParticipants, got: %v", err)
	}
}

// TestAggregatorWithVerification_NilGroupPublicKey tests error handling for nil group public key.
func TestAggregatorWithVerification_NilGroupPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	msg := []byte("test message")
	share1, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
	}

	verificationKey1, _ := grp.RandomScalar()
	verificationShares := []frost.VerificationShare{
		{Identifier: frost.Identifier(1), VerificationKey: grp.ScalarBaseMult(verificationKey1)},
	}

	// Nil group public key
	_, err := agg.AggregateWithVerification(nil, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for nil group public key")
	}
}

// TestAggregatorWithVerification_EmptyCommitmentList tests error handling for empty commitment list.
func TestAggregatorWithVerification_EmptyCommitmentList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	commitmentList := frost.CommitmentList{}
	msg := []byte("test message")

	signatureShares := []frost.SignatureShare{}
	verificationShares := []frost.VerificationShare{}

	// Should fail with empty commitment list error
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for empty commitment list")
	}
	if err != frost.ErrEmptyCommitmentList {
		t.Errorf("Expected ErrEmptyCommitmentList, got: %v", err)
	}
}

// TestAggregator_AggregateWithVerification_EmptyVerificationShares tests that aggregation fails with empty verification shares
func TestAggregator_AggregateWithVerification_EmptyVerificationShares(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	agg := NewAggregator(suite, 2)

	// Create commitment list
	nonce1, _ := grp.RandomScalar()
	binding1, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(binding1),
		},
	}

	// Create signature shares
	share1, _ := grp.RandomScalar()
	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	groupPublicKey := grp.Generator()
	msg := []byte("test")

	// Empty verification shares - should fail
	verificationShares := []frost.VerificationShare{}

	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for empty verification shares")
	}
}

// TestNewAggregator tests the NewAggregator constructor
func TestNewAggregator(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	minSigners := uint32(3)

	agg := NewAggregator(suite, minSigners)
	if agg == nil {
		t.Fatal("NewAggregator returned nil")
	}

	// Verify it's an aggregator by using it
	a := agg.(*aggregator)
	if a.minSigners != minSigners {
		t.Errorf("Expected minSigners %d, got %d", minSigners, a.minSigners)
	}
}

// TestAggregator_Verify_IdentityR tests verification fails with identity R
func TestAggregator_Verify_IdentityR(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	secretKey, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(secretKey)

	z, _ := grp.RandomScalar()
	msg := []byte("test message")

	signature := frost.Signature{
		R: grp.Identity(), // Identity element
		Z: z,
	}

	// Verify should fail
	err := agg.Verify(msg, signature, publicKey)
	if err == nil {
		t.Error("Expected error for identity R")
	}
}

// TestAggregator_Verify_IdentityPublicKey tests verification fails with identity public key
func TestAggregator_Verify_IdentityPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	r, _ := grp.RandomScalar()
	R := grp.ScalarBaseMult(r)
	z, _ := grp.RandomScalar()
	msg := []byte("test message")

	signature := frost.Signature{
		R: R,
		Z: z,
	}

	// Verify should fail with identity public key
	err := agg.Verify(msg, signature, grp.Identity())
	if err == nil {
		t.Error("Expected error for identity public key")
	}
}

// TestAggregator_Aggregate_NilGroupPublicKey2 tests error handling for nil group public key in Aggregate
func TestAggregator_Aggregate_NilGroupPublicKey2(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(2), SignatureShare: share2},
	}

	// Nil group public key should fail
	_, err := agg.Aggregate(nil, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for nil group public key")
	}
}

// TestAggregatorWithVerification_MissingBindingFactor tests error handling when
// a signature share has an identifier that isn't in the commitment list
func TestAggregatorWithVerification_MissingBindingFactor(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create commitments for identifiers 1 and 2
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	// Signature share with identifier 999 not in commitment list
	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(999), SignatureShare: share2}, // Not in commitments
	}

	verificationShares := []frost.VerificationShare{
		{Identifier: frost.Identifier(1), VerificationKey: grp.Generator()},
		{Identifier: frost.Identifier(999), VerificationKey: grp.Generator()},
	}

	// Should fail when looking up binding factor for identifier 999
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for missing binding factor")
	}
}

// TestAggregatorWithVerification_MissingCommitment tests error handling when
// a signature share identifier has no corresponding commitment in the list
func TestAggregatorWithVerification_MissingCommitment(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create commitments for identifiers 1 and 2
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	msg := []byte("test message")

	share1, _ := grp.RandomScalar()
	share3, _ := grp.RandomScalar()

	// Signature share for identifier 3, but commitmentList only has 1 and 2
	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share1},
		{Identifier: frost.Identifier(3), SignatureShare: share3}, // No commitment for 3
	}

	// Verification shares include identifier 3
	verificationShares := []frost.VerificationShare{
		{Identifier: frost.Identifier(1), VerificationKey: grp.Generator()},
		{Identifier: frost.Identifier(3), VerificationKey: grp.Generator()},
	}

	// Should fail when looking for commitment for identifier 3
	_, err := agg.AggregateWithVerification(groupPublicKey, commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Fatal("Expected error for missing commitment")
	}
}
