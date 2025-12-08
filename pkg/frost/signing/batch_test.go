package signing

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

// TestBatchVerifier_Ed25519 tests batch verification with Ed25519
func TestBatchVerifier_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testBatchVerifier(t, suite)
}

// TestBatchVerifier_Ristretto255 tests batch verification with Ristretto255
func TestBatchVerifier_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	testBatchVerifier(t, suite)
}

// TestBatchVerifier_P256 tests batch verification with P-256
func TestBatchVerifier_P256(t *testing.T) {
	suite := p256_sha256.New()
	testBatchVerifier(t, suite)
}

func testBatchVerifier(t *testing.T, suite ciphersuite.Ciphersuite) {
	// Generate multiple signatures using different key pairs
	numSignatures := 5
	signatures := make([]frost.Signature, numSignatures)
	verifyingKeys := make([]group.Element, numSignatures)
	messages := make([][]byte, numSignatures)

	for i := 0; i < numSignatures; i++ {
		// Generate key packages
		identifiers := []frost.Identifier{1, 2, 3}
		keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
		if err != nil {
			t.Fatalf("failed to generate keys: %v", err)
		}

		// Create signature using first 2 participants
		message := []byte("test message " + string(rune('A'+i)))
		sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
		if err != nil {
			t.Fatalf("failed to create signature %d: %v", i, err)
		}

		signatures[i] = sig
		verifyingKeys[i] = publicKeyPackage.GroupPublicKey
		messages[i] = message
	}

	// Batch verify all signatures
	bv := NewBatchVerifier(suite)
	for i := 0; i < numSignatures; i++ {
		err := bv.Add(verifyingKeys[i], signatures[i], messages[i])
		if err != nil {
			t.Fatalf("failed to add signature %d to batch: %v", i, err)
		}
	}

	if bv.Size() != numSignatures {
		t.Errorf("batch size mismatch: got %d, want %d", bv.Size(), numSignatures)
	}

	err := bv.Verify()
	if err != nil {
		t.Errorf("batch verification failed: %v", err)
	}
}

// TestBatchVerifier_SingleSignature tests batch verification with a single signature
func TestBatchVerifier_SingleSignature(t *testing.T) {
	suite := ed25519_sha512.New()

	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("single signature test")
	sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}

	bv := NewBatchVerifier(suite)
	err = bv.Add(publicKeyPackage.GroupPublicKey, sig, message)
	if err != nil {
		t.Fatalf("failed to add signature: %v", err)
	}

	err = bv.Verify()
	if err != nil {
		t.Errorf("single signature batch verification failed: %v", err)
	}
}

// TestBatchVerifier_InvalidSignature tests detection of an invalid signature
func TestBatchVerifier_InvalidSignature(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	// Generate valid signatures
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	bv := NewBatchVerifier(suite)

	// Add a valid signature
	message1 := []byte("valid message")
	sig1, err := createTestSignature(t, message1, keyPackages[:2], publicKeyPackage, suite)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}
	err = bv.Add(publicKeyPackage.GroupPublicKey, sig1, message1)
	if err != nil {
		t.Fatalf("failed to add valid signature: %v", err)
	}

	// Add an invalid signature (corrupted)
	message2 := []byte("invalid message")
	sig2, err := createTestSignature(t, message2, keyPackages[:2], publicKeyPackage, suite)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}

	// Corrupt the signature
	randomZ, _ := grp.RandomScalar()
	sig2.Z = randomZ

	err = bv.Add(publicKeyPackage.GroupPublicKey, sig2, message2)
	if err != nil {
		t.Fatalf("failed to add corrupted signature: %v", err)
	}

	// Batch verification should fail
	err = bv.Verify()
	if err == nil {
		t.Error("expected batch verification to fail with invalid signature")
	}
}

// TestBatchVerifier_WrongMessage tests that wrong message is detected
func TestBatchVerifier_WrongMessage(t *testing.T) {
	suite := ed25519_sha512.New()

	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	// Create signature for one message
	originalMessage := []byte("original message")
	sig, err := createTestSignature(t, originalMessage, keyPackages[:2], publicKeyPackage, suite)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}

	// Try to verify with different message
	bv := NewBatchVerifier(suite)
	wrongMessage := []byte("wrong message")
	err = bv.Add(publicKeyPackage.GroupPublicKey, sig, wrongMessage)
	if err != nil {
		t.Fatalf("failed to add signature: %v", err)
	}

	err = bv.Verify()
	if err == nil {
		t.Error("expected verification to fail with wrong message")
	}
}

// TestBatchVerifier_EmptyBatch tests error handling for empty batch
func TestBatchVerifier_EmptyBatch(t *testing.T) {
	suite := ed25519_sha512.New()

	bv := NewBatchVerifier(suite)
	err := bv.Verify()
	if err == nil {
		t.Error("expected error for empty batch")
	}
}

// TestBatchVerifier_Clear tests the Clear method
func TestBatchVerifier_Clear(t *testing.T) {
	suite := ed25519_sha512.New()

	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("test message")
	sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}

	bv := NewBatchVerifier(suite)
	err = bv.Add(publicKeyPackage.GroupPublicKey, sig, message)
	if err != nil {
		t.Fatalf("failed to add signature: %v", err)
	}

	if bv.Size() != 1 {
		t.Errorf("expected size 1, got %d", bv.Size())
	}

	bv.Clear()

	if bv.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", bv.Size())
	}

	// Verify should fail on empty batch
	err = bv.Verify()
	if err == nil {
		t.Error("expected error after clear")
	}
}

// TestBatchVerifier_AddInvalidParameters tests error handling for Add
func TestBatchVerifier_AddInvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	bv := NewBatchVerifier(suite)

	// Generate random elements for testing
	randomScalar1, _ := grp.RandomScalar()
	randomScalar2, _ := grp.RandomScalar()
	randomR := grp.ScalarBaseMult(randomScalar1)
	validKey := grp.ScalarBaseMult(randomScalar2)

	sig := frost.Signature{R: randomR, Z: randomScalar1}

	err := bv.Add(nil, sig, []byte("test"))
	if err == nil {
		t.Error("expected error for nil verifying key")
	}

	// Test identity verifying key
	err = bv.Add(grp.Identity(), sig, []byte("test"))
	if err == nil {
		t.Error("expected error for identity verifying key")
	}

	// Test nil signature components
	invalidSig := frost.Signature{R: nil, Z: nil}
	err = bv.Add(validKey, invalidSig, []byte("test"))
	if err == nil {
		t.Error("expected error for nil signature components")
	}

	// Test identity R
	identityRSig := frost.Signature{R: grp.Identity(), Z: randomScalar1}
	err = bv.Add(validKey, identityRSig, []byte("test"))
	if err == nil {
		t.Error("expected error for identity R in signature")
	}
}

// TestVerifyAll tests the convenience VerifyAll function
func TestVerifyAll(t *testing.T) {
	suite := ed25519_sha512.New()

	numSignatures := 3
	signatures := make([]frost.Signature, numSignatures)
	verifyingKeys := make([]group.Element, numSignatures)
	messages := make([][]byte, numSignatures)

	for i := 0; i < numSignatures; i++ {
		identifiers := []frost.Identifier{1, 2, 3}
		keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
		if err != nil {
			t.Fatalf("failed to generate keys: %v", err)
		}

		message := []byte("message " + string(rune('A'+i)))
		sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
		if err != nil {
			t.Fatalf("failed to create signature: %v", err)
		}

		signatures[i] = sig
		verifyingKeys[i] = publicKeyPackage.GroupPublicKey
		messages[i] = message
	}

	err := VerifyAll(verifyingKeys, signatures, messages, suite)
	if err != nil {
		t.Errorf("VerifyAll failed: %v", err)
	}
}

// TestVerifyAll_MismatchedLengths tests error handling for mismatched input lengths
func TestVerifyAll_MismatchedLengths(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	keyScalar, _ := grp.RandomScalar()
	rScalar, _ := grp.RandomScalar()
	key := grp.ScalarBaseMult(keyScalar)
	r := grp.ScalarBaseMult(rScalar)
	z, _ := grp.RandomScalar()
	sig := frost.Signature{R: r, Z: z}

	// Mismatched lengths
	err := VerifyAll(
		[]group.Element{key, key},
		[]frost.Signature{sig},
		[][]byte{[]byte("test")},
		suite,
	)
	if err == nil {
		t.Error("expected error for mismatched lengths")
	}
}

// TestVerifyAll_Empty tests error handling for empty inputs
func TestVerifyAll_Empty(t *testing.T) {
	suite := ed25519_sha512.New()

	err := VerifyAll(
		[]group.Element{},
		[]frost.Signature{},
		[][]byte{},
		suite,
	)
	if err == nil {
		t.Error("expected error for empty inputs")
	}
}

// TestBatchVerifier_ManySignatures tests batch verification with many signatures
func TestBatchVerifier_ManySignatures(t *testing.T) {
	suite := ed25519_sha512.New()

	numSignatures := 20
	signatures := make([]frost.Signature, numSignatures)
	verifyingKeys := make([]group.Element, numSignatures)
	messages := make([][]byte, numSignatures)

	// Generate a single key set and reuse
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	for i := 0; i < numSignatures; i++ {
		message := []byte("batch message " + string(rune(i)))
		sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
		if err != nil {
			t.Fatalf("failed to create signature %d: %v", i, err)
		}

		signatures[i] = sig
		verifyingKeys[i] = publicKeyPackage.GroupPublicKey
		messages[i] = message
	}

	bv := NewBatchVerifier(suite)
	for i := 0; i < numSignatures; i++ {
		err := bv.Add(verifyingKeys[i], signatures[i], messages[i])
		if err != nil {
			t.Fatalf("failed to add signature %d: %v", i, err)
		}
	}

	err = bv.Verify()
	if err != nil {
		t.Errorf("batch verification of %d signatures failed: %v", numSignatures, err)
	}
}

// TestBatchVerifier_MixedKeys tests batch verification with signatures from different key groups
func TestBatchVerifier_MixedKeys(t *testing.T) {
	suite := ed25519_sha512.New()

	bv := NewBatchVerifier(suite)

	// Generate multiple different key sets and create signatures
	for i := 0; i < 5; i++ {
		identifiers := []frost.Identifier{1, 2, 3}
		keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
		if err != nil {
			t.Fatalf("failed to generate keys for set %d: %v", i, err)
		}

		message := []byte("message for key set " + string(rune('A'+i)))
		sig, err := createTestSignature(t, message, keyPackages[:2], publicKeyPackage, suite)
		if err != nil {
			t.Fatalf("failed to create signature for set %d: %v", i, err)
		}

		err = bv.Add(publicKeyPackage.GroupPublicKey, sig, message)
		if err != nil {
			t.Fatalf("failed to add signature for set %d: %v", i, err)
		}
	}

	err := bv.Verify()
	if err != nil {
		t.Errorf("mixed key batch verification failed: %v", err)
	}
}

// createTestSignature is a helper that creates a FROST signature for testing
func createTestSignature(
	t *testing.T,
	message []byte,
	keyPackages []*frost.KeyPackage,
	publicKeyPackage *keygen.PublicKeyPackage,
	suite ciphersuite.Ciphersuite,
) (frost.Signature, error) {
	t.Helper()

	// Generate nonces and commitments
	noncePackages := make(map[frost.Identifier]*NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range keyPackages {
		noncePkg, err := GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			return frost.Signature{}, err
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	// Generate signature shares
	signatureShares := make(map[frost.Identifier]*SignatureShare)
	for _, kp := range keyPackages {
		share, err := Sign(
			message,
			kp,
			noncePackages[kp.Identifier],
			commitments,
			suite,
		)
		if err != nil {
			return frost.Signature{}, err
		}
		signatureShares[kp.Identifier] = share
	}

	// Create verification shares map
	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for _, vs := range publicKeyPackage.VerificationShares {
		verificationShares[vs.Identifier] = vs
	}

	// Aggregate signature
	signature, err := Aggregate(
		message,
		commitments,
		signatureShares,
		verificationShares,
		publicKeyPackage.GroupPublicKey,
		suite,
	)
	if err != nil {
		return frost.Signature{}, err
	}

	return signature, nil
}
