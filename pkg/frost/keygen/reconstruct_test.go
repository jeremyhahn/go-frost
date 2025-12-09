package keygen

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

func TestReconstruct_Ed25519_ThresholdOfTwo(t *testing.T) {
	suite := ed25519_sha512.New()
	testReconstruct(t, suite, 2, 3)
}

func TestReconstruct_Ed25519_ThresholdOfThree(t *testing.T) {
	suite := ed25519_sha512.New()
	testReconstruct(t, suite, 3, 5)
}

func TestReconstruct_Ristretto255_ThresholdOfTwo(t *testing.T) {
	suite := ristretto255_sha512.New()
	testReconstruct(t, suite, 2, 3)
}

func TestReconstruct_P256_ThresholdOfTwo(t *testing.T) {
	suite := p256_sha256.New()
	testReconstruct(t, suite, 2, 3)
}

func TestReconstruct_MinimumThreshold(t *testing.T) {
	suite := ed25519_sha512.New()
	testReconstruct(t, suite, 2, 2)
}

func TestReconstruct_LargerGroup(t *testing.T) {
	suite := ed25519_sha512.New()
	testReconstruct(t, suite, 5, 10)
}

// testReconstruct is a helper that tests secret reconstruction for a given ciphersuite and threshold
func testReconstruct(t *testing.T, suite ciphersuite.Ciphersuite, minSigners, maxSigners uint32) {
	grp := suite.Group()

	// Create identifiers for all participants
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	// Create shares using the TrustedDealerKeygen
	keyPackages, _, err := TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate key packages: %v", err)
	}

	// Create share inputs from the first minSigners participants
	shareInputs := make([]ShareInput, minSigners)
	for i := uint32(0); i < minSigners; i++ {
		shareInputs[i] = ShareInput{
			Identifier: keyPackages[i].Identifier,
			Share:      keyPackages[i].SecretShare,
		}
	}

	// Reconstruct the secret
	reconstructed, err := Reconstruct(shareInputs, suite)
	if err != nil {
		t.Fatalf("failed to reconstruct secret: %v", err)
	}

	// Verify that g^reconstructed equals the group public key
	computedPublicKey := grp.ScalarBaseMult(reconstructed)
	if !computedPublicKey.Equal(keyPackages[0].GroupPublicKey) {
		t.Error("reconstructed secret does not match group public key")
	}
}

func TestReconstruct_DifferentSubsets(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	identifiers := make([]frost.Identifier, 5)
	for i := 0; i < 5; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	// Generate shares with threshold 3 of 5
	keyPackages, _, err := TrustedDealerKeygen(5, 3, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate key packages: %v", err)
	}

	// Test with first 3 participants
	subset1 := []ShareInput{
		{Identifier: keyPackages[0].Identifier, Share: keyPackages[0].SecretShare},
		{Identifier: keyPackages[1].Identifier, Share: keyPackages[1].SecretShare},
		{Identifier: keyPackages[2].Identifier, Share: keyPackages[2].SecretShare},
	}
	reconstructed1, err := Reconstruct(subset1, suite)
	if err != nil {
		t.Fatalf("failed to reconstruct with subset 1: %v", err)
	}

	// Test with participants 1, 3, 5
	subset2 := []ShareInput{
		{Identifier: keyPackages[0].Identifier, Share: keyPackages[0].SecretShare},
		{Identifier: keyPackages[2].Identifier, Share: keyPackages[2].SecretShare},
		{Identifier: keyPackages[4].Identifier, Share: keyPackages[4].SecretShare},
	}
	reconstructed2, err := Reconstruct(subset2, suite)
	if err != nil {
		t.Fatalf("failed to reconstruct with subset 2: %v", err)
	}

	// Both subsets should reconstruct the same secret
	if !reconstructed1.Equal(reconstructed2) {
		t.Error("different subsets reconstructed different secrets")
	}

	// Verify public key
	publicKey := grp.ScalarBaseMult(reconstructed1)
	if !publicKey.Equal(keyPackages[0].GroupPublicKey) {
		t.Error("reconstructed secret doesn't produce correct public key")
	}
}

func TestReconstruct_InsufficientShares(t *testing.T) {
	suite := ed25519_sha512.New()

	identifiers := make([]frost.Identifier, 3)
	for i := 0; i < 3; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	// Generate shares with threshold 3 of 3
	keyPackages, _, err := TrustedDealerKeygen(3, 3, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate key packages: %v", err)
	}

	// Try to reconstruct with only 2 shares (less than threshold)
	insufficientShares := []ShareInput{
		{Identifier: keyPackages[0].Identifier, Share: keyPackages[0].SecretShare},
		{Identifier: keyPackages[1].Identifier, Share: keyPackages[1].SecretShare},
	}

	// This will still "work" mathematically but produce wrong result
	// (The actual validation happens at a higher level)
	reconstructed, err := Reconstruct(insufficientShares, suite)
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}

	// Verify it doesn't match the group public key
	computedPublicKey := suite.Group().ScalarBaseMult(reconstructed)
	if computedPublicKey.Equal(keyPackages[0].GroupPublicKey) {
		t.Error("insufficient shares should not produce correct reconstruction")
	}
}

func TestReconstruct_EmptyShares(t *testing.T) {
	suite := ed25519_sha512.New()

	_, err := Reconstruct([]ShareInput{}, suite)
	if err == nil {
		t.Error("expected error for empty shares")
	}
}

func TestReconstruct_NilShare(t *testing.T) {
	suite := ed25519_sha512.New()

	shares := []ShareInput{
		{Identifier: frost.Identifier(1), Share: nil},
	}

	_, err := Reconstruct(shares, suite)
	if err == nil {
		t.Error("expected error for nil share")
	}
}

func TestReconstruct_DuplicateIdentifiers(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	scalar, _ := grp.RandomScalar()
	shares := []ShareInput{
		{Identifier: frost.Identifier(1), Share: scalar},
		{Identifier: frost.Identifier(1), Share: scalar}, // Duplicate
	}

	_, err := Reconstruct(shares, suite)
	if err == nil {
		t.Error("expected error for duplicate identifiers")
	}
}

func TestVerifyReconstruction(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	identifiers := make([]frost.Identifier, 3)
	for i := 0; i < 3; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, _, err := TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate key packages: %v", err)
	}

	// Reconstruct
	shares := []ShareInput{
		{Identifier: keyPackages[0].Identifier, Share: keyPackages[0].SecretShare},
		{Identifier: keyPackages[1].Identifier, Share: keyPackages[1].SecretShare},
	}
	reconstructed, err := Reconstruct(shares, suite)
	if err != nil {
		t.Fatalf("failed to reconstruct: %v", err)
	}

	// Verify using the VerifyReconstruction function
	err = VerifyReconstruction(reconstructed, keyPackages[0].GroupPublicKey, grp)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestVerifyReconstruction_WrongSecret(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	identifiers := make([]frost.Identifier, 3)
	for i := 0; i < 3; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, _, err := TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate key packages: %v", err)
	}

	// Use a random (wrong) secret
	wrongSecret, _ := grp.RandomScalar()

	err = VerifyReconstruction(wrongSecret, keyPackages[0].GroupPublicKey, grp)
	if err == nil {
		t.Error("expected verification to fail with wrong secret")
	}
}

func TestVerifyReconstruction_NilSecret(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	// Create a valid public key
	scalar, _ := grp.RandomScalar()
	publicKey := grp.ScalarBaseMult(scalar)

	err := VerifyReconstruction(nil, publicKey, grp)
	if err == nil {
		t.Error("expected error for nil secret")
	}
}

func TestVerifyReconstruction_NilPublicKey(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	// Create a valid secret
	secret, _ := grp.RandomScalar()

	err := VerifyReconstruction(secret, nil, grp)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}
