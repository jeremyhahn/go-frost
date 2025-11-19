// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

// TestNoOpAuthenticator_AlwaysSucceeds tests that NoOpAuthenticator accepts all inputs.
func TestNoOpAuthenticator_AlwaysSucceeds(t *testing.T) {
	auth := NewNoOpAuthenticator()
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create test commitment
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Test with nil proof
	err := auth.AuthenticateCommitment(frost.Identifier(1), commitment, nil)
	if err != nil {
		t.Errorf("NoOpAuthenticator should accept nil proof, got error: %v", err)
	}

	// Test with empty proof
	err = auth.AuthenticateCommitment(frost.Identifier(1), commitment, []byte{})
	if err != nil {
		t.Errorf("NoOpAuthenticator should accept empty proof, got error: %v", err)
	}

	// Test with random proof
	randomProof := make([]byte, 64)
	rand.Read(randomProof)
	err = auth.AuthenticateCommitment(frost.Identifier(1), commitment, randomProof)
	if err != nil {
		t.Errorf("NoOpAuthenticator should accept random proof, got error: %v", err)
	}
}

// TestNoOpAuthenticator_SignatureShareAlwaysSucceeds tests NoOpAuthenticator for signature shares.
func TestNoOpAuthenticator_SignatureShareAlwaysSucceeds(t *testing.T) {
	auth := NewNoOpAuthenticator()
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create test signature share
	sig, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: sig,
	}

	// Test with various proofs
	testCases := []struct {
		name  string
		proof []byte
	}{
		{"nil proof", nil},
		{"empty proof", []byte{}},
		{"random proof", make([]byte, 64)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.proof != nil && len(tc.proof) > 0 {
				rand.Read(tc.proof)
			}
			err := auth.AuthenticateSignatureShare(frost.Identifier(1), share, tc.proof)
			if err != nil {
				t.Errorf("NoOpAuthenticator should always succeed, got error: %v", err)
			}
		})
	}
}

// TestEd25519Authenticator_CommitmentSuccess tests successful commitment authentication.
func TestEd25519Authenticator_CommitmentSuccess(t *testing.T) {
	// Generate Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create authenticator
	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey,
	}
	auth := NewEd25519Authenticator(publicKeys)

	// Create test commitment
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Sign commitment
	signature, err := SignCommitment(frost.Identifier(1), commitment, privKey)
	if err != nil {
		t.Fatalf("Failed to sign commitment: %v", err)
	}

	// Authenticate should succeed
	err = auth.AuthenticateCommitment(frost.Identifier(1), commitment, signature)
	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
}

// TestEd25519Authenticator_CommitmentInvalidSignature tests rejection of invalid signatures.
func TestEd25519Authenticator_CommitmentInvalidSignature(t *testing.T) {
	// Generate Ed25519 keypair
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create authenticator
	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey,
	}
	auth := NewEd25519Authenticator(publicKeys)

	// Create test commitment
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Create invalid signature (random bytes)
	invalidSignature := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidSignature)

	// Authenticate should fail
	err = auth.AuthenticateCommitment(frost.Identifier(1), commitment, invalidSignature)
	if err == nil {
		t.Error("Expected authentication failure for invalid signature")
	}
	if err != nil && !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("Expected ErrAuthenticationFailed, got: %v", err)
	}
}

// TestEd25519Authenticator_CommitmentUnknownParticipant tests rejection of unknown participants.
func TestEd25519Authenticator_CommitmentUnknownParticipant(t *testing.T) {
	// Create empty authenticator (no registered participants)
	auth := NewEd25519Authenticator(make(map[frost.Identifier]ed25519.PublicKey))

	// Create test commitment
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(99),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Authenticate should fail (unknown participant)
	err := auth.AuthenticateCommitment(frost.Identifier(99), commitment, []byte{})
	if err == nil {
		t.Error("Expected authentication failure for unknown participant")
	}
}

// TestEd25519Authenticator_CommitmentWrongSigner tests rejection when signed by different participant.
func TestEd25519Authenticator_CommitmentWrongSigner(t *testing.T) {
	// Generate two keypairs
	pubKey1, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create authenticator with both public keys
	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey1,
		frost.Identifier(2): pubKey2,
	}
	auth := NewEd25519Authenticator(publicKeys)

	// Create commitment for participant 2
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(2),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Sign with participant 1's key (wrong signer!)
	signature, _ := SignCommitment(frost.Identifier(2), commitment, privKey1)

	// Authenticate should fail (signature from wrong participant)
	err := auth.AuthenticateCommitment(frost.Identifier(2), commitment, signature)
	if err == nil {
		t.Error("Expected authentication failure when signed by wrong participant")
	}
}

// TestEd25519Authenticator_SignatureShareSuccess tests successful signature share authentication.
func TestEd25519Authenticator_SignatureShareSuccess(t *testing.T) {
	// Generate Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create authenticator
	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey,
	}
	auth := NewEd25519Authenticator(publicKeys)

	// Create test signature share
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	sig, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: sig,
	}

	// Sign signature share
	signature, err := SignSignatureShare(frost.Identifier(1), share, privKey)
	if err != nil {
		t.Fatalf("Failed to sign signature share: %v", err)
	}

	// Authenticate should succeed
	err = auth.AuthenticateSignatureShare(frost.Identifier(1), share, signature)
	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
}

// TestEd25519Authenticator_SignatureShareInvalidSignature tests rejection of invalid signatures.
func TestEd25519Authenticator_SignatureShareInvalidSignature(t *testing.T) {
	// Generate Ed25519 keypair
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create authenticator
	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey,
	}
	auth := NewEd25519Authenticator(publicKeys)

	// Create test signature share
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	sig, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: sig,
	}

	// Create invalid signature
	invalidSignature := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidSignature)

	// Authenticate should fail
	err = auth.AuthenticateSignatureShare(frost.Identifier(1), share, invalidSignature)
	if err == nil {
		t.Error("Expected authentication failure for invalid signature")
	}
}

// TestEd25519Authenticator_SignatureShareUnknownParticipant tests rejection of unknown participants.
func TestEd25519Authenticator_SignatureShareUnknownParticipant(t *testing.T) {
	// Create empty authenticator
	auth := NewEd25519Authenticator(make(map[frost.Identifier]ed25519.PublicKey))

	// Create test signature share
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	sig, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(99),
		SignatureShare: sig,
	}

	// Authenticate should fail
	err := auth.AuthenticateSignatureShare(frost.Identifier(99), share, []byte{})
	if err == nil {
		t.Error("Expected authentication failure for unknown participant")
	}
}

// TestEd25519Authenticator_AddRemovePublicKey tests key management functions.
func TestEd25519Authenticator_AddRemovePublicKey(t *testing.T) {
	auth := NewEd25519Authenticator(make(map[frost.Identifier]ed25519.PublicKey))

	// Initially no participants
	if auth.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants, got %d", auth.ParticipantCount())
	}

	// Add participant
	pubKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	auth.AddPublicKey(frost.Identifier(1), pubKey1)

	if auth.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant, got %d", auth.ParticipantCount())
	}

	// Get public key
	retrieved := auth.GetPublicKey(frost.Identifier(1))
	if !ed25519PublicKeysEqual(retrieved, pubKey1) {
		t.Error("Retrieved public key doesn't match")
	}

	// Add another participant
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)
	auth.AddPublicKey(frost.Identifier(2), pubKey2)

	if auth.ParticipantCount() != 2 {
		t.Errorf("Expected 2 participants, got %d", auth.ParticipantCount())
	}

	// Remove participant
	auth.RemovePublicKey(frost.Identifier(1))

	if auth.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant after removal, got %d", auth.ParticipantCount())
	}

	// Get removed participant's key (should be nil)
	retrieved = auth.GetPublicKey(frost.Identifier(1))
	if retrieved != nil {
		t.Error("Expected nil for removed participant's public key")
	}
}

// TestEd25519Authenticator_UpdatePublicKey tests updating an existing participant's key.
func TestEd25519Authenticator_UpdatePublicKey(t *testing.T) {
	pubKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	auth := NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey1,
	})

	// Update with new key
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)
	auth.AddPublicKey(frost.Identifier(1), pubKey2)

	// Should still have 1 participant
	if auth.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant after update, got %d", auth.ParticipantCount())
	}

	// Retrieved key should be the new one
	retrieved := auth.GetPublicKey(frost.Identifier(1))
	if !ed25519PublicKeysEqual(retrieved, pubKey2) {
		t.Error("Retrieved key doesn't match updated key")
	}
}

// TestSignCommitment_InvalidPrivateKey tests error handling for invalid private keys.
func TestSignCommitment_InvalidPrivateKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Test with wrong size private key
	invalidKey := make([]byte, 16) // Too short
	_, err := SignCommitment(frost.Identifier(1), commitment, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid private key size")
	}
}

// TestSignSignatureShare_InvalidPrivateKey tests error handling for invalid private keys.
func TestSignSignatureShare_InvalidPrivateKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	sig, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: sig,
	}

	// Test with wrong size private key
	invalidKey := make([]byte, 32) // Wrong size
	_, err := SignSignatureShare(frost.Identifier(1), share, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid private key size")
	}
}

// TestEd25519Authenticator_MultipleParticipants tests authentication with multiple participants.
func TestEd25519Authenticator_MultipleParticipants(t *testing.T) {
	// Generate 3 keypairs
	pubKey1, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, privKey2, _ := ed25519.GenerateKey(rand.Reader)
	pubKey3, privKey3, _ := ed25519.GenerateKey(rand.Reader)

	publicKeys := map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey1,
		frost.Identifier(2): pubKey2,
		frost.Identifier(3): pubKey3,
	}
	auth := NewEd25519Authenticator(publicKeys)

	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create and authenticate commitments for each participant
	for i := 1; i <= 3; i++ {
		var privKey ed25519.PrivateKey
		switch i {
		case 1:
			privKey = privKey1
		case 2:
			privKey = privKey2
		case 3:
			privKey = privKey3
		}

		hiding, _ := grp.RandomScalar()
		binding, _ := grp.RandomScalar()
		commitment := frost.SigningCommitments{
			Identifier:             frost.Identifier(i),
			HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
			BindingNonceCommitment: grp.ScalarBaseMult(binding),
		}

		signature, _ := SignCommitment(frost.Identifier(i), commitment, privKey)
		err := auth.AuthenticateCommitment(frost.Identifier(i), commitment, signature)
		if err != nil {
			t.Errorf("Participant %d authentication failed: %v", i, err)
		}
	}
}

// TestEd25519Authenticator_MessageTampering tests detection of tampered messages.
func TestEd25519Authenticator_MessageTampering(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	auth := NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey,
	})

	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Sign original commitment
	signature, _ := SignCommitment(frost.Identifier(1), commitment, privKey)

	// Tamper with commitment (change hiding nonce)
	tamperedHiding, _ := grp.RandomScalar()
	tamperedCommitment := frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(tamperedHiding),
		BindingNonceCommitment: commitment.BindingNonceCommitment,
	}

	// Authentication should fail (message was tampered)
	err := auth.AuthenticateCommitment(frost.Identifier(1), tamperedCommitment, signature)
	if err == nil {
		t.Error("Expected authentication failure for tampered message")
	}
}

// Helper function to compare Ed25519 public keys
func ed25519PublicKeysEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
