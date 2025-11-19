// RFC 9591 Section 7.2: Participant Authentication (Authenticated Channels)
//
// This file tests the participant authentication mechanisms required by RFC 9591 Section 7.2.
// It verifies that:
// 1. Commitments can be authenticated with Ed25519 signatures
// 2. Signature shares can be authenticated with Ed25519 signatures
// 3. Invalid authentication proofs are rejected
// 4. Missing authenticator is handled correctly
//
// RFC 9591 Section 7.2 Requirements:
// - "Implementations MUST ensure that participants in the protocol are authenticated"
// - "This prevents impersonation attacks where an attacker could inject malicious messages"
// - "Authentication can be achieved using digital signatures, MACs, or TLS with client authentication"
//
// Test Coverage:
// - H-1: Participant Authentication (RFC 9591 Section 7.2)
// - Authentication of commitments
// - Authentication of signature shares
// - Integration with reputation tracking
// - Error handling for authentication failures
package rfc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/security"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestSection7_2_AuthenticatedCommitments verifies that commitments can be authenticated
// using Ed25519 signatures as required by RFC 9591 Section 7.2.
func TestSection7_2_AuthenticatedCommitments(t *testing.T) {
	// Setup ciphersuite
	suite := ristretto255_sha512.New()

	// Generate signing keys for participants using dealer
	const numParticipants = 3
	const threshold = 2

	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := dealer.GenerateShares(nil, threshold, numParticipants, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Generate Ed25519 keys for authentication
	authPublicKeys := make(map[frost.Identifier]ed25519.PublicKey)
	authPrivateKeys := make(map[frost.Identifier]ed25519.PrivateKey)

	for i := 0; i < numParticipants; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}
		id := frost.Identifier(i + 1)
		authPublicKeys[id] = pubKey
		authPrivateKeys[id] = privKey
	}

	// Create authenticator
	authenticator := security.NewEd25519Authenticator(authPublicKeys)

	// Create signing participants
	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate a commitment from participant 1
	_, commitment, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	// Sign the commitment with participant 1's Ed25519 key
	proof, err := security.SignCommitment(1, commitment, authPrivateKeys[1])
	if err != nil {
		t.Fatalf("Failed to sign commitment: %v", err)
	}

	// Test: Valid authentication should succeed
	err = authenticator.AuthenticateCommitment(1, commitment, proof)
	if err != nil {
		t.Errorf("Valid commitment authentication failed: %v", err)
	}

	// Test: Invalid proof should fail
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	err = authenticator.AuthenticateCommitment(1, commitment, invalidProof)
	if err == nil {
		t.Error("Invalid commitment proof was accepted")
	}

	// Test: Wrong participant ID should fail (sign with participant 2's key)
	participant2 := signing.NewParticipant(keyPackages[1], suite)
	_, commitment2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	proof2, err := security.SignCommitment(2, commitment2, authPrivateKeys[2])
	if err != nil {
		t.Fatalf("Failed to sign commitment: %v", err)
	}

	// Try to authenticate participant 2's commitment with participant 1's ID (should fail)
	err = authenticator.AuthenticateCommitment(1, commitment2, proof2)
	if err == nil {
		t.Error("Commitment authenticated with wrong participant ID")
	}
}

// TestSection7_2_AuthenticatedSignatureShares verifies that signature shares
// can be authenticated using Ed25519 signatures as required by RFC 9591 Section 7.2.
func TestSection7_2_AuthenticatedSignatureShares(t *testing.T) {
	// Setup ciphersuite
	suite := ristretto255_sha512.New()

	// Generate signing keys for participants using dealer
	const numParticipants = 3
	const threshold = 2

	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := dealer.GenerateShares(nil, threshold, numParticipants, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Generate Ed25519 keys for authentication
	authPublicKeys := make(map[frost.Identifier]ed25519.PublicKey)
	authPrivateKeys := make(map[frost.Identifier]ed25519.PrivateKey)

	for i := 0; i < numParticipants; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}
		id := frost.Identifier(i + 1)
		authPublicKeys[id] = pubKey
		authPrivateKeys[id] = privKey
	}

	// Create authenticator
	authenticator := security.NewEd25519Authenticator(authPublicKeys)

	// Create signing participants
	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	// Generate commitments and signature share
	msg := []byte("test message for authentication")

	nonces1, commitment1, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	_, commitment2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	commitmentList := frost.CommitmentList{commitment1, commitment2}

	// Generate signature share
	share, err := participant1.RoundTwo(nonces1, msg, commitmentList)
	if err != nil {
		t.Fatalf("Failed to generate signature share: %v", err)
	}

	// Sign the signature share with participant 1's Ed25519 key
	proof, err := security.SignSignatureShare(1, share, authPrivateKeys[1])
	if err != nil {
		t.Fatalf("Failed to sign signature share: %v", err)
	}

	// Test: Valid authentication should succeed
	err = authenticator.AuthenticateSignatureShare(1, share, proof)
	if err != nil {
		t.Errorf("Valid signature share authentication failed: %v", err)
	}

	// Test: Invalid proof should fail
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	err = authenticator.AuthenticateSignatureShare(1, share, invalidProof)
	if err == nil {
		t.Error("Invalid signature share proof was accepted")
	}

	// Test: Wrong participant ID should fail
	err = authenticator.AuthenticateSignatureShare(2, share, proof)
	if err == nil {
		t.Error("Signature share authenticated with wrong participant ID")
	}
}

// TestSection7_2_Ed25519AuthenticatorLifecycle verifies the Ed25519Authenticator
// lifecycle operations for managing participant keys.
func TestSection7_2_Ed25519AuthenticatorLifecycle(t *testing.T) {
	// Create empty authenticator
	authenticator := security.NewEd25519Authenticator(make(map[frost.Identifier]ed25519.PublicKey))

	if authenticator.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants, got %d", authenticator.ParticipantCount())
	}

	// Add participants
	pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	authenticator.AddPublicKey(1, pubKey1)

	if authenticator.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant, got %d", authenticator.ParticipantCount())
	}

	// Verify key retrieval
	retrievedKey := authenticator.GetPublicKey(1)
	if retrievedKey == nil {
		t.Error("Failed to retrieve public key")
	}

	if !retrievedKey.Equal(pubKey1) {
		t.Error("Retrieved key does not match original")
	}

	// Remove participant
	authenticator.RemovePublicKey(1)

	if authenticator.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after removal, got %d", authenticator.ParticipantCount())
	}

	retrievedKey = authenticator.GetPublicKey(1)
	if retrievedKey != nil {
		t.Error("Key should be nil after removal")
	}

	// Verify authentication fails after removal
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, []frost.Identifier{1, 2})
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant := signing.NewParticipant(keyPackages[0], suite)
	_, commitment, err := participant.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	proof, err := security.SignCommitment(1, commitment, privKey1)
	if err != nil {
		t.Fatalf("Failed to sign commitment: %v", err)
	}

	err = authenticator.AuthenticateCommitment(1, commitment, proof)
	if err == nil {
		t.Error("Authentication succeeded for removed participant")
	}
}

// TestSection7_2_NoOpAuthenticator verifies the NoOpAuthenticator behavior.
func TestSection7_2_NoOpAuthenticator(t *testing.T) {
	// Create NoOp authenticator
	authenticator := security.NewNoOpAuthenticator()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, []frost.Identifier{1, 2})
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitment
	nonces, commitment, err := participant.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	// Test: NoOp authenticator should accept anything for commitments
	err = authenticator.AuthenticateCommitment(1, commitment, nil)
	if err != nil {
		t.Errorf("NoOp authenticator rejected commitment: %v", err)
	}

	err = authenticator.AuthenticateCommitment(1, commitment, []byte("invalid proof"))
	if err != nil {
		t.Errorf("NoOp authenticator rejected commitment with invalid proof: %v", err)
	}

	// Generate signature share
	_, commitment2, err := signing.NewParticipant(keyPackages[1], suite).RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitment: %v", err)
	}

	commitmentList := frost.CommitmentList{commitment, commitment2}
	msg := []byte("test message")

	share, err := participant.RoundTwo(nonces, msg, commitmentList)
	if err != nil {
		t.Fatalf("Failed to generate signature share: %v", err)
	}

	// Test: NoOp authenticator should accept anything for signature shares
	err = authenticator.AuthenticateSignatureShare(1, share, nil)
	if err != nil {
		t.Errorf("NoOp authenticator rejected signature share: %v", err)
	}

	err = authenticator.AuthenticateSignatureShare(1, share, []byte("invalid proof"))
	if err != nil {
		t.Errorf("NoOp authenticator rejected signature share with invalid proof: %v", err)
	}
}
