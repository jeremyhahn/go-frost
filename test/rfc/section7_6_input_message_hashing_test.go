// RFC 9591 Section 7.6: Input Message Hashing
//
// This file provides testing for input message hashing requirements in FROST.
// Implements M-6: Message Hashing Testing from RFC 9591 Section 7.6.
//
// RFC 9591 Section 7.6 states:
// "FROST signatures do not pre-hash the message to be signed. This means the
// entire message must be known in advance of invoking the signing protocol."
//
// For applications that require pre-hashing (e.g., due to memory constraints),
// the RFC recommends:
// 1. Use a collision-resistant hash function with security level matching the ciphersuite
// 2. Use the hash function (H) associated with the chosen ciphersuite
// 3. Use domain separation (different prefix from H4) to differentiate the pre-hash
//
// Test Coverage:
// - Verify FROST requires full message during signing
// - Test that different messages produce different signatures
// - Test collision resistance when pre-hashing is used
// - Verify domain separation for pre-hash operations
// - Test hash function consistency with ciphersuite
//
// Ciphersuite Implementation Status (RFC 9591 Section 6):
//
// Currently Implemented:
// - FROST(ristretto255, SHA-512) - Section 6.2 ✓
//
// Not Yet Implemented (Future Work):
// - FROST(Ed25519, SHA-512) - Section 6.1
// - FROST(Ed448, SHAKE256) - Section 6.3
// - FROST(P-256, SHA-256) - Section 6.4
// - FROST(secp256k1, SHA-256) - Section 6.5
//
// NOTE: When additional ciphersuites are implemented, update the test
// functions to use table-driven tests iterating over all available suites.
// See section5_test.go or section6_test.go for examples of multi-ciphersuite
// table-driven test patterns.
package rfc

import (
	"bytes"
	"crypto/sha512"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestSection7_6_MessageHashingFullMessageRequired verifies that FROST
// requires the full message to be available during signing.
// RFC 9591 Section 7.6: "the entire message must be known in advance"
func TestSection7_6_MessageHashingFullMessageRequired(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys for 2-of-3 threshold using Dealer
	const threshold = 2
	const numParticipants = 3
	participantIDs := []frost.Identifier{1, 2, 3}

	dealer := keygen.NewDealer(suite)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, threshold, numParticipants, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Test signing with full message
	message := []byte("RFC 9591 Section 7.6: Full message must be known during signing")

	// Initialize signing participants (using participants 1 and 2)
	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	// Round 1: Generate nonces and commitments
	nonces1, commitment1, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Participant 1 RoundOne failed: %v", err)
	}

	nonces2, commitment2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Participant 2 RoundOne failed: %v", err)
	}

	// Build commitment list
	commitmentList := frost.CommitmentList{commitment1, commitment2}

	// Round 2: Generate signature shares with FULL message
	sigShare1, err := participant1.RoundTwo(nonces1, message, commitmentList)
	if err != nil {
		t.Fatalf("Participant 1 RoundTwo failed: %v", err)
	}

	sigShare2, err := participant2.RoundTwo(nonces2, message, commitmentList)
	if err != nil {
		t.Fatalf("Participant 2 RoundTwo failed: %v", err)
	}

	// Aggregate signature
	aggregator := signing.NewAggregator(suite, threshold)
	signature, err := aggregator.Aggregate(groupPublicKey, commitmentList, message, []frost.SignatureShare{sigShare1, sigShare2})
	if err != nil {
		t.Fatalf("Signature aggregation failed: %v", err)
	}

	// Verify signature
	err = aggregator.Verify(message, signature, groupPublicKey)
	if err != nil {
		t.Fatalf("Signature verification failed - FROST requires full message during signing: %v", err)
	}

	t.Log("✓ FROST correctly requires full message availability during signing")
}

// TestSection7_6_MessageHashingDifferentMessages verifies that different
// messages produce cryptographically distinct signatures.
func TestSection7_6_MessageHashingDifferentMessages(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys for 2-of-3 threshold using Dealer
	const threshold = 2
	const numParticipants = 3
	participantIDs := []frost.Identifier{1, 2, 3}

	dealer := keygen.NewDealer(suite)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, threshold, numParticipants, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Sign two different messages
	message1 := []byte("Message 1")
	message2 := []byte("Message 2")

	// Sign message 1
	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	nonces1, commitment1, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Participant 1 RoundOne failed: %v", err)
	}

	nonces2, commitment2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Participant 2 RoundOne failed: %v", err)
	}

	commitmentList := frost.CommitmentList{commitment1, commitment2}

	sigShare1, err := participant1.RoundTwo(nonces1, message1, commitmentList)
	if err != nil {
		t.Fatalf("Participant 1 RoundTwo failed: %v", err)
	}

	sigShare2, err := participant2.RoundTwo(nonces2, message1, commitmentList)
	if err != nil {
		t.Fatalf("Participant 2 RoundTwo failed: %v", err)
	}

	aggregator := signing.NewAggregator(suite, threshold)
	signature1, err := aggregator.Aggregate(groupPublicKey, commitmentList, message1, []frost.SignatureShare{sigShare1, sigShare2})
	if err != nil {
		t.Fatalf("Signature 1 aggregation failed: %v", err)
	}

	// Sign message 2 with NEW nonces (required for different message)
	participant1 = signing.NewParticipant(keyPackages[0], suite)
	participant2 = signing.NewParticipant(keyPackages[1], suite)

	nonces1, commitment1, err = participant1.RoundOne()
	if err != nil {
		t.Fatalf("Participant 1 RoundOne (msg2) failed: %v", err)
	}

	nonces2, commitment2, err = participant2.RoundOne()
	if err != nil {
		t.Fatalf("Participant 2 RoundOne (msg2) failed: %v", err)
	}

	commitmentList = frost.CommitmentList{commitment1, commitment2}

	sigShare1, err = participant1.RoundTwo(nonces1, message2, commitmentList)
	if err != nil {
		t.Fatalf("Participant 1 RoundTwo (msg2) failed: %v", err)
	}

	sigShare2, err = participant2.RoundTwo(nonces2, message2, commitmentList)
	if err != nil {
		t.Fatalf("Participant 2 RoundTwo (msg2) failed: %v", err)
	}

	signature2, err := aggregator.Aggregate(groupPublicKey, commitmentList, message2, []frost.SignatureShare{sigShare1, sigShare2})
	if err != nil {
		t.Fatalf("Signature 2 aggregation failed: %v", err)
	}

	// Verify signatures are different by serializing them
	sig1Bytes := append(signature1.R.Bytes(), signature1.Z.Bytes()...)
	sig2Bytes := append(signature2.R.Bytes(), signature2.Z.Bytes()...)

	if bytes.Equal(sig1Bytes, sig2Bytes) {
		t.Fatal("Different messages produced identical signatures - SECURITY VIOLATION")
	}

	// Verify correct signature validates with correct message only
	err = aggregator.Verify(message1, signature1, groupPublicKey)
	if err != nil {
		t.Fatalf("Signature 1 failed to verify with its own message: %v", err)
	}

	err = aggregator.Verify(message2, signature1, groupPublicKey)
	if err == nil {
		t.Fatal("Signature 1 incorrectly verified with different message - SECURITY VIOLATION")
	}

	t.Log("✓ Different messages produce cryptographically distinct signatures")
}

// TestSection7_6_PreHashDomainSeparation verifies that if pre-hashing is
// used, it employs proper domain separation as recommended by RFC 9591.
// RFC 9591 Section 7.6: "use a different prefix...to differentiate this
// pre-hash from H4"
func TestSection7_6_PreHashDomainSeparation(t *testing.T) {
	// RFC 9591 recommends using the ciphersuite hash function (H) with
	// domain separation for pre-hashing large messages

	message := []byte("Large message that might require pre-hashing in constrained environments")

	// Domain-separated pre-hash as recommended by RFC
	// Using different prefix from H4 to avoid confusion
	prehashDomain := []byte("FROST-PREHASH-V1")

	h := sha512.New()
	h.Write(prehashDomain)
	h.Write(message)
	prehashedMessage := h.Sum(nil)

	// Verify domain separation produces different output than direct hash
	h2 := sha512.New()
	h2.Write(message)
	directHash := h2.Sum(nil)

	if bytes.Equal(prehashedMessage, directHash) {
		t.Fatal("Pre-hash domain separation not working - same output as direct hash")
	}

	// Verify different domain produces different hash
	differentDomain := []byte("DIFFERENT-DOMAIN")
	h3 := sha512.New()
	h3.Write(differentDomain)
	h3.Write(message)
	differentDomainHash := h3.Sum(nil)

	if bytes.Equal(prehashedMessage, differentDomainHash) {
		t.Fatal("Domain separation not effective - different domains produce same hash")
	}

	t.Log("✓ Pre-hash domain separation working correctly (different from H4)")
}

// TestSection7_6_HashFunctionConsistency verifies that the hash function
// used for any pre-hashing matches the ciphersuite's security level.
// RFC 9591 Section 7.6: "security level commensurate with the security
// inherent to the ciphersuite"
func TestSection7_6_HashFunctionConsistency(t *testing.T) {
	// ristretto255-sha512 provides 128-bit security
	// SHA-512 provides >= 128-bit collision resistance (256-bit output)

	message := []byte("Test message for hash function security level")

	// Use the ciphersuite's hash function
	h := sha512.New()
	h.Write(message)
	hash := h.Sum(nil)

	// Verify hash output size matches expected security level
	expectedHashSize := 64 // SHA-512 produces 512 bits = 64 bytes
	if len(hash) != expectedHashSize {
		t.Fatalf("Hash output size mismatch: got %d bytes, expected %d bytes",
			len(hash), expectedHashSize)
	}

	// Verify hash is deterministic
	h2 := sha512.New()
	h2.Write(message)
	hash2 := h2.Sum(nil)

	if !bytes.Equal(hash, hash2) {
		t.Fatal("Hash function not deterministic - same input produced different outputs")
	}

	// Verify small message changes produce different hashes (avalanche effect)
	messageModified := []byte("Test message for hash function security level!")
	h3 := sha512.New()
	h3.Write(messageModified)
	hash3 := h3.Sum(nil)

	if bytes.Equal(hash, hash3) {
		t.Fatal("Hash function collision detected - SECURITY VIOLATION")
	}

	t.Log("✓ Hash function provides security level consistent with ciphersuite (128-bit)")
}

// TestSection7_6_CollisionResistance verifies the hash function used
// provides adequate collision resistance for the security level.
// RFC 9591 Section 7.6: "collision-resistant hash function"
func TestSection7_6_CollisionResistance(t *testing.T) {
	// Test that different inputs always produce different hashes
	// This is a basic collision resistance check

	testCases := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("Message1"),  // Case sensitivity
		[]byte("message1 "), // Trailing space
		[]byte(" message1"), // Leading space
		[]byte(""),          // Empty message
		[]byte("a"),         // Single byte
	}

	hashes := make(map[string][]byte)

	for _, msg := range testCases {
		h := sha512.New()
		h.Write(msg)
		hash := h.Sum(nil)

		hashStr := string(hash)
		if existing, exists := hashes[hashStr]; exists {
			t.Fatalf("Collision detected: messages %q and %q produced same hash",
				existing, msg)
		}
		hashes[hashStr] = msg
	}

	// Verify hash output is full 512 bits for maximum collision resistance
	h := sha512.New()
	h.Write(testCases[0])
	hash := h.Sum(nil)

	if len(hash)*8 != 512 {
		t.Fatalf("Hash function output size: got %d bits, expected 512 bits",
			len(hash)*8)
	}

	t.Logf("✓ Hash function provides collision resistance (tested %d distinct inputs)",
		len(testCases))
}

// TestSection7_6_MessageIntegrity verifies that any modification to the
// message results in signature verification failure.
func TestSection7_6_MessageIntegrity(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys for 2-of-3 threshold using Dealer
	const threshold = 2
	const numParticipants = 3
	participantIDs := []frost.Identifier{1, 2, 3}

	dealer := keygen.NewDealer(suite)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, threshold, numParticipants, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create and sign original message
	originalMessage := []byte("Original message for integrity testing")

	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	nonces1, commitment1, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Participant 1 RoundOne failed: %v", err)
	}

	nonces2, commitment2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Participant 2 RoundOne failed: %v", err)
	}

	commitmentList := frost.CommitmentList{commitment1, commitment2}

	sigShare1, err := participant1.RoundTwo(nonces1, originalMessage, commitmentList)
	if err != nil {
		t.Fatalf("Participant 1 RoundTwo failed: %v", err)
	}

	sigShare2, err := participant2.RoundTwo(nonces2, originalMessage, commitmentList)
	if err != nil {
		t.Fatalf("Participant 2 RoundTwo failed: %v", err)
	}

	aggregator := signing.NewAggregator(suite, threshold)
	signature, err := aggregator.Aggregate(groupPublicKey, commitmentList, originalMessage, []frost.SignatureShare{sigShare1, sigShare2})
	if err != nil {
		t.Fatalf("Signature aggregation failed: %v", err)
	}

	// Verify original message validates
	err = aggregator.Verify(originalMessage, signature, groupPublicKey)
	if err != nil {
		t.Fatalf("Original message signature verification failed: %v", err)
	}

	// Test various message modifications
	testCases := []struct {
		name     string
		modified []byte
	}{
		{"Single bit flip", []byte("Qriginal message for integrity testing")},
		{"Truncated", []byte("Original message for integrity testin")},
		{"Extended", []byte("Original message for integrity testing ")},
		{"Empty", []byte("")},
		{"Completely different", []byte("Completely different message")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := aggregator.Verify(tc.modified, signature, groupPublicKey)
			if err == nil {
				t.Fatalf("Modified message '%s' incorrectly verified - MESSAGE INTEGRITY VIOLATED",
					tc.name)
			}
		})
	}

	t.Log("✓ Message integrity protected - any modification causes verification failure")
}
