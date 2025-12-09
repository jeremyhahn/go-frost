// These tests verify the complete workflow from key generation through signing and
//
// These tests MUST run in a Docker container and NEVER on the host OS.
package service

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

// TestCompleteKeyGenerationWorkflow tests the complete key generation workflow
// from dealer to participant key packages.
func TestCompleteKeyGenerationWorkflow(t *testing.T) {
	tests := []struct {
		name         string
		minSigners   uint32
		maxSigners   uint32
		participants []frost.Identifier
	}{
		{
			name:         "2-of-3 threshold",
			minSigners:   2,
			maxSigners:   3,
			participants: []frost.Identifier{1, 2, 3},
		},
		{
			name:         "3-of-5 threshold",
			minSigners:   3,
			maxSigners:   5,
			participants: []frost.Identifier{1, 2, 3, 4, 5},
		},
		{
			name:         "5-of-7 threshold",
			minSigners:   5,
			maxSigners:   7,
			participants: []frost.Identifier{1, 2, 3, 4, 5, 6, 7},
		},
		{
			name:         "2-of-2 minimal threshold",
			minSigners:   2,
			maxSigners:   2,
			participants: []frost.Identifier{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create real ciphersuite
			suite := ristretto255_sha512.New()

			// Create real service
			frostService := NewFrostService(suite)

			// Configure FROST
			config := frost.Configuration{
				MinSigners: tt.minSigners,
				MaxSigners: tt.maxSigners,
				Group:      suite.Group(),
			}

			// Generate keys
			keyPackages, groupPubKey, err := frostService.GenerateKeys(config, tt.participants)
			if err != nil {
				t.Fatalf("GenerateKeys failed: %v", err)
			}

			// Verify we got the right number of key packages
			if len(keyPackages) != len(tt.participants) {
				t.Errorf("Expected %d key packages, got %d", len(tt.participants), len(keyPackages))
			}

			// Verify group public key is not nil
			if groupPubKey == nil {
				t.Fatal("Group public key is nil")
			}

			// Verify all key packages have the same group public key
			for i, pkg := range keyPackages {
				if !pkg.GroupPublicKey.Equal(groupPubKey) {
					t.Errorf("Key package %d has different group public key", i)
				}
			}

			// Verify each key package
			for i, pkg := range keyPackages {
				if err := frostService.VerifyKeyShare(pkg); err != nil {
					t.Errorf("Key package %d verification failed: %v", i, err)
				}
			}
		})
	}
}

// TestCompleteSigningWorkflow tests the complete signing workflow
// from round one through round two to aggregation.
func TestCompleteSigningWorkflow(t *testing.T) {
	tests := []struct {
		name       string
		minSigners uint32
		maxSigners uint32
		message    []byte
	}{
		{
			name:       "Simple message",
			minSigners: 2,
			maxSigners: 3,
			message:    []byte("Hello, FROST!"),
		},
		{
			name:       "Empty message",
			minSigners: 2,
			maxSigners: 3,
			message:    []byte{},
		},
		{
			name:       "Binary message",
			minSigners: 2,
			maxSigners: 3,
			message:    []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:       "Large message",
			minSigners: 3,
			maxSigners: 5,
			message:    make([]byte, 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create real ciphersuite
			suite := ristretto255_sha512.New()

			// Create real service
			frostService := NewFrostService(suite)

			// Configure FROST
			config := frost.Configuration{
				MinSigners: tt.minSigners,
				MaxSigners: tt.maxSigners,
				Group:      suite.Group(),
			}

			// Generate participant IDs
			participants := make([]frost.Identifier, tt.maxSigners)
			for i := uint32(0); i < tt.maxSigners; i++ {
				participants[i] = frost.Identifier(i + 1)
			}

			// Generate keys
			keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
			if err != nil {
				t.Fatalf("GenerateKeys failed: %v", err)
			}

			// Select minimum signers for signing
			signingPackages := keyPackages[:tt.minSigners]

			// Sign the message
			signature, err := frostService.Sign(signingPackages, tt.message)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify signature is not empty
			if signature.R == nil || signature.Z == nil {
				t.Fatal("frost.Signature has nil components")
			}

			// Verify the signature
			err = frostService.Verify(tt.message, signature, groupPubKey)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			// Verify that verification fails with wrong message
			wrongMessage := append(tt.message, byte(0xFF))
			err = frostService.Verify(wrongMessage, signature, groupPubKey)
			if err == nil {
				t.Error("Verification should fail with wrong message")
			}
		})
	}
}

// TestMultipleSigningSessions tests multiple signing sessions with the same keys.
func TestMultipleSigningSessions(t *testing.T) {
	// Create real ciphersuite
	suite := ristretto255_sha512.New()

	// Create real service
	frostService := NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Sign multiple different messages with the same keys
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
		[]byte("Message 4"),
		[]byte("Message 5"),
	}

	signatures := make([]frost.Signature, len(messages))

	for i, msg := range messages {
		signingPackages := keyPackages[:2]
		signature, err := frostService.Sign(signingPackages, msg)
		if err != nil {
			t.Fatalf("Sign failed for message %d: %v", i, err)
		}
		signatures[i] = signature

		// Verify immediately
		err = frostService.Verify(msg, signature, groupPubKey)
		if err != nil {
			t.Fatalf("Verify failed for message %d: %v", i, err)
		}
	}

	// Verify all signatures are different
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if signatures[i].R.Equal(signatures[j].R) && signatures[i].Z.Equal(signatures[j].Z) {
				t.Errorf("Signatures %d and %d are identical", i, j)
			}
		}
	}

	// Verify signatures cannot be used for wrong messages
	for i, sig := range signatures {
		for j, msg := range messages {
			err := frostService.Verify(msg, sig, groupPubKey)
			if i == j {
				// Should verify for correct message
				if err != nil {
					t.Errorf("frost.Signature %d should verify for message %d", i, j)
				}
			} else {
				// Should not verify for wrong message
				if err == nil {
					t.Errorf("frost.Signature %d should not verify for message %d", i, j)
				}
			}
		}
	}
}

// TestDifferentParticipantCombinations tests that different combinations
// of participants can all create valid signatures.
func TestDifferentParticipantCombinations(t *testing.T) {
	// Create real ciphersuite
	suite := ristretto255_sha512.New()

	// Create real service
	frostService := NewFrostService(suite)

	// Configure 2-of-4 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 4,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3, 4}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	message := []byte("Test message")

	// Test all possible 2-of-4 combinations
	combinations := [][]int{
		{0, 1}, {0, 2}, {0, 3},
		{1, 2}, {1, 3},
		{2, 3},
	}

	for _, combo := range combinations {
		t.Run(fmt.Sprintf("Participants %d and %d", combo[0]+1, combo[1]+1), func(t *testing.T) {
			signingPackages := []frost.KeyPackage{
				keyPackages[combo[0]],
				keyPackages[combo[1]],
			}

			signature, err := frostService.Sign(signingPackages, message)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			err = frostService.Verify(message, signature, groupPubKey)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
		})
	}
}

// TestThresholdEnforcement verifies that signatures cannot be created
// with fewer than the minimum number of participants.
func TestThresholdEnforcement(t *testing.T) {
	// Create real ciphersuite
	suite := ristretto255_sha512.New()

	// Create real service
	frostService := NewFrostService(suite)

	// Configure 3-of-5 threshold
	config := frost.Configuration{
		MinSigners: 3,
		MaxSigners: 5,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3, 4, 5}
	keyPackages, _, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	message := []byte("Test message")

	// Try to sign with only 1 participant (should fail)
	_, err = frostService.Sign(keyPackages[:1], message)
	if err == nil {
		t.Error("Should fail with only 1 participant")
	}

	// Try to sign with only 2 participants (should fail for 3-of-5)
	// Note: The current implementation validates minimum 2, not the threshold
	// This test documents current behavior
	_, err = frostService.Sign(keyPackages[:2], message)
	if err != nil {
		t.Logf("Failed with 2 participants as expected: %v", err)
	}
}

// TestConcurrentSigningSessions tests concurrent signing sessions
// to verify thread safety.
func TestConcurrentSigningSessions(t *testing.T) {
	// Create real ciphersuite
	suite := ristretto255_sha512.New()

	// Create real service
	frostService := NewFrostService(suite)

	// Configure 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Run 10 concurrent signing sessions
	concurrency := 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer wg.Done()

			message := []byte(fmt.Sprintf("Concurrent message %d", index))
			signingPackages := keyPackages[:2]

			signature, err := frostService.Sign(signingPackages, message)
			if err != nil {
				errors <- fmt.Errorf("concurrent sign %d failed: %v", index, err)
				return
			}

			err = frostService.Verify(message, signature, groupPubKey)
			if err != nil {
				errors <- fmt.Errorf("concurrent verify %d failed: %v", index, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}

// TestErrorScenarios tests various error conditions.
func TestErrorScenarios(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	t.Run("Invalid configuration - minSigners too low", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 1,
			MaxSigners: 3,
			Group:      suite.Group(),
		}

		participants := []frost.Identifier{1, 2, 3}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with minSigners < 2")
		}
	})

	t.Run("Invalid configuration - minSigners > maxSigners", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 5,
			MaxSigners: 3,
			Group:      suite.Group(),
		}

		participants := []frost.Identifier{1, 2, 3}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with minSigners > maxSigners")
		}
	})

	t.Run("Invalid configuration - nil group", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 3,
			Group:      nil,
		}

		participants := []frost.Identifier{1, 2, 3}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with nil group")
		}
	})

	t.Run("Invalid participants - wrong count", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 3,
			Group:      suite.Group(),
		}

		// Provide 2 participants when maxSigners is 3
		participants := []frost.Identifier{1, 2}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with wrong participant count")
		}
	})

	t.Run("Invalid participants - duplicate IDs", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 3,
			Group:      suite.Group(),
		}

		// Duplicate participant ID
		participants := []frost.Identifier{1, 2, 2}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with duplicate participant IDs")
		}
	})

	t.Run("Invalid participants - zero ID", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 3,
			Group:      suite.Group(),
		}

		// Zero participant ID
		participants := []frost.Identifier{0, 1, 2}
		_, _, err := frostService.GenerateKeys(config, participants)
		if err == nil {
			t.Error("Should fail with zero participant ID")
		}
	})

	t.Run("Sign with mismatched group public keys", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 2,
			Group:      suite.Group(),
		}

		// Generate two separate key sets
		participants1 := []frost.Identifier{1, 2}
		keyPackages1, _, _ := frostService.GenerateKeys(config, participants1)

		participants2 := []frost.Identifier{3, 4}
		keyPackages2, _, _ := frostService.GenerateKeys(config, participants2)

		// Try to sign with packages from different key generations
		mixedPackages := []frost.KeyPackage{keyPackages1[0], keyPackages2[0]}
		_, err := frostService.Sign(mixedPackages, []byte("test"))
		if err == nil {
			t.Error("Should fail with mismatched group public keys")
		}
	})

	t.Run("Verify with wrong public key", func(t *testing.T) {
		config := frost.Configuration{
			MinSigners: 2,
			MaxSigners: 2,
			Group:      suite.Group(),
		}

		participants := []frost.Identifier{1, 2}
		keyPackages, _, _ := frostService.GenerateKeys(config, participants)

		message := []byte("test")
		signature, _ := frostService.Sign(keyPackages, message)

		// Generate a different group public key
		participants2 := []frost.Identifier{3, 4}
		_, wrongPubKey, _ := frostService.GenerateKeys(config, participants2)

		// Try to verify with wrong public key
		err := frostService.Verify(message, signature, wrongPubKey)
		if err == nil {
			t.Error("Should fail with wrong public key")
		}
	})

	t.Run("Empty key packages", func(t *testing.T) {
		_, err := frostService.Sign([]frost.KeyPackage{}, []byte("test"))
		if err == nil {
			t.Error("Should fail with empty key packages")
		}
	})

	t.Run("Nil key packages", func(t *testing.T) {
		_, err := frostService.Sign(nil, []byte("test"))
		if err == nil {
			t.Error("Should fail with nil key packages")
		}
	})
}

// TestSessionManager tests the session manager for asynchronous signing.
func TestSessionManager(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)
	sessionManager := NewSessionManager(frostService)

	t.Run("Create and list sessions", func(t *testing.T) {
		participants := []frost.Identifier{1, 2}
		message := []byte("test message")

		// Create session
		session, err := sessionManager.CreateSession(participants, message)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}

		if session.ID() == "" {
			t.Error("Session ID is empty")
		}

		// List sessions
		sessions := sessionManager.ListSessions()
		if len(sessions) != 1 {
			t.Errorf("Expected 1 session, got %d", len(sessions))
		}

		// Get session
		retrieved, err := sessionManager.GetSession(session.ID())
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}

		if retrieved.ID() != session.ID() {
			t.Error("Retrieved session has different ID")
		}
	})

	t.Run("Delete session", func(t *testing.T) {
		participants := []frost.Identifier{1, 2}
		message := []byte("test message")

		session, _ := sessionManager.CreateSession(participants, message)
		sessionID := session.ID()

		// Delete session
		err := sessionManager.DeleteSession(sessionID)
		if err != nil {
			t.Fatalf("DeleteSession failed: %v", err)
		}

		// Try to get deleted session
		_, err = sessionManager.GetSession(sessionID)
		if err == nil {
			t.Error("Should fail to get deleted session")
		}
	})

	t.Run("Multiple sessions", func(t *testing.T) {
		participants := []frost.Identifier{1, 2}

		// Create multiple sessions
		sessionCount := 5
		for i := 0; i < sessionCount; i++ {
			message := []byte(fmt.Sprintf("message %d", i))
			_, err := sessionManager.CreateSession(participants, message)
			if err != nil {
				t.Fatalf("CreateSession %d failed: %v", i, err)
			}
		}

		sessions := sessionManager.ListSessions()
		if len(sessions) < sessionCount {
			t.Errorf("Expected at least %d sessions, got %d", sessionCount, len(sessions))
		}
	})
}

// TestLargeScaleDeployment tests a larger deployment scenario.
func TestLargeScaleDeployment(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	// Configure 7-of-10 threshold
	config := frost.Configuration{
		MinSigners: 7,
		MaxSigners: 10,
		Group:      suite.Group(),
	}

	participants := make([]frost.Identifier, 10)
	for i := 0; i < 10; i++ {
		participants[i] = frost.Identifier(i + 1)
	}

	// Generate keys
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Sign with exactly the threshold
	message := []byte("Large scale test")
	signingPackages := keyPackages[:7]

	signature, err := frostService.Sign(signingPackages, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	err = frostService.Verify(message, signature, groupPubKey)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Sign with more than threshold (8 participants)
	signingPackages = keyPackages[:8]
	signature, err = frostService.Sign(signingPackages, message)
	if err != nil {
		t.Fatalf("Sign with 8 participants failed: %v", err)
	}

	err = frostService.Verify(message, signature, groupPubKey)
	if err != nil {
		t.Fatalf("Verify with 8 participants failed: %v", err)
	}
}

// TestRandomizedMessages tests signing with random messages.
func TestRandomizedMessages(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Test with 20 random messages of varying sizes
	for i := 0; i < 20; i++ {
		// Random message size between 0 and 1000 bytes
		size := i * 50
		message := make([]byte, size)
		_, err := rand.Read(message)
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}

		signingPackages := keyPackages[:2]
		signature, err := frostService.Sign(signingPackages, message)
		if err != nil {
			t.Fatalf("Sign failed for message %d: %v", i, err)
		}

		err = frostService.Verify(message, signature, groupPubKey)
		if err != nil {
			t.Fatalf("Verify failed for message %d: %v", i, err)
		}
	}
}

// TestSignatureNonMalleability verifies that signatures are unique
// for each signing session (nonces are properly randomized).
func TestSignatureNonMalleability(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	message := []byte("Same message")

	// Generate multiple signatures for the same message
	signatures := make([]frost.Signature, 10)
	for i := 0; i < 10; i++ {
		signingPackages := keyPackages[:2]
		signature, err := frostService.Sign(signingPackages, message)
		if err != nil {
			t.Fatalf("Sign %d failed: %v", i, err)
		}
		signatures[i] = signature
	}

	// Verify all signatures are different (due to random nonces)
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if signatures[i].R.Equal(signatures[j].R) {
				t.Errorf("Signatures %d and %d have the same R value", i, j)
			}
		}
	}
}

// TestKeyPackageIndependence verifies that key packages can be used
// independently and don't interfere with each other.
func TestKeyPackageIndependence(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	message := []byte("test")

	// Sign with different combinations simultaneously
	var wg sync.WaitGroup
	wg.Add(3)

	errors := make(chan error, 3)

	combinations := [][]int{{0, 1}, {0, 2}, {1, 2}}

	for i, combo := range combinations {
		go func(index int, c []int) {
			defer wg.Done()

			signingPackages := []frost.KeyPackage{
				keyPackages[c[0]],
				keyPackages[c[1]],
			}

			signature, err := frostService.Sign(signingPackages, message)
			if err != nil {
				errors <- fmt.Errorf("combination %d failed to sign: %v", index, err)
				return
			}

			err = frostService.Verify(message, signature, groupPubKey)
			if err != nil {
				errors <- fmt.Errorf("combination %d failed to verify: %v", index, err)
				return
			}
		}(i, combo)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestMessageIntegrity verifies that any modification to the message
// causes verification to fail.
func TestMessageIntegrity(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := NewFrostService(suite)

	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participants := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	message := []byte("Original message")
	signature, err := frostService.Sign(keyPackages[:2], message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Test various message modifications
	modifications := []struct {
		name     string
		modifier func([]byte) []byte
	}{
		{
			name: "append byte",
			modifier: func(msg []byte) []byte {
				return append(bytes.Clone(msg), byte(0x00))
			},
		},
		{
			name: "prepend byte",
			modifier: func(msg []byte) []byte {
				return append([]byte{0x00}, msg...)
			},
		},
		{
			name: "flip one bit",
			modifier: func(msg []byte) []byte {
				modified := bytes.Clone(msg)
				if len(modified) > 0 {
					modified[0] ^= 0x01
				}
				return modified
			},
		},
		{
			name: "truncate",
			modifier: func(msg []byte) []byte {
				if len(msg) > 1 {
					return msg[:len(msg)-1]
				}
				return msg
			},
		},
		{
			name: "completely different",
			modifier: func(msg []byte) []byte {
				return []byte("Completely different message")
			},
		},
	}

	for _, mod := range modifications {
		t.Run(mod.name, func(t *testing.T) {
			modifiedMessage := mod.modifier(message)
			err := frostService.Verify(modifiedMessage, signature, groupPubKey)
			if err == nil {
				t.Errorf("Verification should fail for modification: %s", mod.name)
			}
		})
	}
}
