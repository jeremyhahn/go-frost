package service

import (
	"sync"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestFrostService_GenerateKeys tests key generation through the service layer
func TestFrostService_GenerateKeys(t *testing.T) {
	suite := ristretto255_sha512.New()

	tests := []struct {
		name           string
		minSigners     uint32
		maxSigners     uint32
		participantIDs []frost.Identifier
		expectError    bool
		expectedErr    error
		description    string
	}{
		{
			name:           "valid 2-of-3 threshold",
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2, 3},
			expectError:    false,
			description:    "standard 2-of-3 threshold configuration",
		},
		{
			name:           "valid 3-of-5 threshold",
			minSigners:     3,
			maxSigners:     5,
			participantIDs: []frost.Identifier{1, 2, 3, 4, 5},
			expectError:    false,
			description:    "3-of-5 threshold configuration",
		},
		{
			name:           "minimum threshold (2-of-2)",
			minSigners:     2,
			maxSigners:     2,
			participantIDs: []frost.Identifier{1, 2},
			expectError:    false,
			description:    "minimum valid threshold",
		},
		{
			name:           "invalid threshold (minSigners = 1)",
			minSigners:     1,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2, 3},
			expectError:    true,
			expectedErr:    frost.ErrInvalidThreshold,
			description:    "threshold must be at least 2",
		},
		{
			name:           "invalid threshold (minSigners > maxSigners)",
			minSigners:     4,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2, 3},
			expectError:    true,
			expectedErr:    frost.ErrInvalidThreshold,
			description:    "minSigners cannot exceed maxSigners",
		},
		{
			name:           "invalid participant count mismatch",
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2},
			expectError:    true,
			expectedErr:    frost.ErrInvalidParameters,
			description:    "participant count must match maxSigners",
		},
		{
			name:           "duplicate participant IDs",
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2, 2},
			expectError:    true,
			expectedErr:    frost.ErrDuplicateParticipant,
			description:    "participant IDs must be unique",
		},
		{
			name:           "zero participant ID",
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{0, 1, 2},
			expectError:    true,
			expectedErr:    frost.ErrInvalidParticipant,
			description:    "participant IDs cannot be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewFrostService(suite)

			config := frost.Configuration{
				MinSigners: tt.minSigners,
				MaxSigners: tt.maxSigners,
				Group:      suite.Group(),
			}

			keyPackages, groupPubKey, err := service.GenerateKeys(config, tt.participantIDs)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				// Verify we get the expected error type
				if tt.expectedErr != nil && !isErrorType(err, tt.expectedErr) {
					t.Errorf("expected error type %v, got %v", tt.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}

			// Verify we got the correct number of key packages
			if uint32(len(keyPackages)) != tt.maxSigners {
				t.Errorf("expected %d key packages, got %d", tt.maxSigners, len(keyPackages))
			}

			// Verify group public key is not nil
			if groupPubKey == nil {
				t.Error("group public key is nil")
			}

			// Verify each key package has required fields
			for i, pkg := range keyPackages {
				if pkg.Identifier != tt.participantIDs[i] {
					t.Errorf("package %d has wrong identifier: expected %d, got %d",
						i, tt.participantIDs[i], pkg.Identifier)
				}
				if pkg.SecretShare == nil {
					t.Errorf("package %d has nil secret share", i)
				}
				if pkg.GroupPublicKey == nil {
					t.Errorf("package %d has nil group public key", i)
				}
				if !pkg.GroupPublicKey.Equal(groupPubKey) {
					t.Errorf("package %d group public key doesn't match returned public key", i)
				}
			}
		})
	}
}

// TestFrostService_Sign tests the complete signing flow
func TestFrostService_Sign(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys for 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	tests := []struct {
		name        string
		keyPackages []frost.KeyPackage
		message     []byte
		expectError bool
		description string
	}{
		{
			name:        "valid signing with 2 participants",
			keyPackages: []frost.KeyPackage{keyPackages[0], keyPackages[1]},
			message:     []byte("test message"),
			expectError: false,
			description: "minimum threshold participants",
		},
		{
			name:        "valid signing with all 3 participants",
			keyPackages: []frost.KeyPackage{keyPackages[0], keyPackages[1], keyPackages[2]},
			message:     []byte("test message"),
			expectError: false,
			description: "all participants signing",
		},
		{
			name:        "insufficient participants (1 of 2 required)",
			keyPackages: []frost.KeyPackage{keyPackages[0]},
			message:     []byte("test message"),
			expectError: true,
			description: "below threshold",
		},
		{
			name:        "empty message",
			keyPackages: []frost.KeyPackage{keyPackages[0], keyPackages[1]},
			message:     []byte{},
			expectError: false,
			description: "empty message should be allowed",
		},
		{
			name:        "nil key packages",
			keyPackages: nil,
			message:     []byte("test message"),
			expectError: true,
			description: "nil key packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := service.Sign(tt.keyPackages, tt.message)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}

			// Verify signature is not empty
			if signature.R == nil {
				t.Error("signature R component is nil")
			}
			if signature.Z == nil {
				t.Error("signature Z component is nil")
			}

			// Verify the signature
			err = service.Verify(tt.message, signature, groupPubKey)
			if err != nil {
				t.Errorf("signature verification failed: %v", err)
			}
		})
	}
}

// TestFrostService_Verify tests signature verification
func TestFrostService_Verify(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys and create a valid signature
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("test message")
	signature, err := service.Sign([]frost.KeyPackage{keyPackages[0], keyPackages[1]}, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	tests := []struct {
		name        string
		message     []byte
		signature   frost.Signature
		publicKey   group.Element
		expectError bool
		description string
	}{
		{
			name:        "valid signature",
			message:     message,
			signature:   signature,
			publicKey:   groupPubKey,
			expectError: false,
			description: "signature should verify correctly",
		},
		{
			name:        "wrong message",
			message:     []byte("different message"),
			signature:   signature,
			publicKey:   groupPubKey,
			expectError: true,
			description: "signature should fail with different message",
		},
		{
			name:        "wrong public key",
			message:     message,
			signature:   signature,
			publicKey:   suite.Group().Generator(),
			expectError: true,
			description: "signature should fail with wrong public key",
		},
		{
			name:        "nil signature R",
			message:     message,
			signature:   frost.Signature{R: nil, Z: signature.Z},
			publicKey:   groupPubKey,
			expectError: true,
			description: "nil R component should fail",
		},
		{
			name:        "nil signature Z",
			message:     message,
			signature:   frost.Signature{R: signature.R, Z: nil},
			publicKey:   groupPubKey,
			expectError: true,
			description: "nil Z component should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.Verify(tt.message, tt.signature, tt.publicKey)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}
		})
	}
}

// TestFrostService_VerifyKeyShare tests key share verification
func TestFrostService_VerifyKeyShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate valid keys
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	tests := []struct {
		name        string
		keyPackage  frost.KeyPackage
		expectError bool
		description string
	}{
		{
			name: "nil secret share",
			keyPackage: frost.KeyPackage{
				Identifier:         keyPackages[0].Identifier,
				SecretShare:        nil,
				GroupPublicKey:     keyPackages[0].GroupPublicKey,
				VerificationShares: keyPackages[0].VerificationShares,
			},
			expectError: true,
			description: "nil secret share should fail",
		},
		{
			name: "empty verification shares",
			keyPackage: frost.KeyPackage{
				Identifier:         keyPackages[0].Identifier,
				SecretShare:        keyPackages[0].SecretShare,
				GroupPublicKey:     keyPackages[0].GroupPublicKey,
				VerificationShares: []frost.VerificationShare{},
			},
			expectError: true,
			description: "empty verification shares should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.VerifyKeyShare(tt.keyPackage)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}
		})
	}
}

// TestFrostService_ConcurrentSigning tests concurrent signing sessions
func TestFrostService_ConcurrentSigning(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys for 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	// Run multiple concurrent signing operations
	concurrentSigners := 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrentSigners)

	for i := 0; i < concurrentSigners; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			message := []byte("concurrent message " + string(rune(iteration)))
			signature, err := service.Sign([]frost.KeyPackage{keyPackages[0], keyPackages[1]}, message)
			if err != nil {
				errors <- err
				return
			}

			// Verify the signature
			err = service.Verify(message, signature, groupPubKey)
			if err != nil {
				errors <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("concurrent signing error: %v", err)
	}
}

// TestFrostService_GetCiphersuite tests getting the ciphersuite
func TestFrostService_GetCiphersuite(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	retrievedSuite := service.GetCiphersuite()
	if retrievedSuite != suite {
		t.Error("GetCiphersuite returned wrong ciphersuite")
	}

	if retrievedSuite.ID() != suite.ID() {
		t.Errorf("ciphersuite ID mismatch: expected %s, got %s", suite.ID(), retrievedSuite.ID())
	}
}

// TestFrostService_SigningWithDifferentParticipants tests that different participant
// combinations produce valid signatures
func TestFrostService_SigningWithDifferentParticipants(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys for 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("test message")

	tests := []struct {
		name         string
		participants []int
		description  string
	}{
		{
			name:         "participants 1 and 2",
			participants: []int{0, 1},
			description:  "first two participants",
		},
		{
			name:         "participants 1 and 3",
			participants: []int{0, 2},
			description:  "first and third participants",
		},
		{
			name:         "participants 2 and 3",
			participants: []int{1, 2},
			description:  "second and third participants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingPackages := make([]frost.KeyPackage, len(tt.participants))
			for i, idx := range tt.participants {
				signingPackages[i] = keyPackages[idx]
			}

			signature, err := service.Sign(signingPackages, message)
			if err != nil {
				t.Fatalf("failed to sign: %v (%s)", err, tt.description)
			}

			// Verify the signature
			err = service.Verify(message, signature, groupPubKey)
			if err != nil {
				t.Errorf("signature verification failed: %v (%s)", err, tt.description)
			}
		})
	}
}

// TestFrostService_MultipleMessages tests signing multiple different messages
func TestFrostService_MultipleMessages(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys for 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
		[]byte("a longer message with more content"),
		[]byte(""),
		[]byte{0x00, 0x01, 0x02, 0xFF},
	}

	signingPackages := []frost.KeyPackage{keyPackages[0], keyPackages[1]}

	signatures := make([]frost.Signature, len(messages))

	// Sign all messages
	for i, msg := range messages {
		signature, err := service.Sign(signingPackages, msg)
		if err != nil {
			t.Fatalf("failed to sign message %d: %v", i, err)
		}
		signatures[i] = signature
	}

	// Verify all signatures
	for i, msg := range messages {
		err := service.Verify(msg, signatures[i], groupPubKey)
		if err != nil {
			t.Errorf("signature %d verification failed: %v", i, err)
		}
	}

	// Verify signatures don't cross-validate with wrong messages
	for i, msg := range messages {
		for j, sig := range signatures {
			if i == j {
				continue
			}
			err := service.Verify(msg, sig, groupPubKey)
			if err == nil {
				t.Errorf("signature %d incorrectly verified with message %d", j, i)
			}
		}
	}
}

// TestFrostService_GenerateKeys_Validation tests validation logic in GenerateKeys
func TestFrostService_GenerateKeys_Validation(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	tests := []struct {
		name           string
		config         frost.Configuration
		participantIDs []frost.Identifier
		expectError    bool
		description    string
	}{
		{
			name: "nil group",
			config: frost.Configuration{
				MinSigners: 2,
				MaxSigners: 3,
				Group:      nil,
			},
			participantIDs: []frost.Identifier{1, 2, 3},
			expectError:    true,
			description:    "nil group should fail",
		},
		{
			name: "nil participant IDs",
			config: frost.Configuration{
				MinSigners: 2,
				MaxSigners: 3,
				Group:      suite.Group(),
			},
			participantIDs: nil,
			expectError:    true,
			description:    "nil participant IDs should fail",
		},
		{
			name: "empty participant IDs",
			config: frost.Configuration{
				MinSigners: 2,
				MaxSigners: 3,
				Group:      suite.Group(),
			},
			participantIDs: []frost.Identifier{},
			expectError:    true,
			description:    "empty participant IDs should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := service.GenerateKeys(tt.config, tt.participantIDs)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}
		})
	}
}

// TestFrostService_Sign_Validation tests validation in Sign function
func TestFrostService_Sign_Validation(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate valid key packages
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	tests := []struct {
		name        string
		keyPackages []frost.KeyPackage
		expectError bool
		description string
	}{
		{
			name:        "single key package",
			keyPackages: []frost.KeyPackage{keyPackages[0]},
			expectError: true,
			description: "single key package should fail (need at least 2)",
		},
		{
			name:        "nil key packages",
			keyPackages: nil,
			expectError: true,
			description: "nil key packages should fail",
		},
		{
			name:        "empty key packages",
			keyPackages: []frost.KeyPackage{},
			expectError: true,
			description: "empty key packages should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Sign(tt.keyPackages, []byte("test"))

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}
		})
	}
}

// TestFrostService_Verify_InvalidSignature tests Verify with invalid signature
func TestFrostService_Verify_InvalidSignature(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	// Create a valid signature
	message := []byte("test message")
	signature, err := service.Sign([]frost.KeyPackage{keyPackages[0], keyPackages[1]}, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Try to verify with wrong public key
	invalidKey := suite.Group().Identity()
	err = service.Verify(message, signature, invalidKey)
	if err == nil {
		t.Error("Verify should fail with incorrect public key")
	}

	// Try to verify with nil public key
	err = service.Verify(message, signature, nil)
	if err == nil {
		t.Error("Verify should fail with nil public key")
	}
}

// Helper function to check if an error is of a specific type
func isErrorType(err, target error) bool {
	if err == target {
		return true
	}
	// Check if it's wrapped
	type unwrapper interface {
		Unwrap() error
	}
	if u, ok := err.(unwrapper); ok {
		return isErrorType(u.Unwrap(), target)
	}
	return false
}
