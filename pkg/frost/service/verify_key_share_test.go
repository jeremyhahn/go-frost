package service

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

// TestFrostService_VerifyKeyShare_Integration tests that generated keys verify correctly.
func TestFrostService_VerifyKeyShare_Integration(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	tests := []struct {
		name        string
		minSigners  uint32
		maxSigners  uint32
		description string
	}{
		{
			name:        "2-of-3 threshold",
			minSigners:  2,
			maxSigners:  3,
			description: "standard 2-of-3 configuration",
		},
		{
			name:        "3-of-5 threshold",
			minSigners:  3,
			maxSigners:  5,
			description: "3-of-5 configuration",
		},
		{
			name:        "2-of-2 minimal threshold",
			minSigners:  2,
			maxSigners:  2,
			description: "minimum valid threshold",
		},
		{
			name:        "5-of-7 threshold",
			minSigners:  5,
			maxSigners:  7,
			description: "larger threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate keys
			config := frost.Configuration{
				MinSigners: tt.minSigners,
				MaxSigners: tt.maxSigners,
				Group:      suite.Group(),
			}

			participantIDs := make([]frost.Identifier, tt.maxSigners)
			for i := uint32(0); i < tt.maxSigners; i++ {
				participantIDs[i] = frost.Identifier(i + 1)
			}

			keyPackages, _, err := service.GenerateKeys(config, participantIDs)
			if err != nil {
				t.Fatalf("GenerateKeys failed: %v", err)
			}

			// Verify each key package
			for i, pkg := range keyPackages {
				err := service.VerifyKeyShare(pkg)
				if err != nil {
					t.Errorf("VerifyKeyShare failed for participant %d (ID %d): %v (%s)",
						i, pkg.Identifier, err, tt.description)
				}
			}
		})
	}
}

// TestFrostService_VerifyKeyShare_InvalidShares tests that invalid shares fail verification.
func TestFrostService_VerifyKeyShare_InvalidShares(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate valid keys first
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}

	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	validPkg := keyPackages[0]

	tests := []struct {
		name        string
		keyPackage  frost.KeyPackage
		expectError bool
		description string
	}{
		{
			name:        "valid key package",
			keyPackage:  validPkg,
			expectError: false,
			description: "properly generated key should verify",
		},
		{
			name: "nil secret share",
			keyPackage: frost.KeyPackage{
				Identifier:         validPkg.Identifier,
				SecretShare:        nil,
				GroupPublicKey:     validPkg.GroupPublicKey,
				VerificationShares: validPkg.VerificationShares,
			},
			expectError: true,
			description: "nil secret share should fail",
		},
		{
			name: "empty verification shares",
			keyPackage: frost.KeyPackage{
				Identifier:         validPkg.Identifier,
				SecretShare:        validPkg.SecretShare,
				GroupPublicKey:     validPkg.GroupPublicKey,
				VerificationShares: []frost.VerificationShare{},
			},
			expectError: true,
			description: "empty verification shares should fail",
		},
		{
			name: "tampered secret share",
			keyPackage: frost.KeyPackage{
				Identifier:         validPkg.Identifier,
				SecretShare:        suite.Group().NewScalar(), // Wrong value (zero)
				GroupPublicKey:     validPkg.GroupPublicKey,
				VerificationShares: validPkg.VerificationShares,
			},
			expectError: true,
			description: "tampered secret share should fail verification",
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
