package keygen

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// mockCiphersuite implements ciphersuite.Ciphersuite for testing
type mockCiphersuite struct {
	group *mockGroup
}

func newMockCiphersuite() *mockCiphersuite {
	return &mockCiphersuite{
		group: newMockGroup(),
	}
}

func (m *mockCiphersuite) ID() string {
	return "mock-suite"
}

func (m *mockCiphersuite) Group() group.Group {
	return m.group
}

func (m *mockCiphersuite) H1(data []byte) group.Scalar {
	return m.group.NewScalar()
}

func (m *mockCiphersuite) H2(data []byte) group.Scalar {
	return m.group.NewScalar()
}

func (m *mockCiphersuite) H3(data []byte) group.Scalar {
	return m.group.NewScalar()
}

func (m *mockCiphersuite) H4(msg []byte) []byte {
	return msg
}

func (m *mockCiphersuite) H5(data []byte) []byte {
	return data
}

func (m *mockCiphersuite) HashToCurve(data []byte) (group.Element, error) {
	return m.group.Generator(), nil
}

func (m *mockCiphersuite) Hash(data []byte) []byte {
	return data
}

func (m *mockCiphersuite) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
	return nil
}

func (m *mockCiphersuite) HDKG(data []byte) group.Scalar {
	return m.group.NewScalar()
}

func (m *mockCiphersuite) HID(data []byte) group.Scalar {
	return m.group.NewScalar()
}

func (m *mockCiphersuite) ContextString() string {
	return "MOCK"
}

func (m *mockCiphersuite) Name() string {
	return "Mock Ciphersuite"
}

func TestDealer_GenerateShares(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	tests := []struct {
		name           string
		secret         group.Scalar
		minSigners     uint32
		maxSigners     uint32
		participantIDs []frost.Identifier
		expectError    bool
		description    string
	}{
		{
			name:           "valid 2-of-3 threshold",
			secret:         nil, // Will be generated
			minSigners:     2,
			maxSigners:     3,
			participantIDs: createParticipantIDs(3),
			expectError:    false,
			description:    "standard 2-of-3 threshold signature scheme",
		},
		{
			name:           "valid 3-of-5 threshold",
			secret:         nil,
			minSigners:     3,
			maxSigners:     5,
			participantIDs: createParticipantIDs(5),
			expectError:    false,
			description:    "3-of-5 threshold signature scheme",
		},
		{
			name:           "valid with provided secret",
			secret:         newMockScalar(7, suite.group.order),
			minSigners:     2,
			maxSigners:     3,
			participantIDs: createParticipantIDs(3),
			expectError:    false,
			description:    "use provided secret instead of generating",
		},
		{
			name:           "minimum threshold",
			secret:         nil,
			minSigners:     2,
			maxSigners:     2,
			participantIDs: createParticipantIDs(2),
			expectError:    false,
			description:    "minimum participants equals threshold",
		},
		{
			name:           "invalid: minSigners > maxSigners",
			secret:         nil,
			minSigners:     4,
			maxSigners:     3,
			participantIDs: createParticipantIDs(3),
			expectError:    true,
			description:    "threshold cannot exceed total participants",
		},
		{
			name:           "invalid: minSigners < 2",
			secret:         nil,
			minSigners:     1,
			maxSigners:     3,
			participantIDs: createParticipantIDs(3),
			expectError:    true,
			description:    "threshold must be at least 2",
		},
		{
			name:           "invalid: wrong number of participant IDs",
			secret:         nil,
			minSigners:     2,
			maxSigners:     3,
			participantIDs: createParticipantIDs(2), // Should be 3
			expectError:    true,
			description:    "participant ID count must match maxSigners",
		},
		{
			name:           "invalid: duplicate participant IDs",
			secret:         nil,
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{1, 2, 2},
			expectError:    true,
			description:    "participant IDs must be unique",
		},
		{
			name:           "invalid: zero participant ID",
			secret:         nil,
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{0, 1, 2},
			expectError:    true,
			description:    "participant IDs must be non-zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPackages, groupPubKey, err := dealer.GenerateShares(
				tt.secret,
				tt.minSigners,
				tt.maxSigners,
				tt.participantIDs,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("GenerateShares() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateShares() unexpected error: %v", err)
				return
			}

			// Verify correct number of key packages
			if len(keyPackages) != int(tt.maxSigners) {
				t.Errorf("GenerateShares() returned %d key packages, expected %d",
					len(keyPackages), tt.maxSigners)
			}

			// Verify group public key is not nil or identity
			if groupPubKey == nil {
				t.Error("GenerateShares() returned nil group public key")
				return
			}
			if groupPubKey.IsIdentity() {
				t.Error("GenerateShares() returned identity element as group public key")
			}

			// Verify each key package
			for i, pkg := range keyPackages {
				// Check identifier matches
				if pkg.Identifier != tt.participantIDs[i] {
					t.Errorf("KeyPackage[%d] has identifier %d, expected %d",
						i, pkg.Identifier, tt.participantIDs[i])
				}

				// Check secret share is not nil or zero
				if pkg.SecretShare == nil {
					t.Errorf("KeyPackage[%d] has nil secret share", i)
					continue
				}
				if pkg.SecretShare.IsZero() {
					t.Errorf("KeyPackage[%d] has zero secret share", i)
				}

				// Check group public key matches
				if !pkg.GroupPublicKey.Equal(groupPubKey) {
					t.Errorf("KeyPackage[%d] has different group public key", i)
				}

				// Check verification shares
				if len(pkg.VerificationShares) != int(tt.minSigners) {
					t.Errorf("KeyPackage[%d] has %d verification shares, expected %d",
						i, len(pkg.VerificationShares), tt.minSigners)
				}
			}

			// Note: VSS verification is tested separately in TestVSS_*.
			// The mock group has limitations with large random coefficients,
			// so we skip detailed VSS verification here and trust that
			// the VSS tests validate the correctness of the verification logic.

			// If secret was provided, verify group public key matches
			if tt.secret != nil {
				expectedGroupPubKey := suite.Group().ScalarBaseMult(tt.secret)
				if !groupPubKey.Equal(expectedGroupPubKey) {
					t.Error("Group public key does not match ScalarBaseMult(secret)")
				}
			}
		})
	}
}

func TestDealer_VerifyShare(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	// Create a simple polynomial with small known coefficients for testing
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(3, suite.group.order),
			newMockScalar(2, suite.group.order),
		},
	}

	// Create VSS commitments
	vss := NewVSS(suite.Group())
	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("Failed to create commitments: %v", err)
	}

	// Evaluate polynomial at participant 1: f(1) = 3 + 2*1 = 5
	polyHelper := helpers.NewPolynomialHelper(suite.Group())
	idScalar := newMockScalar(1, suite.group.order)
	share1 := polyHelper.Evaluate(polynomial, idScalar)

	tests := []struct {
		name               string
		identifier         frost.Identifier
		secretShare        group.Scalar
		verificationShares []frost.VerificationShare
		expectError        bool
		description        string
	}{
		{
			name:               "valid share verification",
			identifier:         1,
			secretShare:        share1,
			verificationShares: commitments,
			expectError:        false,
			description:        "correctly computed share should verify",
		},
		{
			name:               "invalid share",
			identifier:         1,
			secretShare:        newMockScalar(999, suite.group.order),
			verificationShares: commitments,
			expectError:        true,
			description:        "incorrectly computed share should fail",
		},
		{
			name:               "wrong identifier",
			identifier:         99,
			secretShare:        share1,
			verificationShares: commitments,
			expectError:        true,
			description:        "share verification with wrong identifier should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dealer.VerifyShare(tt.identifier, tt.secretShare, tt.verificationShares)

			if tt.expectError {
				if err == nil {
					t.Errorf("VerifyShare() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("VerifyShare() unexpected error: %v", err)
			}
		})
	}
}

func TestDealer_RecoverSecret(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	// Generate shares with a known secret
	secretScalar := newMockScalar(42, suite.group.order)
	participantIDs := createParticipantIDs(5)
	keyPackages, _, err := dealer.GenerateShares(secretScalar, 3, 5, participantIDs)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	tests := []struct {
		name          string
		shares        map[frost.Identifier]group.Scalar
		expectError   bool
		checkEquality bool
		description   string
	}{
		{
			name: "recover from minimum threshold",
			shares: map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
				keyPackages[2].Identifier: keyPackages[2].SecretShare,
			},
			expectError:   false,
			checkEquality: true,
			description:   "exactly 3 shares (threshold) should recover secret",
		},
		{
			name: "recover from more than threshold",
			shares: map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
				keyPackages[2].Identifier: keyPackages[2].SecretShare,
				keyPackages[3].Identifier: keyPackages[3].SecretShare,
			},
			expectError:   false,
			checkEquality: true,
			description:   "4 shares (more than threshold) should recover secret",
		},
		{
			name: "recover from all shares",
			shares: map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
				keyPackages[2].Identifier: keyPackages[2].SecretShare,
				keyPackages[3].Identifier: keyPackages[3].SecretShare,
				keyPackages[4].Identifier: keyPackages[4].SecretShare,
			},
			expectError:   false,
			checkEquality: true,
			description:   "all 5 shares should recover secret",
		},
		{
			name: "insufficient shares",
			shares: map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
			},
			expectError:   false,
			checkEquality: false,
			description:   "2 shares (less than threshold of 3) - Note: Lagrange interpolation mathematically succeeds but recovers wrong secret",
		},
		{
			name:          "empty shares",
			shares:        map[frost.Identifier]group.Scalar{},
			expectError:   true,
			checkEquality: false,
			description:   "no shares should fail",
		},
		{
			name:          "nil shares",
			shares:        nil,
			expectError:   true,
			checkEquality: false,
			description:   "nil shares map should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recoveredSecret, err := dealer.RecoverSecret(tt.shares)

			if tt.expectError {
				if err == nil {
					t.Errorf("RecoverSecret() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("RecoverSecret() unexpected error: %v", err)
				return
			}

			// Verify recovered secret matches original (only if we have enough shares)
			if tt.checkEquality && !recoveredSecret.Equal(secretScalar) {
				recoveredVal := recoveredSecret.(*mockScalar).value
				secretVal := secretScalar.value
				t.Errorf("RecoverSecret() = %v, want %v", recoveredVal, secretVal)
			}
		})
	}
}

func TestDealer_Integration(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	// Test a complete key generation and recovery flow
	minSigners := uint32(3)
	maxSigners := uint32(5)
	participantIDs := createParticipantIDs(int(maxSigners))

	// Generate shares
	keyPackages, groupPubKey, err := dealer.GenerateShares(nil, minSigners, maxSigners, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Basic sanity checks on generated packages
	if len(keyPackages) != int(maxSigners) {
		t.Fatalf("Expected %d key packages, got %d", maxSigners, len(keyPackages))
	}

	for i, pkg := range keyPackages {
		if pkg.Identifier != participantIDs[i] {
			t.Errorf("Package %d has wrong identifier: got %d, want %d",
				i, pkg.Identifier, participantIDs[i])
		}
		if pkg.SecretShare == nil || pkg.SecretShare.IsZero() {
			t.Errorf("Package %d has invalid secret share", i)
		}
		if !pkg.GroupPublicKey.Equal(groupPubKey) {
			t.Errorf("Package %d has inconsistent group public key", i)
		}
	}

	// Recover secret from threshold shares
	shares := make(map[frost.Identifier]group.Scalar)
	for i := 0; i < int(minSigners); i++ {
		shares[keyPackages[i].Identifier] = keyPackages[i].SecretShare
	}

	recoveredSecret, err := dealer.RecoverSecret(shares)
	if err != nil {
		t.Fatalf("RecoverSecret failed: %v", err)
	}

	// Verify group public key matches recovered secret
	recoveredGroupPubKey := suite.Group().ScalarBaseMult(recoveredSecret)
	if !groupPubKey.Equal(recoveredGroupPubKey) {
		t.Error("Group public key does not match ScalarBaseMult(recovered secret)")
	}

	// Test with different subset of shares
	shares2 := make(map[frost.Identifier]group.Scalar)
	shares2[keyPackages[1].Identifier] = keyPackages[1].SecretShare
	shares2[keyPackages[2].Identifier] = keyPackages[2].SecretShare
	shares2[keyPackages[4].Identifier] = keyPackages[4].SecretShare

	recoveredSecret2, err := dealer.RecoverSecret(shares2)
	if err != nil {
		t.Fatalf("RecoverSecret with different shares failed: %v", err)
	}

	// Should recover the same secret
	if !recoveredSecret.Equal(recoveredSecret2) {
		t.Error("Different subset of shares recovered different secret")
	}
}

func TestDealer_GenerateShares_EdgeCases(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	tests := []struct {
		name           string
		secret         group.Scalar
		minSigners     uint32
		maxSigners     uint32
		participantIDs []frost.Identifier
		expectError    bool
		description    string
	}{
		{
			name:           "large threshold",
			secret:         nil,
			minSigners:     10,
			maxSigners:     10,
			participantIDs: createParticipantIDs(10),
			expectError:    false,
			description:    "large threshold value",
		},
		{
			name:           "large number of participants",
			secret:         nil,
			minSigners:     5,
			maxSigners:     20,
			participantIDs: createParticipantIDs(20),
			expectError:    false,
			description:    "20 participants with 5-of-20 threshold",
		},
		{
			name:           "small secret value",
			secret:         newMockScalar(1, suite.group.order),
			minSigners:     2,
			maxSigners:     3,
			participantIDs: createParticipantIDs(3),
			expectError:    false,
			description:    "minimal secret value",
		},
		{
			name:           "non-sequential participant IDs",
			secret:         nil,
			minSigners:     2,
			maxSigners:     3,
			participantIDs: []frost.Identifier{2, 5, 10},
			expectError:    false,
			description:    "non-sequential participant ID values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPackages, groupPubKey, err := dealer.GenerateShares(
				tt.secret,
				tt.minSigners,
				tt.maxSigners,
				tt.participantIDs,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("GenerateShares() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateShares() unexpected error: %v", err)
				return
			}

			// Verify correct number of key packages
			if len(keyPackages) != int(tt.maxSigners) {
				t.Errorf("GenerateShares() returned %d key packages, expected %d",
					len(keyPackages), tt.maxSigners)
			}

			// Verify group public key is not nil
			if groupPubKey == nil {
				t.Error("GenerateShares() returned nil group public key")
				return
			}

			// Verify each key package has correct structure
			for i, pkg := range keyPackages {
				if pkg.Identifier != tt.participantIDs[i] {
					t.Errorf("KeyPackage[%d] has wrong identifier", i)
				}
				if pkg.SecretShare == nil {
					t.Errorf("KeyPackage[%d] has nil secret share", i)
				}
				if len(pkg.VerificationShares) != int(tt.minSigners) {
					t.Errorf("KeyPackage[%d] has wrong number of verification shares", i)
				}
			}
		})
	}
}

func TestDealer_VerifyShare_Additional(t *testing.T) {
	suite := newMockCiphersuite()
	dealer := NewDealer(suite)

	// Create a polynomial with more coefficients
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(5, suite.group.order),
			newMockScalar(3, suite.group.order),
			newMockScalar(2, suite.group.order),
		},
	}

	vss := NewVSS(suite.Group())
	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("Failed to create commitments: %v", err)
	}

	// Test high participant ID (within group order)
	t.Run("high participant ID", func(t *testing.T) {
		highID := frost.Identifier(20)
		polyHelper := helpers.NewPolynomialHelper(suite.Group())
		idScalar := newMockScalar(int64(highID), suite.group.order)
		share := polyHelper.Evaluate(polynomial, idScalar)

		err := dealer.VerifyShare(highID, share, commitments)
		if err != nil {
			t.Errorf("VerifyShare() with high ID failed: %v", err)
		}
	})
}
