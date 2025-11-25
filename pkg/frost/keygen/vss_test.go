package keygen

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

func TestVSS_CreateCommitments(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	tests := []struct {
		name        string
		polynomial  frost.Polynomial
		expectError bool
		description string
	}{
		{
			name: "valid polynomial degree 0",
			polynomial: frost.Polynomial{
				Coefficients: []group.Scalar{
					newMockScalar(42, grp.order),
				},
			},
			expectError: false,
			description: "single coefficient polynomial should create one commitment",
		},
		{
			name: "valid polynomial degree 2",
			polynomial: frost.Polynomial{
				Coefficients: []group.Scalar{
					newMockScalar(5, grp.order),
					newMockScalar(10, grp.order),
					newMockScalar(15, grp.order),
				},
			},
			expectError: false,
			description: "polynomial with 3 coefficients should create 3 commitments",
		},
		{
			name: "empty polynomial",
			polynomial: frost.Polynomial{
				Coefficients: []group.Scalar{},
			},
			expectError: true,
			description: "empty polynomial should return error",
		},
		{
			name: "polynomial with zero coefficient",
			polynomial: frost.Polynomial{
				Coefficients: []group.Scalar{
					newMockScalar(0, grp.order),
					newMockScalar(5, grp.order),
				},
			},
			expectError: false,
			description: "zero coefficients are valid in polynomial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commitments, err := vss.CreateCommitments(tt.polynomial)

			if tt.expectError {
				if err == nil {
					t.Errorf("CreateCommitments() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("CreateCommitments() unexpected error: %v", err)
				return
			}

			if len(commitments) != len(tt.polynomial.Coefficients) {
				t.Errorf("CreateCommitments() returned %d commitments, expected %d",
					len(commitments), len(tt.polynomial.Coefficients))
			}

			// Verify each commitment is ScalarBaseMult(coefficient)
			for i, coeff := range tt.polynomial.Coefficients {
				expected := grp.ScalarBaseMult(coeff)
				if !commitments[i].VerificationKey.Equal(expected) {
					t.Errorf("Commitment[%d] does not match ScalarBaseMult(coefficient[%d])", i, i)
				}
				if commitments[i].Identifier != frost.Identifier(i) {
					t.Errorf("Commitment[%d] has wrong identifier: got %d, want %d",
						i, commitments[i].Identifier, i)
				}
			}
		})
	}
}

func TestVSS_VerifyShare(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	// Create a simpler test polynomial with smaller coefficients: f(x) = 3 + 2x
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(3, grp.order),
			newMockScalar(2, grp.order),
		},
	}

	// Create commitments
	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("Failed to create commitments: %v", err)
	}

	// Helper function to evaluate polynomial at a point
	evaluatePoly := func(coeffs []group.Scalar, x int64) group.Scalar {
		idScalar := newMockScalar(x, grp.order)
		result := coeffs[0].Copy()
		idPower := idScalar.Copy()
		for j := 1; j < len(coeffs); j++ {
			term := coeffs[j].Mul(idPower)
			result = result.Add(term)
			idPower = idPower.Mul(idScalar)
		}
		return result
	}

	tests := []struct {
		name        string
		identifier  frost.Identifier
		share       group.Scalar
		commitments []frost.VerificationShare
		expectError bool
		description string
	}{
		{
			name:       "valid share for participant 1",
			identifier: 1,
			// f(1) = 3 + 2*1 = 5
			share:       evaluatePoly(polynomial.Coefficients, 1),
			commitments: commitments,
			expectError: false,
			description: "correctly computed share should verify",
		},
		{
			name:       "valid share for participant 2",
			identifier: 2,
			// f(2) = 3 + 2*2 = 7
			share:       evaluatePoly(polynomial.Coefficients, 2),
			commitments: commitments,
			expectError: false,
			description: "correctly computed share should verify",
		},
		{
			name:       "valid share for participant 3",
			identifier: 3,
			// f(3) = 3 + 2*3 = 9
			share:       evaluatePoly(polynomial.Coefficients, 3),
			commitments: commitments,
			expectError: false,
			description: "correctly computed share should verify",
		},
		{
			name:        "invalid share",
			identifier:  1,
			share:       newMockScalar(999, grp.order),
			commitments: commitments,
			expectError: true,
			description: "incorrectly computed share should fail verification",
		},
		{
			name:        "zero identifier",
			identifier:  0,
			share:       newMockScalar(3, grp.order), // f(0) = 3
			commitments: commitments,
			expectError: true,
			description: "zero identifier should be rejected",
		},
		{
			name:        "empty commitments",
			identifier:  1,
			share:       newMockScalar(5, grp.order),
			commitments: []frost.VerificationShare{},
			expectError: true,
			description: "empty commitments list should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vss.VerifyShare(tt.identifier, tt.share, tt.commitments)

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

func TestVSS_VerifyShare_EdgeCases(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	// Create a simple constant polynomial: f(x) = 42
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(42, grp.order),
		},
	}

	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("Failed to create commitments: %v", err)
	}

	t.Run("constant polynomial", func(t *testing.T) {
		// For constant polynomial, f(x) = 42 for all x
		for id := 1; id <= 5; id++ {
			err := vss.VerifyShare(frost.Identifier(id), newMockScalar(42, grp.order), commitments)
			if err != nil {
				t.Errorf("VerifyShare() for constant polynomial failed for id %d: %v", id, err)
			}
		}
	})

	t.Run("nil commitments", func(t *testing.T) {
		err := vss.VerifyShare(1, newMockScalar(42, grp.order), nil)
		if err == nil {
			t.Error("VerifyShare() with nil commitments should return error")
		}
	})
}

func TestVSS_CombineShares(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	tests := []struct {
		name        string
		shares      []group.Scalar
		expected    int64
		expectError bool
		description string
	}{
		{
			name: "combine two shares",
			shares: []group.Scalar{
				newMockScalar(10, grp.order),
				newMockScalar(20, grp.order),
			},
			expected:    30,
			expectError: false,
			description: "sum of two shares",
		},
		{
			name: "combine three shares",
			shares: []group.Scalar{
				newMockScalar(5, grp.order),
				newMockScalar(15, grp.order),
				newMockScalar(25, grp.order),
			},
			expected:    45,
			expectError: false,
			description: "sum of three shares",
		},
		{
			name: "combine with modular reduction",
			shares: []group.Scalar{
				newMockScalar(90, grp.order),
				newMockScalar(20, grp.order),
			},
			expected:    13, // (90 + 20) mod 97 = 13
			expectError: false,
			description: "sum with modular reduction",
		},
		{
			name:        "single share",
			shares:      []group.Scalar{newMockScalar(42, grp.order)},
			expected:    42,
			expectError: false,
			description: "single share returns itself",
		},
		{
			name:        "empty shares",
			shares:      []group.Scalar{},
			expectError: true,
			description: "empty shares should return error",
		},
		{
			name:        "nil shares",
			shares:      nil,
			expectError: true,
			description: "nil shares should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vss.CombineShares(tt.shares)

			if tt.expectError {
				if err == nil {
					t.Errorf("CombineShares() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("CombineShares() unexpected error: %v", err)
				return
			}

			expected := newMockScalar(tt.expected, grp.order)
			if !result.Equal(expected) {
				t.Errorf("CombineShares() = %v, want %v",
					result.(*mockScalar).value, expected.value)
			}
		})
	}
}

func TestVSS_Integration(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	// Create a polynomial representing a secret sharing scheme with small coefficients
	secret := newMockScalar(5, grp.order)
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			secret,
			newMockScalar(2, grp.order),
		},
	}

	// Create commitments
	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("CreateCommitments failed: %v", err)
	}

	// Evaluate polynomial at participant identifiers and verify shares
	participantIDs := []frost.Identifier{1, 2, 3, 4, 5}
	shares := make([]group.Scalar, len(participantIDs))

	for i, id := range participantIDs {
		// Manually compute f(id) = c0 + c1*id + c2*id^2
		idScalar := newMockScalar(int64(id), grp.order)
		share := polynomial.Coefficients[0].Copy()

		idPower := idScalar.Copy()
		for j := 1; j < len(polynomial.Coefficients); j++ {
			term := polynomial.Coefficients[j].Mul(idPower)
			share = share.Add(term)
			idPower = idPower.Mul(idScalar)
		}

		shares[i] = share

		// Verify the share
		err := vss.VerifyShare(id, share, commitments)
		if err != nil {
			t.Errorf("VerifyShare failed for participant %d: %v", id, err)
		}
	}

	// Verify that commitments[0] equals ScalarBaseMult(secret)
	expectedCommitment := grp.ScalarBaseMult(secret)
	if !commitments[0].VerificationKey.Equal(expectedCommitment) {
		t.Error("First commitment should equal ScalarBaseMult(secret)")
	}
}

func TestVSS_VerifyShare_Computation(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	// Test that verification correctly computes:
	// ScalarBaseMult(share) == sum_{j=0}^{degree} commitment_j * id^j

	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(3, grp.order),
			newMockScalar(7, grp.order),
		},
	}

	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("CreateCommitments failed: %v", err)
	}

	// Test with id=4
	// f(4) = 3 + 7*4 = 31
	id := frost.Identifier(4)
	share := newMockScalar(31, grp.order)

	// Manually verify the computation
	// Left side: ScalarBaseMult(share)
	left := grp.ScalarBaseMult(share)

	// Right side: commitment[0] * 1 + commitment[1] * 4
	idScalar := newMockScalar(int64(id), grp.order)
	right := commitments[0].VerificationKey.Copy()
	term := grp.ScalarMult(commitments[1].VerificationKey, idScalar)
	right = right.Add(term)

	if !left.Equal(right) {
		t.Error("Manual verification computation does not match expected result")
	}

	// Now verify using VSS
	err = vss.VerifyShare(id, share, commitments)
	if err != nil {
		t.Errorf("VerifyShare failed: %v", err)
	}
}

func TestVSS_VerifyShare_LargePolynomial(t *testing.T) {
	grp := newMockGroup()
	vss := NewVSS(grp)

	// Create a polynomial with more terms to test all branches
	polynomial := frost.Polynomial{
		Coefficients: []group.Scalar{
			newMockScalar(1, grp.order),
			newMockScalar(2, grp.order),
			newMockScalar(3, grp.order),
		},
	}

	commitments, err := vss.CreateCommitments(polynomial)
	if err != nil {
		t.Fatalf("CreateCommitments failed: %v", err)
	}

	// Test with a specific identifier
	id := frost.Identifier(5)

	// Evaluate polynomial: f(5) = 1 + 2*5 + 3*5^2 = 1 + 10 + 75 = 86
	expectedShare := newMockScalar(86, grp.order)

	err = vss.VerifyShare(id, expectedShare, commitments)
	if err != nil {
		t.Errorf("VerifyShare failed for large polynomial: %v", err)
	}
}
