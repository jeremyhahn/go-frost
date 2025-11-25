package rfc

import (
	"encoding/hex"
	"sort"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// TestSection4_1_NonceGeneration tests RFC 9591 Section 4.1
// nonce_generate function requirements
func TestSection4_1_NonceGeneration(t *testing.T) {
	// RFC 9591 Section 4.1: Nonce Generation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("NonceGenerationBasic", func(t *testing.T) {
		// RFC 9591 Section 4.1: nonce_generate(secret) returns a nonce Scalar
		secret, _ := grp.RandomScalar()
		nonceGen := helpers.NewNonceGenerator(suite)

		nonce, err := nonceGen.Generate(secret)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		if nonce == nil {
			t.Fatal("Generated nonce should not be nil")
		}
	})

	t.Run("NonceUniqueness", func(t *testing.T) {
		// RFC 9591 Section 4.1: Fresh randomness ensures nonce uniqueness
		secret, _ := grp.RandomScalar()
		nonceGen := helpers.NewNonceGenerator(suite)

		nonce1, _ := nonceGen.Generate(secret)
		nonce2, _ := nonceGen.Generate(secret)

		// Even with the same secret, nonces should be different due to fresh randomness
		if nonce1.Equal(nonce2) {
			t.Error("Two nonces generated with same secret should be different")
		}
	})

	t.Run("NonceReusePrevention", func(t *testing.T) {
		// RFC 9591 Section 4.1: The probability of nonce reuse is at most 2^-128
		// as long as no more than 2^64 signatures are computed
		secret, _ := grp.RandomScalar()
		nonceGen := helpers.NewNonceGenerator(suite)

		// Generate multiple nonces and verify they're unique
		nonces := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			nonce, _ := nonceGen.Generate(secret)
			nonceHex := hex.EncodeToString(nonce.Bytes())

			if nonces[nonceHex] {
				t.Errorf("Nonce collision detected at iteration %d", i)
			}
			nonces[nonceHex] = true
		}
	})

	t.Run("DomainSeparation", func(t *testing.T) {
		// RFC 9591 Section 4.1: Nonces are generated using H3 which is domain-separated
		secret, _ := grp.RandomScalar()
		nonceGen := helpers.NewNonceGenerator(suite)

		nonce, _ := nonceGen.Generate(secret)

		// Verify the nonce is a valid scalar
		element := grp.ScalarBaseMult(nonce)
		if element == nil {
			t.Error("Nonce should be a valid scalar for group operations")
		}
	})
}

// TestSection4_2_Polynomials tests RFC 9591 Section 4.2
// polynomial operations requirements
func TestSection4_2_Polynomials(t *testing.T) {
	// RFC 9591 Section 4.2: Polynomials
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	polyHelper := helpers.NewPolynomialHelper(grp)

	t.Run("PolynomialRepresentation", func(t *testing.T) {
		// RFC 9591 Section 4.2: A polynomial of maximum degree t is represented as a
		// list of t+1 coefficients, where the constant term is first
		// Example: x^2 + 2x + 3 is represented as [3, 2, 1]

		// Create polynomial: 3 + 2x + 1x^2
		coeff0 := scalarFromUint64(grp, 3)
		coeff1 := scalarFromUint64(grp, 2)
		coeff2 := scalarFromUint64(grp, 1)

		poly := frost.Polynomial{
			Coefficients: []group.Scalar{coeff0, coeff1, coeff2},
		}

		// Degree should be 2 (number of coefficients - 1)
		if len(poly.Coefficients) != 3 {
			t.Errorf("Expected 3 coefficients, got %d", len(poly.Coefficients))
		}
	})

	t.Run("PolynomialEvaluation", func(t *testing.T) {
		// RFC 9591 Section 4.2: A point on the polynomial f is a tuple (x, y),
		// where y = f(x)

		// Create polynomial: 3 + 2x + 1x^2
		coeff0 := scalarFromUint64(grp, 3)
		coeff1 := scalarFromUint64(grp, 2)
		coeff2 := scalarFromUint64(grp, 1)

		poly := frost.Polynomial{
			Coefficients: []group.Scalar{coeff0, coeff1, coeff2},
		}

		// Evaluate at x = 0: f(0) = 3
		x0 := grp.NewScalar() // zero
		y0 := polyHelper.Evaluate(poly, x0)
		if !y0.Equal(coeff0) {
			t.Error("f(0) should equal the constant term")
		}

		// Evaluate at x = 1: f(1) = 3 + 2(1) + 1(1)^2 = 6
		x1 := scalarFromUint64(grp, 1)
		y1 := polyHelper.Evaluate(poly, x1)
		expected1 := scalarFromUint64(grp, 6)
		if !y1.Equal(expected1) {
			t.Errorf("f(1) should equal 6, got %v", y1)
		}

		// Evaluate at x = 2: f(2) = 3 + 2(2) + 1(2)^2 = 3 + 4 + 4 = 11
		x2 := scalarFromUint64(grp, 2)
		y2 := polyHelper.Evaluate(poly, x2)
		expected2 := scalarFromUint64(grp, 11)
		if !y2.Equal(expected2) {
			t.Errorf("f(2) should equal 11, got %v", y2)
		}
	})

	t.Run("DeriveInterpolatingValue", func(t *testing.T) {
		// RFC 9591 Section 4.2: derive_interpolating_value derives a value used
		// for polynomial interpolation (Lagrange coefficient)

		// Create a list of x-coordinates
		x1 := scalarFromUint64(grp, 1)
		x2 := scalarFromUint64(grp, 2)
		x3 := scalarFromUint64(grp, 3)

		xCoords := []group.Scalar{x1, x2, x3}

		// Compute Lagrange coefficient for x1
		lambda1, err := polyHelper.DeriveInterpolatingValue(xCoords, x1)
		if err != nil {
			t.Fatalf("DeriveInterpolatingValue failed: %v", err)
		}

		if lambda1 == nil {
			t.Fatal("Interpolating value should not be nil")
		}
	})

	t.Run("InterpolationErrorConditions", func(t *testing.T) {
		// RFC 9591 Section 4.2: derive_interpolating_value raises error if:
		// 1) x_i is not in L, or
		// 2) any x-coordinate is represented more than once in L

		x1 := scalarFromUint64(grp, 1)
		x2 := scalarFromUint64(grp, 2)
		x3 := scalarFromUint64(grp, 3)
		x4 := scalarFromUint64(grp, 4)

		// Test 1: x_i not in L
		xCoords := []group.Scalar{x1, x2, x3}
		_, err := polyHelper.DeriveInterpolatingValue(xCoords, x4)
		if err == nil {
			t.Error("Should error when x_i is not in list")
		}

		// Test 2: Duplicate x-coordinate in L
		duplicateCoords := []group.Scalar{x1, x2, x2, x3}
		_, err = polyHelper.DeriveInterpolatingValue(duplicateCoords, x1)
		if err == nil {
			t.Error("Should error when list contains duplicate x-coordinates")
		}
	})
}

// TestSection4_3_ListOperations tests RFC 9591 Section 4.3
// list operation requirements
func TestSection4_3_ListOperations(t *testing.T) {
	// RFC 9591 Section 4.3: List Operations
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("EncodeGroupCommitmentList", func(t *testing.T) {
		// RFC 9591 Section 4.3: encode_group_commitment_list encodes a list of
		// participant commitments into a byte string

		// Create commitments for 3 participants
		commitments := make(frost.CommitmentList, 3)
		for i := 0; i < 3; i++ {
			hidingNonce, _ := grp.RandomScalar()
			bindingNonce, _ := grp.RandomScalar()

			commitments[i] = frost.SigningCommitments{
				Identifier:             frost.Identifier(i + 1),
				HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
				BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
			}
		}

		// RFC 9591 Section 4.3: List MUST be sorted in ascending order by identifier
		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		encoder := helpers.NewCommitmentListEncoder(grp)
		encoded, err := encoder.Encode(commitments)
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		if encoded == nil || len(encoded) == 0 {
			t.Fatal("Encoded commitment list should not be empty")
		}

		// Expected size: 3 * (Ns + Ne + Ne) where Ns is scalar length, Ne is element length
		expectedSize := 3 * (grp.ScalarLength() + 2*grp.ElementLength())
		if len(encoded) != expectedSize {
			t.Errorf("Expected encoded size %d, got %d", expectedSize, len(encoded))
		}
	})

	t.Run("ParticipantsFromCommitmentList", func(t *testing.T) {
		// RFC 9591 Section 4.3: participants_from_commitment_list extracts
		// identifiers from a commitment list

		commitments := make(frost.CommitmentList, 3)
		expectedIDs := []frost.Identifier{1, 2, 3}

		for i := 0; i < 3; i++ {
			hidingNonce, _ := grp.RandomScalar()
			bindingNonce, _ := grp.RandomScalar()

			commitments[i] = frost.SigningCommitments{
				Identifier:             expectedIDs[i],
				HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
				BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
			}
		}

		encoder := helpers.NewCommitmentListEncoder(grp)
		identifiers := encoder.GetParticipants(commitments)

		if len(identifiers) != len(expectedIDs) {
			t.Fatalf("Expected %d identifiers, got %d", len(expectedIDs), len(identifiers))
		}

		for i, id := range identifiers {
			if id != expectedIDs[i] {
				t.Errorf("Expected identifier %d at position %d, got %d", expectedIDs[i], i, id)
			}
		}
	})

	t.Run("BindingFactorForParticipant", func(t *testing.T) {
		// RFC 9591 Section 4.3: binding_factor_for_participant extracts a binding
		// factor for a specific participant

		bf1, _ := grp.RandomScalar()
		bf2, _ := grp.RandomScalar()
		bf3, _ := grp.RandomScalar()

		bindingFactors := frost.BindingFactorList{
			{Identifier: 1, BindingFactor: bf1},
			{Identifier: 2, BindingFactor: bf2},
			{Identifier: 3, BindingFactor: bf3},
		}

		bfComputer := helpers.NewBindingFactorComputer(suite)

		// Test successful lookup
		bf, err := bfComputer.GetBindingFactor(bindingFactors, 2)
		if err != nil {
			t.Fatalf("GetBindingFactor failed: %v", err)
		}

		if !bf.Equal(bindingFactors[1].BindingFactor) {
			t.Error("Retrieved binding factor does not match expected value")
		}

		// RFC 9591 Section 4.3: Raise error when participant is not known
		_, err = bfComputer.GetBindingFactor(bindingFactors, 99)
		if err == nil {
			t.Error("Should error for unknown participant")
		}
	})
}

// TestSection4_4_BindingFactors tests RFC 9591 Section 4.4
// binding factor computation requirements
func TestSection4_4_BindingFactors(t *testing.T) {
	// RFC 9591 Section 4.4: Binding Factors Computation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("ComputeBindingFactors", func(t *testing.T) {
		// RFC 9591 Section 4.4: compute_binding_factors computes binding factors
		// based on group public key, commitment list, and message

		// Setup
		groupSecret, _ := grp.RandomScalar()
		groupPublicKey := grp.ScalarBaseMult(groupSecret)

		commitments := make(frost.CommitmentList, 3)
		for i := 0; i < 3; i++ {
			h, _ := grp.RandomScalar()
			b, _ := grp.RandomScalar()

			commitments[i] = frost.SigningCommitments{
				Identifier:             frost.Identifier(i + 1),
				HidingNonceCommitment:  grp.ScalarBaseMult(h),
				BindingNonceCommitment: grp.ScalarBaseMult(b),
			}
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		message := []byte("test message")

		bfComputer := helpers.NewBindingFactorComputer(suite)
		bindingFactors, err := bfComputer.Compute(groupPublicKey, commitments, message)

		if err != nil {
			t.Fatalf("Compute failed: %v", err)
		}

		// Should return one binding factor per participant
		if len(bindingFactors) != len(commitments) {
			t.Errorf("Expected %d binding factors, got %d", len(commitments), len(bindingFactors))
		}

		// Each binding factor should be a valid scalar
		for i, bf := range bindingFactors {
			if bf.BindingFactor == nil {
				t.Errorf("Binding factor %d is nil", i)
			}

			// Verify it can be used in group operations
			element := grp.ScalarBaseMult(bf.BindingFactor)
			if element == nil {
				t.Errorf("Binding factor %d is not a valid scalar", i)
			}
		}
	})

	t.Run("BindingFactorDeterminism", func(t *testing.T) {
		// RFC 9591 Section 4.4: Binding factors should be deterministic
		// for the same inputs

		groupSecret, _ := grp.RandomScalar()
		groupPublicKey := grp.ScalarBaseMult(groupSecret)

		commitments := make(frost.CommitmentList, 2)
		for i := 0; i < 2; i++ {
			h, _ := grp.RandomScalar()
			b, _ := grp.RandomScalar()

			commitments[i] = frost.SigningCommitments{
				Identifier:             frost.Identifier(i + 1),
				HidingNonceCommitment:  grp.ScalarBaseMult(h),
				BindingNonceCommitment: grp.ScalarBaseMult(b),
			}
		}

		message := []byte("test message")

		bfComputer := helpers.NewBindingFactorComputer(suite)
		bf1, _ := bfComputer.Compute(groupPublicKey, commitments, message)
		bf2, _ := bfComputer.Compute(groupPublicKey, commitments, message)

		// Same inputs should produce same binding factors
		for i := 0; i < len(bf1); i++ {
			if !bf1[i].BindingFactor.Equal(bf2[i].BindingFactor) {
				t.Errorf("Binding factor %d differs between computations", i)
			}
		}
	})
}

// TestSection4_5_GroupCommitment tests RFC 9591 Section 4.5
// group commitment computation requirements
func TestSection4_5_GroupCommitment(t *testing.T) {
	// RFC 9591 Section 4.5: Group Commitment Computation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("ComputeGroupCommitment", func(t *testing.T) {
		// RFC 9591 Section 4.5: compute_group_commitment creates the group
		// commitment from a commitment list and binding factors

		// Setup commitments
		commitments := make(frost.CommitmentList, 3)
		for i := 0; i < 3; i++ {
			h, _ := grp.RandomScalar()
			b, _ := grp.RandomScalar()

			commitments[i] = frost.SigningCommitments{
				Identifier:             frost.Identifier(i + 1),
				HidingNonceCommitment:  grp.ScalarBaseMult(h),
				BindingNonceCommitment: grp.ScalarBaseMult(b),
			}
		}

		// Setup binding factors
		bindingFactors := make(frost.BindingFactorList, 3)
		for i := 0; i < 3; i++ {
			bf, _ := grp.RandomScalar()

			bindingFactors[i] = frost.BindingFactor{
				Identifier:    frost.Identifier(i + 1),
				BindingFactor: bf,
			}
		}

		gcComputer := helpers.NewGroupCommitmentComputer(grp)
		groupCommitment, err := gcComputer.Compute(commitments, bindingFactors)

		if err != nil {
			t.Fatalf("Compute failed: %v", err)
		}

		if groupCommitment == nil {
			t.Fatal("Group commitment should not be nil")
		}

		// RFC 9591 Section 4.5: Group commitment should not be identity
		if groupCommitment.Equal(grp.Identity()) {
			t.Error("Group commitment should not be identity element")
		}
	})

	t.Run("GroupCommitmentFormula", func(t *testing.T) {
		// RFC 9591 Section 4.5: group_commitment = sum of
		// (hiding_nonce_commitment + binding_factor * binding_nonce_commitment)

		// Create single commitment for testing
		hidingNonce, _ := grp.RandomScalar()
		bindingNonce, _ := grp.RandomScalar()
		bindingFactor, _ := grp.RandomScalar()

		hidingCommitment := grp.ScalarBaseMult(hidingNonce)
		bindingCommitment := grp.ScalarBaseMult(bindingNonce)

		commitments := frost.CommitmentList{
			{
				Identifier:             1,
				HidingNonceCommitment:  hidingCommitment,
				BindingNonceCommitment: bindingCommitment,
			},
		}

		bindingFactors := frost.BindingFactorList{
			{
				Identifier:    1,
				BindingFactor: bindingFactor,
			},
		}

		gcComputer := helpers.NewGroupCommitmentComputer(grp)
		groupCommitment, _ := gcComputer.Compute(commitments, bindingFactors)

		// Manually compute expected: hiding_commitment + (binding_factor * binding_commitment)
		expected := hidingCommitment.Add(grp.ScalarMult(bindingCommitment, bindingFactor))

		if !groupCommitment.Equal(expected) {
			t.Error("Group commitment does not match expected formula")
		}
	})
}

// TestSection4_6_SignatureChallenge tests RFC 9591 Section 4.6
// signature challenge computation requirements
func TestSection4_6_SignatureChallenge(t *testing.T) {
	// RFC 9591 Section 4.6: Signature Challenge Computation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("ComputeChallenge", func(t *testing.T) {
		// RFC 9591 Section 4.6: compute_challenge creates the per-message challenge

		gc, _ := grp.RandomScalar()
		gpk, _ := grp.RandomScalar()

		groupCommitment := grp.ScalarBaseMult(gc)
		groupPublicKey := grp.ScalarBaseMult(gpk)
		message := []byte("test message")

		challengeComputer := helpers.NewChallengeComputer(suite)
		challenge, err := challengeComputer.Compute(groupCommitment, groupPublicKey, message)

		if err != nil {
			t.Fatalf("Compute failed: %v", err)
		}

		if challenge == nil {
			t.Fatal("Challenge should not be nil")
		}

		// Challenge should be a valid scalar
		element := grp.ScalarBaseMult(challenge)
		if element == nil {
			t.Error("Challenge is not a valid scalar")
		}
	})

	t.Run("ChallengeDeterminism", func(t *testing.T) {
		// RFC 9591 Section 4.6: Challenge should be deterministic for same inputs

		gc, _ := grp.RandomScalar()
		gpk, _ := grp.RandomScalar()

		groupCommitment := grp.ScalarBaseMult(gc)
		groupPublicKey := grp.ScalarBaseMult(gpk)
		message := []byte("test message")

		challengeComputer := helpers.NewChallengeComputer(suite)
		challenge1, _ := challengeComputer.Compute(groupCommitment, groupPublicKey, message)
		challenge2, _ := challengeComputer.Compute(groupCommitment, groupPublicKey, message)

		if !challenge1.Equal(challenge2) {
			t.Error("Challenge should be deterministic for same inputs")
		}
	})

	t.Run("ChallengeInputDependence", func(t *testing.T) {
		// RFC 9591 Section 4.6: Challenge depends on group_commitment, group_public_key, and msg

		gc1, _ := grp.RandomScalar()
		gc2, _ := grp.RandomScalar()
		gpk, _ := grp.RandomScalar()

		groupCommitment1 := grp.ScalarBaseMult(gc1)
		groupCommitment2 := grp.ScalarBaseMult(gc2)
		groupPublicKey := grp.ScalarBaseMult(gpk)
		message := []byte("test message")

		challengeComputer := helpers.NewChallengeComputer(suite)

		// Different group commitment should produce different challenge
		c1, _ := challengeComputer.Compute(groupCommitment1, groupPublicKey, message)
		c2, _ := challengeComputer.Compute(groupCommitment2, groupPublicKey, message)

		if c1.Equal(c2) {
			t.Error("Different group commitments should produce different challenges")
		}
	})

	t.Run("ChallengeUsesH2", func(t *testing.T) {
		// RFC 9591 Section 4.6: challenge = H2(group_comm_enc || group_public_key_enc || msg)

		gc, _ := grp.RandomScalar()
		gpk, _ := grp.RandomScalar()

		groupCommitment := grp.ScalarBaseMult(gc)
		groupPublicKey := grp.ScalarBaseMult(gpk)
		message := []byte("test message")

		challengeComputer := helpers.NewChallengeComputer(suite)
		challenge, _ := challengeComputer.Compute(groupCommitment, groupPublicKey, message)

		// Manually compute using H2
		input := append(groupCommitment.Bytes(), groupPublicKey.Bytes()...)
		input = append(input, message...)
		expectedChallenge := suite.H2(input)

		if !challenge.Equal(expectedChallenge) {
			t.Error("Challenge does not match H2 computation")
		}
	})
}
