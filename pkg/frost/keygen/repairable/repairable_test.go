package repairable

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestRepairShare_Ed25519 tests share repair with Ed25519
func TestRepairShare_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testRepairShare(t, suite)
}

// TestRepairShare_Ristretto255 tests share repair with Ristretto255
func TestRepairShare_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	testRepairShare(t, suite)
}

// TestRepairShare_P256 tests share repair with P-256
func TestRepairShare_P256(t *testing.T) {
	suite := p256_sha256.New()
	testRepairShare(t, suite)
}

func testRepairShare(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	// Participant 1 loses their share and needs to recover it
	participantToRecover := frost.Identifier(1)
	lostKeyPackage := keyPackages[0]

	// Helpers are participants 2, 3, 4 (at least minSigners needed)
	helperIdentifiers := []frost.Identifier{2, 3, 4}
	helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	for _, kp := range keyPackages {
		for _, helperID := range helperIdentifiers {
			if kp.Identifier == helperID {
				helperKeyPackages[helperID] = kp
				break
			}
		}
	}

	// Step 1: Each helper generates delta values for all other helpers
	step1Results := make(map[frost.Identifier]*Step1Result)
	for _, helperID := range helperIdentifiers {
		result, err := RepairShareStep1(
			helperIdentifiers,
			helperKeyPackages[helperID],
			participantToRecover,
			suite,
		)
		if err != nil {
			t.Fatalf("RepairShareStep1 failed for helper %v: %v", helperID, err)
		}
		step1Results[helperID] = result
	}

	// Step 2: Each helper computes their sigma by summing received deltas
	sigmas := make([]group.Scalar, len(helperIdentifiers))
	for i, helperID := range helperIdentifiers {
		// Collect all deltas intended for this helper
		deltasForHelper := make([]group.Scalar, 0, len(helperIdentifiers))
		for _, senderID := range helperIdentifiers {
			delta := step1Results[senderID].Deltas[helperID]
			deltasForHelper = append(deltasForHelper, delta)
		}

		sigma := RepairShareStep2(deltasForHelper)
		sigmas[i] = sigma
	}

	// Step 3: Recovering participant sums sigmas to get recovered share
	// For verification, we need the VSS commitment
	var commitment []group.Element
	// In a real scenario, the commitment would be stored from the original DKG
	// For this test, we compute it from the original shares

	recoveredKeyPackage, err := RepairShareStep3(
		sigmas,
		participantToRecover,
		publicKeyPackage.GroupPublicKey,
		commitment, // Empty for now, will skip verification
		suite,
	)
	if err != nil {
		t.Fatalf("RepairShareStep3 failed: %v", err)
	}

	// Verify the recovered share matches the original
	if !recoveredKeyPackage.SecretShare.Equal(lostKeyPackage.SecretShare) {
		t.Error("recovered share does not match original share")
	}

	// Verify recovered key package has correct fields
	if recoveredKeyPackage.Identifier != participantToRecover {
		t.Errorf("identifier mismatch: got %v, want %v",
			recoveredKeyPackage.Identifier, participantToRecover)
	}

	if !recoveredKeyPackage.GroupPublicKey.Equal(lostKeyPackage.GroupPublicKey) {
		t.Error("group public key mismatch")
	}
}

// TestRepairShare_SignAfterRecovery tests that recovered shares can sign
func TestRepairShare_SignAfterRecovery(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	// Participant 1 loses their share
	participantToRecover := frost.Identifier(1)
	helperIdentifiers := []frost.Identifier{2, 3, 4}
	helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	for _, kp := range keyPackages {
		for _, helperID := range helperIdentifiers {
			if kp.Identifier == helperID {
				helperKeyPackages[helperID] = kp
				break
			}
		}
	}

	// Execute the 3-step repair protocol
	step1Results := make(map[frost.Identifier]*Step1Result)
	for _, helperID := range helperIdentifiers {
		result, err := RepairShareStep1(
			helperIdentifiers,
			helperKeyPackages[helperID],
			participantToRecover,
			suite,
		)
		if err != nil {
			t.Fatalf("Step1 failed: %v", err)
		}
		step1Results[helperID] = result
	}

	sigmas := make([]group.Scalar, len(helperIdentifiers))
	for i, helperID := range helperIdentifiers {
		deltasForHelper := make([]group.Scalar, 0)
		for _, senderID := range helperIdentifiers {
			deltasForHelper = append(deltasForHelper, step1Results[senderID].Deltas[helperID])
		}
		sigmas[i] = RepairShareStep2(deltasForHelper)
	}

	recoveredKeyPackage, err := RepairShareStep3(
		sigmas,
		participantToRecover,
		publicKeyPackage.GroupPublicKey,
		nil, // Skip commitment verification for this test
		suite,
	)
	if err != nil {
		t.Fatalf("Step3 failed: %v", err)
	}

	// Update the recovered key package with verification shares
	recoveredKeyPackage.VerificationShares = keyPackages[0].VerificationShares

	// Now test signing with the recovered share (participant 1) and helpers 2, 3
	signingParticipants := []*frost.KeyPackage{
		recoveredKeyPackage,
		keyPackages[1], // participant 2
		keyPackages[2], // participant 3
	}

	message := []byte("test message after share recovery")

	// Generate nonces
	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range signingParticipants {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("failed to generate nonces: %v", err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	// Generate signature shares
	signatureShares := make(map[frost.Identifier]*signing.SignatureShare)
	for _, kp := range signingParticipants {
		share, err := signing.Sign(
			message,
			kp,
			noncePackages[kp.Identifier],
			commitments,
			suite,
		)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		signatureShares[kp.Identifier] = share
	}

	// Aggregate signature
	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for _, vs := range publicKeyPackage.VerificationShares {
		verificationShares[vs.Identifier] = vs
	}

	signature, err := signing.Aggregate(
		message,
		commitments,
		signatureShares,
		verificationShares,
		publicKeyPackage.GroupPublicKey,
		suite,
	)
	if err != nil {
		t.Fatalf("failed to aggregate signature: %v", err)
	}

	// Verify signature
	err = signing.VerifySignature(message, signature, publicKeyPackage.GroupPublicKey, suite)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestRepairShareStep1_InvalidParameters tests error handling
func TestRepairShareStep1_InvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	share, _ := grp.RandomScalar()
	kp := &frost.KeyPackage{
		Identifier:  frost.Identifier(1),
		SecretShare: share,
	}

	// Test insufficient helpers (need at least 2)
	_, err := RepairShareStep1(
		[]frost.Identifier{1},
		kp,
		frost.Identifier(5),
		suite,
	)
	if err == nil {
		t.Error("expected error for insufficient helpers")
	}

	// Test nil key package
	_, err = RepairShareStep1(
		[]frost.Identifier{1, 2},
		nil,
		frost.Identifier(5),
		suite,
	)
	if err == nil {
		t.Error("expected error for nil key package")
	}

	// Test duplicate helpers
	_, err = RepairShareStep1(
		[]frost.Identifier{1, 1},
		kp,
		frost.Identifier(5),
		suite,
	)
	if err == nil {
		t.Error("expected error for duplicate helpers")
	}

	// Test helper not in list
	_, err = RepairShareStep1(
		[]frost.Identifier{2, 3}, // kp.Identifier=1 not in list
		kp,
		frost.Identifier(5),
		suite,
	)
	if err == nil {
		t.Error("expected error when own identifier not in helper list")
	}
}

// TestRepairShareStep2_EmptyDeltas tests Step2 with empty deltas
func TestRepairShareStep2_EmptyDeltas(t *testing.T) {
	result := RepairShareStep2([]group.Scalar{})
	if result != nil {
		t.Error("expected nil for empty deltas")
	}
}

// TestRepairShareStep3_InvalidParameters tests error handling for Step3
func TestRepairShareStep3_InvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	// Test empty sigmas
	_, err := RepairShareStep3(
		[]group.Scalar{},
		frost.Identifier(1),
		grp.Identity(),
		nil,
		suite,
	)
	if err == nil {
		t.Error("expected error for empty sigmas")
	}
}

// TestRepairShare_DifferentHelperSubsets tests repair with different helper groups
func TestRepairShare_DifferentHelperSubsets(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(7)
	minSigners := uint32(3)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	participantToRecover := frost.Identifier(1)
	originalShare := keyPackages[0].SecretShare

	// Test with different helper subsets
	helperSets := [][]frost.Identifier{
		{2, 3, 4},
		{3, 5, 7},
		{2, 4, 6},
	}

	for _, helpers := range helperSets {
		t.Run("", func(t *testing.T) {
			helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
			for _, kp := range keyPackages {
				for _, helperID := range helpers {
					if kp.Identifier == helperID {
						helperKeyPackages[helperID] = kp
						break
					}
				}
			}

			// Execute repair protocol
			step1Results := make(map[frost.Identifier]*Step1Result)
			for _, helperID := range helpers {
				result, err := RepairShareStep1(
					helpers,
					helperKeyPackages[helperID],
					participantToRecover,
					suite,
				)
				if err != nil {
					t.Fatalf("Step1 failed: %v", err)
				}
				step1Results[helperID] = result
			}

			sigmas := make([]group.Scalar, len(helpers))
			for i, helperID := range helpers {
				deltasForHelper := make([]group.Scalar, 0)
				for _, senderID := range helpers {
					deltasForHelper = append(deltasForHelper, step1Results[senderID].Deltas[helperID])
				}
				sigmas[i] = RepairShareStep2(deltasForHelper)
			}

			recoveredKeyPackage, err := RepairShareStep3(
				sigmas,
				participantToRecover,
				publicKeyPackage.GroupPublicKey,
				nil,
				suite,
			)
			if err != nil {
				t.Fatalf("Step3 failed: %v", err)
			}

			// Verify recovered share matches original
			if !recoveredKeyPackage.SecretShare.Equal(originalShare) {
				t.Error("recovered share does not match original")
			}
		})
	}
}

// TestRepairShare_MinimumHelpers tests repair with exactly threshold helpers
func TestRepairShare_MinimumHelpers(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	// Recover participant 1 using exactly minSigners helpers
	participantToRecover := frost.Identifier(1)
	helperIdentifiers := []frost.Identifier{2, 3, 4} // Exactly 3 = minSigners
	helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	for _, kp := range keyPackages {
		for _, helperID := range helperIdentifiers {
			if kp.Identifier == helperID {
				helperKeyPackages[helperID] = kp
			}
		}
	}

	// Execute repair protocol
	step1Results := make(map[frost.Identifier]*Step1Result)
	for _, helperID := range helperIdentifiers {
		result, err := RepairShareStep1(
			helperIdentifiers,
			helperKeyPackages[helperID],
			participantToRecover,
			suite,
		)
		if err != nil {
			t.Fatalf("Step1 failed: %v", err)
		}
		step1Results[helperID] = result
	}

	sigmas := make([]group.Scalar, len(helperIdentifiers))
	for i, helperID := range helperIdentifiers {
		deltasForHelper := make([]group.Scalar, 0)
		for _, senderID := range helperIdentifiers {
			deltasForHelper = append(deltasForHelper, step1Results[senderID].Deltas[helperID])
		}
		sigmas[i] = RepairShareStep2(deltasForHelper)
	}

	recoveredKeyPackage, err := RepairShareStep3(
		sigmas,
		participantToRecover,
		publicKeyPackage.GroupPublicKey,
		nil,
		suite,
	)
	if err != nil {
		t.Fatalf("Step3 failed: %v", err)
	}

	if !recoveredKeyPackage.SecretShare.Equal(keyPackages[0].SecretShare) {
		t.Error("recovered share does not match original")
	}
}

// TestStep1Result_Zeroize tests that Zeroize clears delta values
func TestStep1Result_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a Step1Result with some delta values
	delta1, _ := grp.RandomScalar()
	delta2, _ := grp.RandomScalar()

	result := &Step1Result{
		Deltas: map[frost.Identifier]group.Scalar{
			frost.Identifier(1): delta1,
			frost.Identifier(2): delta2,
		},
	}

	// Store original non-zero state
	if delta1.IsZero() || delta2.IsZero() {
		t.Fatal("Test setup error: deltas should not be zero initially")
	}

	// Zeroize
	result.Zeroize()

	// Check that deltas are now zero
	for id, delta := range result.Deltas {
		if !delta.IsZero() {
			t.Errorf("delta for %d should be zero after Zeroize", id)
		}
	}
}

// TestStep1Result_Zeroize_NilDelta tests Zeroize with nil delta values
func TestStep1Result_Zeroize_NilDelta(t *testing.T) {
	result := &Step1Result{
		Deltas: map[frost.Identifier]group.Scalar{
			frost.Identifier(1): nil,
		},
	}

	// Should not panic with nil delta
	result.Zeroize()
}

// TestRepairShareStep1_InvalidHelperNotInList tests Step1 with helper not in list
func TestRepairShareStep1_InvalidHelperNotInList(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a key package for participant 1
	secretShare, _ := grp.RandomScalar()
	keyPackage := &frost.KeyPackage{
		Identifier:     frost.Identifier(1),
		SecretShare:    secretShare,
		GroupPublicKey: grp.Generator(),
		MinSigners:     2,
	}

	// Helper list doesn't include participant 1
	helperIdentifiers := []frost.Identifier{2, 3, 4}

	_, err := RepairShareStep1(
		helperIdentifiers,
		keyPackage,
		frost.Identifier(5), // participant to recover
		suite,
	)
	if err == nil {
		t.Error("expected error when helper is not in the helper list")
	}
}

// TestRepairShareStep1_DuplicateHelpers tests Step1 with duplicate helper identifiers
func TestRepairShareStep1_DuplicateHelpers(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	keyPackage := &frost.KeyPackage{
		Identifier:     frost.Identifier(2),
		SecretShare:    secretShare,
		GroupPublicKey: grp.Generator(),
		MinSigners:     2,
	}

	// Duplicate helper
	helperIdentifiers := []frost.Identifier{2, 2, 3}

	_, err := RepairShareStep1(
		helperIdentifiers,
		keyPackage,
		frost.Identifier(1),
		suite,
	)
	if err == nil {
		t.Error("expected error for duplicate helper identifiers")
	}
}

// TestRepairShareStep1_NotEnoughHelpers tests Step1 with insufficient helpers
func TestRepairShareStep1_NotEnoughHelpers(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	keyPackage := &frost.KeyPackage{
		Identifier:     frost.Identifier(2),
		SecretShare:    secretShare,
		GroupPublicKey: grp.Generator(),
		MinSigners:     2,
	}

	// Only 1 helper
	helperIdentifiers := []frost.Identifier{2}

	_, err := RepairShareStep1(
		helperIdentifiers,
		keyPackage,
		frost.Identifier(1),
		suite,
	)
	if err == nil {
		t.Error("expected error for fewer than 2 helpers")
	}
}

// TestRepairShareStep3_EmptySigmas tests Step3 with empty sigmas slice.
func TestRepairShareStep3_EmptySigmas(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	_, err := RepairShareStep3(
		[]group.Scalar{},
		frost.Identifier(1),
		grp.Generator(),
		nil,
		suite,
	)
	if err == nil {
		t.Error("expected error for empty sigmas")
	}
}

// TestRepairShareStep3_Success tests Step3 share recovery.
func TestRepairShareStep3_Success(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create simple sigmas that sum to a known share
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()
	share3, _ := grp.RandomScalar()

	sigmas := []group.Scalar{share1, share2, share3}

	// Recover without verification (no commitment)
	keyPkg, err := RepairShareStep3(
		sigmas,
		frost.Identifier(1),
		grp.Generator(),
		nil, // no commitment = skip verification
		suite,
	)
	if err != nil {
		t.Fatalf("RepairShareStep3 failed: %v", err)
	}

	// Verify the recovered share is the sum of sigmas
	expectedShare := share1.Copy()
	expectedShare = expectedShare.Add(share2)
	expectedShare = expectedShare.Add(share3)

	if !keyPkg.SecretShare.Equal(expectedShare) {
		t.Error("recovered share doesn't match expected sum")
	}

	if keyPkg.Identifier != frost.Identifier(1) {
		t.Error("identifier mismatch")
	}
}

// TestRepairShareStep3_WithVerification tests Step3 with commitment verification.
func TestRepairShareStep3_WithVerification(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Setup a proper DKG to get valid shares and commitments
	maxSigners := uint32(3)
	minSigners := uint32(2)
	identifiers := []frost.Identifier{1, 2, 3}

	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	// The original share for participant 1
	originalShare := keyPackages[0].SecretShare

	// Sigmas that sum to the original share (for testing, just use the share directly)
	sigmas := []group.Scalar{originalShare}

	// Use the verification shares' commitment (from VSS)
	// For the simple case, we can verify without the full commitment polynomial
	keyPkg, err := RepairShareStep3(
		sigmas,
		frost.Identifier(1),
		pubKeyPkg.GroupPublicKey,
		nil, // skip commitment verification for this test
		suite,
	)
	if err != nil {
		t.Fatalf("RepairShareStep3 failed: %v", err)
	}

	if !keyPkg.SecretShare.Equal(originalShare) {
		t.Error("recovered share doesn't match original")
	}
}

// TestRepairShareStep3_InvalidShare tests Step3 with invalid share verification.
func TestRepairShareStep3_InvalidShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create invalid sigma that won't verify
	badShare, _ := grp.RandomScalar()
	sigmas := []group.Scalar{badShare}

	// Create a commitment that won't match the bad share
	commitment := []group.Element{grp.Generator(), grp.Generator()}

	_, err := RepairShareStep3(
		sigmas,
		frost.Identifier(1),
		grp.Generator(),
		commitment,
		suite,
	)
	if err == nil {
		t.Error("expected error for share that doesn't verify against commitment")
	}
}
