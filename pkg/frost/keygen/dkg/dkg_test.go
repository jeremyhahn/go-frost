package dkg

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestDKGRound1_Ed25519 tests round 1 of DKG with Ed25519
func TestDKGRound1_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testDKGRound1(t, suite)
}

// TestDKGRound1_Ristretto255 tests round 1 of DKG with Ristretto255
func TestDKGRound1_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	testDKGRound1(t, suite)
}

// TestDKGRound1_P256 tests round 1 of DKG with P-256
func TestDKGRound1_P256(t *testing.T) {
	suite := p256_sha256.New()
	testDKGRound1(t, suite)
}

func testDKGRound1(t *testing.T, suite ciphersuite.Ciphersuite) {
	id := frost.Identifier(1)
	maxSigners := uint32(3)
	minSigners := uint32(2)

	secretPkg, publicPkg, err := Part1(id, maxSigners, minSigners, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}

	// Verify secret package fields
	if secretPkg.Identifier != id {
		t.Errorf("identifier mismatch: got %v, want %v", secretPkg.Identifier, id)
	}
	if len(secretPkg.Coefficients) != int(minSigners) {
		t.Errorf("coefficient count: got %d, want %d", len(secretPkg.Coefficients), minSigners)
	}
	if len(secretPkg.Commitment) != int(minSigners) {
		t.Errorf("commitment count: got %d, want %d", len(secretPkg.Commitment), minSigners)
	}

	// Verify public package fields
	if len(publicPkg.Commitment) != int(minSigners) {
		t.Errorf("public commitment count mismatch")
	}
	if publicPkg.ProofOfKnowledge.R == nil || publicPkg.ProofOfKnowledge.Z == nil {
		t.Error("proof of knowledge components are nil")
	}
}

// TestDKGRound1_InvalidParameters tests error handling for invalid parameters
func TestDKGRound1_InvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()

	// Test minSigners < 2
	_, _, err := Part1(frost.Identifier(1), 3, 1, suite)
	if err == nil {
		t.Error("expected error for minSigners < 2")
	}

	// Test minSigners > maxSigners
	_, _, err = Part1(frost.Identifier(1), 2, 3, suite)
	if err == nil {
		t.Error("expected error for minSigners > maxSigners")
	}
}

// TestDKGRound2_Ed25519 tests round 2 of DKG
func TestDKGRound2_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testDKGRound2(t, suite)
}

func testDKGRound2(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Run Part1 for all participants
	secretPackages := make(map[frost.Identifier]*Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("Part1 failed for participant %d: %v", i, err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	// Run Part2 for participant 1
	id1 := frost.Identifier(1)
	round1ForP1 := make(map[frost.Identifier]*Round1Package)
	for id, pkg := range publicPackages {
		if id != id1 {
			round1ForP1[id] = pkg
		}
	}

	round2SecretPkg, round2Packages, err := Part2(secretPackages[id1], round1ForP1, suite)
	if err != nil {
		t.Fatalf("Part2 failed: %v", err)
	}

	// Verify round 2 secret package
	if round2SecretPkg.Identifier != id1 {
		t.Errorf("identifier mismatch")
	}
	if round2SecretPkg.SecretShare == nil {
		t.Error("secret share is nil")
	}

	// Verify round 2 packages for other participants
	if len(round2Packages) != int(maxSigners-1) {
		t.Errorf("wrong number of round 2 packages: got %d, want %d", len(round2Packages), maxSigners-1)
	}

	for peerID, pkg := range round2Packages {
		if peerID == id1 {
			t.Error("round 2 package should not include self")
		}
		if pkg.SigningShare == nil {
			t.Errorf("signing share for %v is nil", peerID)
		}
	}
}

// TestDKGRound2_InvalidProof tests that Part2 rejects invalid proofs of knowledge
func TestDKGRound2_InvalidProof(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Run Part1 for all participants
	secretPackages := make(map[frost.Identifier]*Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("Part1 failed for participant %d: %v", i, err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	// Corrupt the proof of knowledge for participant 2
	randomZ, _ := grp.RandomScalar()
	publicPackages[frost.Identifier(2)].ProofOfKnowledge.Z = randomZ

	// Part2 should fail
	id1 := frost.Identifier(1)
	round1ForP1 := make(map[frost.Identifier]*Round1Package)
	for id, pkg := range publicPackages {
		if id != id1 {
			round1ForP1[id] = pkg
		}
	}

	_, _, err := Part2(secretPackages[id1], round1ForP1, suite)
	if err == nil {
		t.Error("expected error for invalid proof of knowledge")
	}
}

// TestDKGRound3_Ed25519 tests round 3 of DKG
func TestDKGRound3_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testDKGRound3(t, suite)
}

func testDKGRound3(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Complete DKG for all participants
	keyPackages, publicKeyPkg := completeDKG(t, maxSigners, minSigners, suite)

	// Verify key packages
	if len(keyPackages) != int(maxSigners) {
		t.Errorf("wrong number of key packages: got %d, want %d", len(keyPackages), maxSigners)
	}

	// Verify all participants have the same group public key
	groupPublicKey := publicKeyPkg.VerifyingKey
	for id, kp := range keyPackages {
		if !kp.GroupPublicKey.Equal(groupPublicKey) {
			t.Errorf("participant %v has different group public key", id)
		}
	}

	// Verify each participant's verifying share matches
	for id, kp := range keyPackages {
		expectedVerifyingShare := suite.Group().ScalarBaseMult(kp.SecretShare)
		actualVerifyingShare := publicKeyPkg.VerifyingShares[id]
		if !expectedVerifyingShare.Equal(actualVerifyingShare) {
			t.Errorf("verifying share mismatch for participant %v", id)
		}
	}
}

// TestDKGRound3_InvalidShare tests that Part3 rejects invalid shares
func TestDKGRound3_InvalidShare(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Run Part1 for all participants
	secretPackages := make(map[frost.Identifier]*Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("Part1 failed for participant %d: %v", i, err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	// Run Part2 for all participants
	round2SecretPackages := make(map[frost.Identifier]*Round2SecretPackage)
	round2Packages := make(map[frost.Identifier]map[frost.Identifier]*Round2Package)

	for id, secretPkg := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		r2SecretPkg, r2Pkgs, err := Part2(secretPkg, round1ForParticipant, suite)
		if err != nil {
			t.Fatalf("Part2 failed for participant %v: %v", id, err)
		}
		round2SecretPackages[id] = r2SecretPkg
		round2Packages[id] = r2Pkgs
	}

	// Collect round 2 packages for participant 1, but corrupt one
	id1 := frost.Identifier(1)
	round1ForP1 := make(map[frost.Identifier]*Round1Package)
	round2ForP1 := make(map[frost.Identifier]*Round2Package)

	for id, pkg := range publicPackages {
		if id != id1 {
			round1ForP1[id] = pkg
		}
	}

	for senderId, packages := range round2Packages {
		if senderId != id1 {
			round2ForP1[senderId] = packages[id1]
		}
	}

	// Corrupt participant 2's share to participant 1
	corruptedShare, _ := grp.RandomScalar()
	round2ForP1[frost.Identifier(2)].SigningShare = corruptedShare

	// Part3 should fail due to invalid share
	_, _, err := Part3(round2SecretPackages[id1], round1ForP1, round2ForP1, suite)
	if err == nil {
		t.Error("expected error for invalid share")
	}
}

// TestDKGFullProtocol_Ed25519 tests the complete DKG protocol
func TestDKGFullProtocol_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testDKGFullProtocol(t, suite)
}

// TestDKGFullProtocol_Ristretto255 tests the complete DKG protocol with Ristretto255
func TestDKGFullProtocol_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	testDKGFullProtocol(t, suite)
}

// TestDKGFullProtocol_P256 tests the complete DKG protocol with P-256
func TestDKGFullProtocol_P256(t *testing.T) {
	suite := p256_sha256.New()
	testDKGFullProtocol(t, suite)
}

func testDKGFullProtocol(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(5)
	minSigners := uint32(3)

	keyPackages, publicKeyPkg := completeDKG(t, maxSigners, minSigners, suite)

	// Test that the generated keys can produce valid signatures
	message := []byte("test message for DKG-generated keys")

	// Select first minSigners participants for signing
	signingParticipants := make([]*frost.KeyPackage, 0, minSigners)
	for _, kp := range keyPackages {
		signingParticipants = append(signingParticipants, kp)
		if uint32(len(signingParticipants)) >= minSigners {
			break
		}
	}

	// Round 1: Generate nonces and commitments
	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range signingParticipants {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("failed to generate nonces for %v: %v", kp.Identifier, err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	// Round 2: Generate signature shares
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
			t.Fatalf("failed to sign for %v: %v", kp.Identifier, err)
		}
		signatureShares[kp.Identifier] = share
	}

	// Aggregate signature
	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for id, vs := range publicKeyPkg.VerifyingShares {
		verificationShares[id] = frost.VerificationShare{
			Identifier:      id,
			VerificationKey: vs,
		}
	}

	signature, err := signing.Aggregate(
		message,
		commitments,
		signatureShares,
		verificationShares,
		publicKeyPkg.VerifyingKey,
		suite,
	)
	if err != nil {
		t.Fatalf("failed to aggregate signature: %v", err)
	}

	// Verify signature
	err = signing.VerifySignature(message, signature, publicKeyPkg.VerifyingKey, suite)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestDKGDifferentThresholds tests DKG with various threshold configurations
func TestDKGDifferentThresholds(t *testing.T) {
	suite := ed25519_sha512.New()

	testCases := []struct {
		maxSigners uint32
		minSigners uint32
	}{
		{2, 2},
		{3, 2},
		{5, 3},
		{7, 4},
		{10, 7},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			keyPackages, publicKeyPkg := completeDKG(t, tc.maxSigners, tc.minSigners, suite)

			if len(keyPackages) != int(tc.maxSigners) {
				t.Errorf("wrong number of key packages")
			}

			if len(publicKeyPkg.VerifyingShares) != int(tc.maxSigners) {
				t.Errorf("wrong number of verifying shares")
			}
		})
	}
}

// TestVerifyProofOfKnowledge tests the proof of knowledge verification
func TestVerifyProofOfKnowledge(t *testing.T) {
	suite := ed25519_sha512.New()

	id := frost.Identifier(1)
	_, publicPkg, err := Part1(id, 3, 2, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}

	// Verification should pass
	err = VerifyProofOfKnowledge(id, publicPkg, suite)
	if err != nil {
		t.Errorf("proof verification failed: %v", err)
	}
}

// TestVerifyShare tests share verification
func TestVerifyShare(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Run Part1 for participant 1
	id1 := frost.Identifier(1)
	secretPkg1, publicPkg1, err := Part1(id1, maxSigners, minSigners, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}

	// Generate share for participant 2
	id2 := frost.Identifier(2)
	_, publicPkg2, err := Part1(id2, maxSigners, minSigners, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}

	// Create round 1 packages map for Part2
	round1Pkgs := map[frost.Identifier]*Round1Package{
		id2: publicPkg2,
	}

	// Need to also add participant 3 for a valid Part2 call
	id3 := frost.Identifier(3)
	_, publicPkg3, err := Part1(id3, maxSigners, minSigners, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}
	round1Pkgs[id3] = publicPkg3

	// Run Part2 for participant 1
	_, round2Pkgs, err := Part2(secretPkg1, round1Pkgs, suite)
	if err != nil {
		t.Fatalf("Part2 failed: %v", err)
	}

	// Verify the share for participant 2
	share := round2Pkgs[id2].SigningShare
	err = VerifyShare(id2, share, publicPkg1.Commitment, suite)
	if err != nil {
		t.Errorf("share verification failed: %v", err)
	}

	// Verify the share for participant 3
	share3 := round2Pkgs[id3].SigningShare
	err = VerifyShare(id3, share3, publicPkg1.Commitment, suite)
	if err != nil {
		t.Errorf("share verification failed for p3: %v", err)
	}
}

// completeDKG runs the complete DKG protocol for all participants
func completeDKG(t *testing.T, maxSigners, minSigners uint32, suite ciphersuite.Ciphersuite) (
	map[frost.Identifier]*frost.KeyPackage, *PublicKeyPackage) {
	// Run Part1 for all participants
	secretPackages := make(map[frost.Identifier]*Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("Part1 failed for participant %d: %v", i, err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	// Run Part2 for all participants
	round2SecretPackages := make(map[frost.Identifier]*Round2SecretPackage)
	round2Packages := make(map[frost.Identifier]map[frost.Identifier]*Round2Package)

	for id, secretPkg := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		r2SecretPkg, r2Pkgs, err := Part2(secretPkg, round1ForParticipant, suite)
		if err != nil {
			t.Fatalf("Part2 failed for participant %v: %v", id, err)
		}
		round2SecretPackages[id] = r2SecretPkg
		round2Packages[id] = r2Pkgs
	}

	// Run Part3 for all participants
	keyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	var publicKeyPackage *PublicKeyPackage

	for id := range secretPackages {
		// Collect round 1 packages from others
		round1ForParticipant := make(map[frost.Identifier]*Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		// Collect round 2 packages intended for this participant
		round2ForParticipant := make(map[frost.Identifier]*Round2Package)
		for senderId, packages := range round2Packages {
			if senderId != id {
				round2ForParticipant[senderId] = packages[id]
			}
		}

		keyPkg, pubKeyPkg, err := Part3(round2SecretPackages[id], round1ForParticipant, round2ForParticipant, suite)
		if err != nil {
			t.Fatalf("Part3 failed for participant %v: %v", id, err)
		}
		keyPackages[id] = keyPkg
		publicKeyPackage = pubKeyPkg
	}

	return keyPackages, publicKeyPackage
}

// TestRound2Package_Zeroize tests that Round2Package.Zeroize securely erases the signing share.
func TestRound2Package_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	scalar, _ := grp.RandomScalar()
	pkg := &Round2Package{
		SigningShare: scalar,
	}

	// Verify the share is not zero before zeroizing
	if pkg.SigningShare.IsZero() {
		t.Fatal("SigningShare should not be zero before Zeroize")
	}

	pkg.Zeroize()

	// After zeroizing, the scalar should be zero
	if !pkg.SigningShare.IsZero() {
		t.Error("SigningShare should be zero after Zeroize")
	}
}

// TestRound2Package_Zeroize_NilSigningShare tests Zeroize with nil SigningShare.
func TestRound2Package_Zeroize_NilSigningShare(t *testing.T) {
	pkg := &Round2Package{
		SigningShare: nil,
	}

	// Should not panic
	pkg.Zeroize()
}

// TestRound1SecretPackage_Zeroize tests that Round1SecretPackage.Zeroize securely erases coefficients.
func TestRound1SecretPackage_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a secret package with coefficients
	coeffs := make([]group.Scalar, 3)
	for i := range coeffs {
		coeffs[i], _ = grp.RandomScalar()
	}

	pkg := &Round1SecretPackage{
		Identifier:   frost.Identifier(1),
		Coefficients: coeffs,
		MinSigners:   2,
		MaxSigners:   3,
	}

	// Verify coefficients are not zero before zeroizing
	for i, c := range pkg.Coefficients {
		if c.IsZero() {
			t.Fatalf("Coefficient %d should not be zero before Zeroize", i)
		}
	}

	pkg.Zeroize()

	// After zeroizing, all coefficients should be zero
	for i, c := range pkg.Coefficients {
		if !c.IsZero() {
			t.Errorf("Coefficient %d should be zero after Zeroize", i)
		}
	}
}

// TestRound1SecretPackage_Zeroize_NilCoefficient tests Zeroize with nil coefficient.
func TestRound1SecretPackage_Zeroize_NilCoefficient(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	scalar, _ := grp.RandomScalar()
	pkg := &Round1SecretPackage{
		Identifier:   frost.Identifier(1),
		Coefficients: []group.Scalar{scalar, nil, scalar},
		MinSigners:   2,
		MaxSigners:   3,
	}

	// Should not panic
	pkg.Zeroize()
}

// TestRound2SecretPackage_Zeroize tests that Round2SecretPackage.Zeroize securely erases the secret share.
func TestRound2SecretPackage_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	scalar, _ := grp.RandomScalar()
	pkg := &Round2SecretPackage{
		Identifier:  frost.Identifier(1),
		SecretShare: scalar,
		MinSigners:  2,
		MaxSigners:  3,
	}

	// Verify the share is not zero before zeroizing
	if pkg.SecretShare.IsZero() {
		t.Fatal("SecretShare should not be zero before Zeroize")
	}

	pkg.Zeroize()

	// After zeroizing, the scalar should be zero
	if !pkg.SecretShare.IsZero() {
		t.Error("SecretShare should be zero after Zeroize")
	}
}

// TestRound2SecretPackage_Zeroize_NilSecretShare tests Zeroize with nil SecretShare.
func TestRound2SecretPackage_Zeroize_NilSecretShare(t *testing.T) {
	pkg := &Round2SecretPackage{
		Identifier:  frost.Identifier(1),
		SecretShare: nil,
		MinSigners:  2,
		MaxSigners:  3,
	}

	// Should not panic
	pkg.Zeroize()
}

// TestPart1_MaxSignersLessThanMinSigners tests Part1 validation error.
func TestPart1_MaxSignersLessThanMinSigners(t *testing.T) {
	suite := ristretto255_sha512.New()

	_, _, err := Part1(frost.Identifier(1), 2, 3, suite)
	if err == nil {
		t.Error("Expected error when maxSigners < minSigners")
	}
}

// TestPart1_MinSignersZero tests Part1 validation error.
func TestPart1_MinSignersZero(t *testing.T) {
	suite := ristretto255_sha512.New()

	_, _, err := Part1(frost.Identifier(1), 3, 0, suite)
	if err == nil {
		t.Error("Expected error when minSigners is 0")
	}
}

// TestPart2_MissingRound1Packages tests Part2 with missing packages.
func TestPart2_MissingRound1Packages(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Run Part1 for participant 1
	secretPkg, _, err := Part1(frost.Identifier(1), 3, 2, suite)
	if err != nil {
		t.Fatalf("Part1 failed: %v", err)
	}

	// Try Part2 with empty round1 packages (missing n-1 participants)
	_, _, err = Part2(secretPkg, map[frost.Identifier]*Round1Package{}, suite)
	if err == nil {
		t.Error("Expected error when round1 packages are missing")
	}
}

// TestVerifyShare_EmptyCommitment tests VerifyShare with empty commitment.
func TestVerifyShare_EmptyCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	share, _ := grp.RandomScalar()
	err := VerifyShare(frost.Identifier(1), share, []group.Element{}, suite)
	if err == nil {
		t.Error("Expected error with empty commitment")
	}
}

// TestVerifyShare_NilShare tests VerifyShare with nil share.
func TestVerifyShare_NilShare(t *testing.T) {
	suite := ristretto255_sha512.New()

	commitment := []group.Element{suite.Group().Generator()}
	err := VerifyShare(frost.Identifier(1), nil, commitment, suite)
	if err == nil {
		t.Error("Expected error with nil share")
	}
}

// TestVerifyProofOfKnowledge_NilR tests proof verification with nil R.
func TestVerifyProofOfKnowledge_NilR(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	pkg := &Round1Package{
		Commitment: []group.Element{grp.Generator()},
		ProofOfKnowledge: Signature{
			R: nil,
			Z: grp.NewScalar(),
		},
	}
	err := VerifyProofOfKnowledge(frost.Identifier(1), pkg, suite)
	if err == nil {
		t.Error("Expected error with nil R in proof")
	}
}

// TestVerifyProofOfKnowledge_NilZ tests proof verification with nil Z.
func TestVerifyProofOfKnowledge_NilZ(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	pkg := &Round1Package{
		Commitment: []group.Element{grp.Generator()},
		ProofOfKnowledge: Signature{
			R: grp.Generator(),
			Z: nil,
		},
	}
	err := VerifyProofOfKnowledge(frost.Identifier(1), pkg, suite)
	if err == nil {
		t.Error("Expected error with nil Z in proof")
	}
}

// TestVerifyProofOfKnowledge_NilPackage tests proof verification with nil package.
func TestVerifyProofOfKnowledge_NilPackage(t *testing.T) {
	suite := ristretto255_sha512.New()

	err := VerifyProofOfKnowledge(frost.Identifier(1), nil, suite)
	if err == nil {
		t.Error("Expected error with nil package")
	}
}

// TestVerifyProofOfKnowledge_EmptyCommitment tests proof verification with empty commitment.
func TestVerifyProofOfKnowledge_EmptyCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	pkg := &Round1Package{
		Commitment: []group.Element{},
		ProofOfKnowledge: Signature{
			R: grp.Generator(),
			Z: grp.NewScalar(),
		},
	}
	err := VerifyProofOfKnowledge(frost.Identifier(1), pkg, suite)
	if err == nil {
		t.Error("Expected error with empty commitment")
	}
}

// TestPart3_MismatchedRound1AndRound2Packages tests Part3 with mismatched packages.
func TestPart3_MismatchedRound1AndRound2Packages(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Run Part1 for participants
	secretPkg1, publicPkg1, _ := Part1(frost.Identifier(1), 3, 2, suite)
	_, publicPkg2, _ := Part1(frost.Identifier(2), 3, 2, suite)
	secretPkg3, publicPkg3, _ := Part1(frost.Identifier(3), 3, 2, suite)

	// Run Part2 for participant 1
	round1ForP1 := map[frost.Identifier]*Round1Package{
		frost.Identifier(2): publicPkg2,
		frost.Identifier(3): publicPkg3,
	}
	r2SecretPkg, _, _ := Part2(secretPkg1, round1ForP1, suite)

	// Run Part2 for participant 3 to get valid round2 packages
	round1ForP3 := map[frost.Identifier]*Round1Package{
		frost.Identifier(1): publicPkg1,
		frost.Identifier(2): publicPkg2,
	}
	_, r2PkgsP3, _ := Part2(secretPkg3, round1ForP3, suite)

	// Part3 for participant 1 - provide mismatched packages (wrong sender)
	round2ForP1 := map[frost.Identifier]*Round2Package{
		frost.Identifier(2): r2PkgsP3[frost.Identifier(1)], // Wrong share
	}

	_, _, err := Part3(r2SecretPkg, round1ForP1, round2ForP1, suite)
	if err == nil {
		t.Error("Expected error with mismatched round2 packages")
	}
}
