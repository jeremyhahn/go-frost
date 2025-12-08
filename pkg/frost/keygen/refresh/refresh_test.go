package refresh

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/dkg"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestRefresh_Ed25519 tests key refresh with Ed25519
func TestRefresh_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	testRefresh(t, suite)
}

// TestRefresh_Ristretto255 tests key refresh with Ristretto255
func TestRefresh_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	testRefresh(t, suite)
}

// TestRefresh_P256 tests key refresh with P-256
func TestRefresh_P256(t *testing.T) {
	suite := p256_sha256.New()
	testRefresh(t, suite)
}

func testRefresh(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Generate initial keys using trusted dealer
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	originalGroupPublicKey := keyPackages[0].GroupPublicKey

	// Create public key package for refresh
	verifyingShares := make(map[frost.Identifier]frost.VerificationShare)
	for _, vs := range publicKeyPackage.VerificationShares {
		verifyingShares[vs.Identifier] = vs
	}

	dkgPublicKeyPackage := &dkg.PublicKeyPackage{
		VerifyingKey:    publicKeyPackage.GroupPublicKey,
		VerifyingShares: make(map[frost.Identifier]group.Element),
	}
	for _, vs := range publicKeyPackage.VerificationShares {
		dkgPublicKeyPackage.VerifyingShares[vs.Identifier] = vs.VerificationKey
	}

	// Generate refresh shares
	refreshShares, newPublicKeyPackage, err := ComputeRefreshingShares(
		dkgPublicKeyPackage,
		maxSigners,
		minSigners,
		identifiers,
		suite,
	)
	if err != nil {
		t.Fatalf("failed to compute refresh shares: %v", err)
	}

	// Verify that the group public key remains unchanged
	if !newPublicKeyPackage.VerifyingKey.Equal(originalGroupPublicKey) {
		t.Error("group public key changed after refresh")
	}

	// Apply refresh shares to each participant
	refreshedKeyPackages := make([]*frost.KeyPackage, len(keyPackages))
	for i, kp := range keyPackages {
		// Find the refresh share for this participant
		var refreshShare RefreshShare
		for _, rs := range refreshShares {
			if rs.Identifier == kp.Identifier {
				refreshShare = rs
				break
			}
		}

		refreshedKP, err := ApplyRefreshShare(refreshShare, kp, suite)
		if err != nil {
			t.Fatalf("failed to apply refresh share for participant %v: %v", kp.Identifier, err)
		}
		refreshedKeyPackages[i] = refreshedKP
	}

	// Verify all refreshed key packages have the same group public key
	for _, kp := range refreshedKeyPackages {
		if !kp.GroupPublicKey.Equal(originalGroupPublicKey) {
			t.Errorf("participant %v has different group public key after refresh", kp.Identifier)
		}
	}

	// Verify refreshed shares are different from original shares
	for i, originalKP := range keyPackages {
		refreshedKP := refreshedKeyPackages[i]
		if originalKP.SecretShare.Equal(refreshedKP.SecretShare) {
			t.Errorf("participant %v share unchanged after refresh", originalKP.Identifier)
		}
	}

	// Verify that the refreshed keys can produce valid signatures
	message := []byte("test message after key refresh")

	// Generate nonces and commitments
	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range refreshedKeyPackages[:minSigners] {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("failed to generate nonces: %v", err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	// Generate signature shares
	signatureShares := make(map[frost.Identifier]*signing.SignatureShare)
	for _, kp := range refreshedKeyPackages[:minSigners] {
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

	// Aggregate and verify signature
	verificationSharesMap := make(map[frost.Identifier]frost.VerificationShare)
	for id, vs := range newPublicKeyPackage.VerifyingShares {
		verificationSharesMap[id] = frost.VerificationShare{
			Identifier:      id,
			VerificationKey: vs,
		}
	}

	signature, err := signing.Aggregate(
		message,
		commitments,
		signatureShares,
		verificationSharesMap,
		newPublicKeyPackage.VerifyingKey,
		suite,
	)
	if err != nil {
		t.Fatalf("failed to aggregate signature: %v", err)
	}

	err = signing.VerifySignature(message, signature, newPublicKeyPackage.VerifyingKey, suite)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestRefresh_MultipleRounds tests multiple consecutive refresh operations
func TestRefresh_MultipleRounds(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(3)
	minSigners := uint32(2)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("failed to generate initial keys: %v", err)
	}

	originalGroupPublicKey := keyPackages[0].GroupPublicKey

	// Create DKG public key package
	dkgPublicKeyPackage := &dkg.PublicKeyPackage{
		VerifyingKey:    publicKeyPackage.GroupPublicKey,
		VerifyingShares: make(map[frost.Identifier]group.Element),
	}
	for _, vs := range publicKeyPackage.VerificationShares {
		dkgPublicKeyPackage.VerifyingShares[vs.Identifier] = vs.VerificationKey
	}

	currentKeyPackages := keyPackages
	currentPublicKeyPackage := dkgPublicKeyPackage

	// Perform 5 consecutive refreshes
	for round := 1; round <= 5; round++ {
		refreshShares, newPublicKeyPackage, err := ComputeRefreshingShares(
			currentPublicKeyPackage,
			maxSigners,
			minSigners,
			identifiers,
			suite,
		)
		if err != nil {
			t.Fatalf("refresh round %d: failed to compute refresh shares: %v", round, err)
		}

		// Apply refresh shares
		newKeyPackages := make([]*frost.KeyPackage, len(currentKeyPackages))
		for i, kp := range currentKeyPackages {
			var refreshShare RefreshShare
			for _, rs := range refreshShares {
				if rs.Identifier == kp.Identifier {
					refreshShare = rs
					break
				}
			}

			refreshedKP, err := ApplyRefreshShare(refreshShare, kp, suite)
			if err != nil {
				t.Fatalf("refresh round %d: failed to apply refresh share: %v", round, err)
			}
			newKeyPackages[i] = refreshedKP
		}

		// Verify group public key is unchanged
		if !newPublicKeyPackage.VerifyingKey.Equal(originalGroupPublicKey) {
			t.Errorf("refresh round %d: group public key changed", round)
		}

		currentKeyPackages = newKeyPackages
		currentPublicKeyPackage = newPublicKeyPackage
	}

	// Verify final keys can still sign
	message := []byte("message after 5 refresh rounds")

	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range currentKeyPackages[:minSigners] {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("failed to generate nonces: %v", err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	signatureShares := make(map[frost.Identifier]*signing.SignatureShare)
	for _, kp := range currentKeyPackages[:minSigners] {
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

	verificationSharesMap := make(map[frost.Identifier]frost.VerificationShare)
	for id, vs := range currentPublicKeyPackage.VerifyingShares {
		verificationSharesMap[id] = frost.VerificationShare{
			Identifier:      id,
			VerificationKey: vs,
		}
	}

	signature, err := signing.Aggregate(
		message,
		commitments,
		signatureShares,
		verificationSharesMap,
		currentPublicKeyPackage.VerifyingKey,
		suite,
	)
	if err != nil {
		t.Fatalf("failed to aggregate signature: %v", err)
	}

	err = signing.VerifySignature(message, signature, currentPublicKeyPackage.VerifyingKey, suite)
	if err != nil {
		t.Errorf("signature verification failed after multiple refreshes: %v", err)
	}
}

// TestRefresh_InvalidParameters tests error handling for invalid parameters
func TestRefresh_InvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()

	// Test nil public key package
	_, _, err := ComputeRefreshingShares(nil, 3, 2, []frost.Identifier{1, 2, 3}, suite)
	if err == nil {
		t.Error("expected error for nil public key package")
	}

	// Test empty identifiers
	dkgPkp := &dkg.PublicKeyPackage{
		VerifyingKey:    suite.Group().Identity(),
		VerifyingShares: map[frost.Identifier]group.Element{},
	}
	_, _, err = ComputeRefreshingShares(dkgPkp, 3, 2, []frost.Identifier{}, suite)
	if err == nil {
		t.Error("expected error for empty identifiers")
	}

	// Test minSigners < 2
	_, _, err = ComputeRefreshingShares(dkgPkp, 3, 1, []frost.Identifier{1, 2, 3}, suite)
	if err == nil {
		t.Error("expected error for minSigners < 2")
	}

	// Test minSigners > maxSigners
	_, _, err = ComputeRefreshingShares(dkgPkp, 2, 3, []frost.Identifier{1, 2}, suite)
	if err == nil {
		t.Error("expected error for minSigners > maxSigners")
	}
}

// TestApplyRefreshShare_InvalidParameters tests error handling for ApplyRefreshShare
func TestApplyRefreshShare_InvalidParameters(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	// Test nil key package
	share, _ := grp.RandomScalar()
	refreshShare := RefreshShare{
		Identifier: frost.Identifier(1),
		Share:      share,
		Commitment: []group.Element{},
	}
	_, err := ApplyRefreshShare(refreshShare, nil, suite)
	if err == nil {
		t.Error("expected error for nil key package")
	}

	// Test nil share
	kp := &frost.KeyPackage{
		Identifier:  frost.Identifier(1),
		SecretShare: share,
	}
	refreshShare.Share = nil
	_, err = ApplyRefreshShare(refreshShare, kp, suite)
	if err == nil {
		t.Error("expected error for nil share")
	}

	// Test identifier mismatch
	refreshShare.Share = share
	refreshShare.Identifier = frost.Identifier(2) // Different from key package
	_, err = ApplyRefreshShare(refreshShare, kp, suite)
	if err == nil {
		t.Error("expected error for identifier mismatch")
	}
}

// TestRefresh_DifferentThresholds tests refresh with various configurations
func TestRefresh_DifferentThresholds(t *testing.T) {
	suite := ed25519_sha512.New()

	testCases := []struct {
		maxSigners uint32
		minSigners uint32
	}{
		{2, 2},
		{3, 2},
		{5, 3},
		{7, 4},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			identifiers := make([]frost.Identifier, tc.maxSigners)
			for i := uint32(0); i < tc.maxSigners; i++ {
				identifiers[i] = frost.Identifier(i + 1)
			}

			keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(tc.maxSigners, tc.minSigners, identifiers, suite)
			if err != nil {
				t.Fatalf("failed to generate initial keys: %v", err)
			}

			dkgPublicKeyPackage := &dkg.PublicKeyPackage{
				VerifyingKey:    publicKeyPackage.GroupPublicKey,
				VerifyingShares: make(map[frost.Identifier]group.Element),
			}
			for _, vs := range publicKeyPackage.VerificationShares {
				dkgPublicKeyPackage.VerifyingShares[vs.Identifier] = vs.VerificationKey
			}

			refreshShares, _, err := ComputeRefreshingShares(
				dkgPublicKeyPackage,
				tc.maxSigners,
				tc.minSigners,
				identifiers,
				suite,
			)
			if err != nil {
				t.Fatalf("failed to compute refresh shares: %v", err)
			}

			if len(refreshShares) != int(tc.maxSigners) {
				t.Errorf("wrong number of refresh shares: got %d, want %d", len(refreshShares), tc.maxSigners)
			}

			// Apply and verify at least one
			for _, kp := range keyPackages {
				var rs RefreshShare
				for _, r := range refreshShares {
					if r.Identifier == kp.Identifier {
						rs = r
						break
					}
				}
				_, err := ApplyRefreshShare(rs, kp, suite)
				if err != nil {
					t.Fatalf("failed to apply refresh share: %v", err)
				}
			}
		})
	}
}

// TestRefreshShare_Zeroize tests that Zeroize securely erases the refresh share.
func TestRefreshShare_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	scalar, _ := grp.RandomScalar()
	rs := &RefreshShare{
		Identifier: frost.Identifier(1),
		Share:      scalar,
		Commitment: []group.Element{grp.Generator()},
	}

	// Verify the share is not zero before zeroizing
	if rs.Share.IsZero() {
		t.Fatal("Share should not be zero before Zeroize")
	}

	rs.Zeroize()

	// After zeroizing, the scalar should be zero
	if !rs.Share.IsZero() {
		t.Error("Share should be zero after Zeroize")
	}
}

// TestRefreshShare_Zeroize_NilShare tests Zeroize with nil share.
func TestRefreshShare_Zeroize_NilShare(t *testing.T) {
	rs := &RefreshShare{
		Identifier: frost.Identifier(1),
		Share:      nil,
	}

	// Should not panic
	rs.Zeroize()
}
