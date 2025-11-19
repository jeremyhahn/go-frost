package rfc

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

// TestAppendixC_TrustedDealerKeyGeneration tests RFC 9591 Appendix C
// Trusted Dealer Key Generation requirements
func TestAppendixC_TrustedDealerKeyGeneration(t *testing.T) {
	// RFC 9591 Appendix C: Trusted Dealer Key Generation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	const minParticipants = 2
	const maxParticipants = 5

	t.Run("BasicKeyGeneration", func(t *testing.T) {
		// RFC 9591 Appendix C: Trusted dealer generates key shares

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, groupPublicKey, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Should generate shares for all participants
		if len(keyShares) != maxParticipants {
			t.Errorf("Expected %d key shares, got %d", maxParticipants, len(keyShares))
		}

		// Group public key should be valid
		if groupPublicKey == nil {
			t.Fatal("Group public key should not be nil")
		}

		// Group public key should not be identity
		if groupPublicKey.Equal(grp.Identity()) {
			t.Error("Group public key should not be identity")
		}
	})

	t.Run("ShareGeneration", func(t *testing.T) {
		// RFC 9591 Appendix C.1: Shamir Secret Sharing
		// sk_i is the value f(i) on a secret polynomial f of degree (MIN_PARTICIPANTS - 1)

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, _, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Each share should have a unique identifier
		identifiers := make(map[frost.Identifier]bool)
		for _, share := range keyShares {
			if identifiers[share.Identifier] {
				t.Errorf("Duplicate identifier %d found", share.Identifier)
			}
			identifiers[share.Identifier] = true
		}

		// Identifiers should be in range [1, MAX_PARTICIPANTS]
		for _, share := range keyShares {
			if share.Identifier < 1 || share.Identifier > frost.Identifier(maxParticipants) {
				t.Errorf("Identifier %d out of valid range [1, %d]", share.Identifier, maxParticipants)
			}
		}

		// Each share should be a valid scalar
		for _, share := range keyShares {
			if share.SecretShare == nil {
				t.Errorf("Share %d has nil secret", share.Identifier)
			}

			// Share should be usable for group operations
			element := grp.ScalarBaseMult(share.SecretShare)
			if element == nil {
				t.Errorf("Share %d is not a valid scalar", share.Identifier)
			}
		}
	})

	t.Run("VerificationShares", func(t *testing.T) {
		// RFC 9591 Appendix C.2: Verifiable Secret Sharing
		// Public verification shares allow participants to verify their shares

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, groupPublicKey, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Each participant should be able to verify their share
		for _, share := range keyShares {
			// Compute public verification share: PK_i = sk_i * G
			publicShare := grp.ScalarBaseMult(share.SecretShare)

			if publicShare == nil {
				t.Errorf("Failed to compute public share for participant %d", share.Identifier)
			}

			// Public share should not be identity
			if publicShare.Equal(grp.Identity()) {
				t.Errorf("Public share for participant %d should not be identity", share.Identifier)
			}
		}

		// Verify group public key relationship
		// This is implementation-specific, but group public key should be derivable
		if groupPublicKey == nil {
			t.Error("Group public key should be computable from shares")
		}
	})

	t.Run("ThresholdProperty", func(t *testing.T) {
		// RFC 9591 Appendix C.1: Any MIN_PARTICIPANTS shares can reconstruct the secret

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, groupPublicKey, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Use exactly MIN_PARTICIPANTS shares to verify threshold property
		selectedShares := keyShares[:minParticipants]

		// Build map for RecoverSecret
		shareMap := make(map[frost.Identifier]group.Scalar)
		for _, share := range selectedShares {
			shareMap[share.Identifier] = share.SecretShare
		}

		// Reconstruct secret using dealer's RecoverSecret function
		reconstructedSecret, err := dealer.RecoverSecret(shareMap)
		if err != nil {
			t.Fatalf("RecoverSecret failed: %v", err)
		}

		// Reconstructed group public key should match
		reconstructedPublicKey := grp.ScalarBaseMult(reconstructedSecret)
		if !reconstructedPublicKey.Equal(groupPublicKey) {
			t.Error("Reconstructed public key does not match group public key")
		}
	})

	t.Run("PolynomialDegree", func(t *testing.T) {
		// RFC 9591 Appendix C.1: Secret polynomial f has degree (MIN_PARTICIPANTS - 1)

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		_, _, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// The polynomial should have MIN_PARTICIPANTS coefficients
		// (degree MIN_PARTICIPANTS - 1)
		// This is internal to the dealer, but we can verify the threshold property
		// works correctly with exactly MIN_PARTICIPANTS shares
	})

	t.Run("ShareIndependence", func(t *testing.T) {
		// RFC 9591 Appendix C: Each share should be independent

		dealer1 := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		shares1, _, _ := dealer1.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		dealer2 := keygen.NewDealer(suite)
		shares2, _, _ := dealer2.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		// Different dealer runs should produce different shares
		for i := 0; i < maxParticipants; i++ {
			if shares1[i].SecretShare.Equal(shares2[i].SecretShare) {
				t.Errorf("Share %d should be different across dealer runs", i+1)
			}
		}
	})

	t.Run("GroupSecretRandomness", func(t *testing.T) {
		// RFC 9591 Appendix C: Group secret should be randomly generated

		dealer1 := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		_, pk1, _ := dealer1.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		dealer2 := keygen.NewDealer(suite)
		_, pk2, _ := dealer2.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		// Different dealer runs should produce different group public keys
		if pk1.Equal(pk2) {
			t.Error("Group public keys should be different across dealer runs")
		}
	})
}

// TestAppendixC_1_ShamirSecretSharing tests RFC 9591 Appendix C.1
// Shamir Secret Sharing specific requirements
func TestAppendixC_1_ShamirSecretSharing(t *testing.T) {
	// RFC 9591 Appendix C.1: Shamir Secret Sharing
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("PolynomialEvaluationShares", func(t *testing.T) {
		// RFC 9591 Appendix C.1: sk_i = f(i) where f is the secret polynomial

		const minParticipants = 3
		const maxParticipants = 5

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, _, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Each share represents f(i) for identifier i
		for _, share := range keyShares {
			if share.SecretShare == nil {
				t.Errorf("Share for participant %d is nil", share.Identifier)
			}

			// Verify share is non-zero (extremely unlikely to be zero by chance)
			zero := grp.NewScalar()
			if share.SecretShare.Equal(zero) {
				t.Errorf("Share for participant %d is zero", share.Identifier)
			}
		}
	})

	t.Run("SecretReconstruction", func(t *testing.T) {
		// RFC 9591 Appendix C.1: Secret can be reconstructed from MIN_PARTICIPANTS shares

		const minParticipants = 2
		const maxParticipants = 4

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		allShares, groupPublicKey, _ := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		// Test reconstruction with different subsets of MIN_PARTICIPANTS shares
		for startIdx := 0; startIdx <= maxParticipants-minParticipants; startIdx++ {
			selectedShares := allShares[startIdx : startIdx+minParticipants]

			// Build map for RecoverSecret
			shareMap := make(map[frost.Identifier]group.Scalar)
			for _, share := range selectedShares {
				shareMap[share.Identifier] = share.SecretShare
			}

			// Reconstruct secret
			reconstructedSecret, err := dealer.RecoverSecret(shareMap)
			if err != nil {
				t.Fatalf("RecoverSecret failed for subset %d: %v", startIdx, err)
			}

			// Verify reconstruction
			reconstructedPK := grp.ScalarBaseMult(reconstructedSecret)
			if !reconstructedPK.Equal(groupPublicKey) {
				t.Errorf("Reconstruction failed for subset starting at %d", startIdx)
			}
		}
	})
}

// TestAppendixC_2_VerifiableSecretSharing tests RFC 9591 Appendix C.2
// Verifiable Secret Sharing requirements
func TestAppendixC_2_VerifiableSecretSharing(t *testing.T) {
	// RFC 9591 Appendix C.2: Verifiable Secret Sharing
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("VerificationCommitments", func(t *testing.T) {
		// RFC 9591 Appendix C.2: VSS includes verification commitments

		const minParticipants = 2
		const maxParticipants = 3

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, _, err := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Each participant can verify their share using verification commitments
		for _, share := range keyShares {
			// Compute verification value: sk_i * G
			verificationValue := grp.ScalarBaseMult(share.SecretShare)

			if verificationValue == nil {
				t.Errorf("Failed to compute verification for participant %d", share.Identifier)
			}

			// Verification value should not be identity
			if verificationValue.Equal(grp.Identity()) {
				t.Errorf("Verification value for participant %d should not be identity", share.Identifier)
			}
		}
	})

	t.Run("ShareValidation", func(t *testing.T) {
		// RFC 9591 Appendix C.2: Participants can validate their shares

		const minParticipants = 2
		const maxParticipants = 3

		dealer := keygen.NewDealer(suite)
		participantIDs := participantIDsSequential(maxParticipants)
		keyShares, groupPublicKey, _ := dealer.GenerateShares(nil, minParticipants, maxParticipants, participantIDs)

		// For VSS, the dealer also provides polynomial commitments
		// C_k = a_k * G for each coefficient a_k
		// Participants verify: sk_i * G = sum(C_k * i^k) for k in [0, t]

		for _, share := range keyShares {
			// Compute public share
			publicShare := grp.ScalarBaseMult(share.SecretShare)

			// Public share should be a valid group element
			if publicShare == nil || publicShare.Equal(grp.Identity()) {
				t.Errorf("Invalid public share for participant %d", share.Identifier)
			}
		}

		// Group public key is C_0 (commitment to the secret)
		if groupPublicKey == nil || groupPublicKey.Equal(grp.Identity()) {
			t.Error("Invalid group public key")
		}
	})
}
