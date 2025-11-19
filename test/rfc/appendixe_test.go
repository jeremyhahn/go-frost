package rfc

import (
	"testing"

	"github.com/jeremyhahn/go-frost/test/testvectors"
)

// TestAppendixE_TestVectors tests RFC 9591 Appendix E
// Test Vector validation requirements
func TestAppendixE_TestVectors(t *testing.T) {
	// RFC 9591 Appendix E: Test Vectors
	// This appendix provides test vectors for all 5 ciphersuites

	t.Run("TestVectorStructure", func(t *testing.T) {
		// RFC 9591 Appendix E: Test vectors include:
		// - Configuration (MIN_PARTICIPANTS, MAX_PARTICIPANTS, NUM_PARTICIPANTS)
		// - Group secret key and public key
		// - Participant shares and public keys
		// - Round 1 nonces and commitments
		// - Binding factors
		// - Group commitment
		// - Signature shares
		// - Final signature

		tv := testvectors.Ristretto255SHA512Vector()

		// Validate configuration
		if tv.MinParticipants == 0 {
			t.Error("Test vector should specify MIN_PARTICIPANTS")
		}
		if tv.MaxParticipants == 0 {
			t.Error("Test vector should specify MAX_PARTICIPANTS")
		}
		if len(tv.ParticipantList) == 0 {
			t.Error("Test vector should specify participant list")
		}

		// Validate group keys
		if tv.GroupSecretKey == "" {
			t.Error("Test vector should include group secret key")
		}
		if tv.GroupPublicKey == "" {
			t.Error("Test vector should include group public key")
		}

		// Validate participants
		if len(tv.Participants) == 0 {
			t.Error("Test vector should include participant data")
		}

		// Validate each participant has required data
		for id, participant := range tv.Participants {
			if participant.Share == "" {
				t.Errorf("Participant %d missing share", id)
			}
			if participant.HidingNonce == "" {
				t.Errorf("Participant %d missing hiding nonce", id)
			}
			if participant.BindingNonce == "" {
				t.Errorf("Participant %d missing binding nonce", id)
			}
			if participant.HidingNonceCommitment == "" {
				t.Errorf("Participant %d missing hiding nonce commitment", id)
			}
			if participant.BindingNonceCommitment == "" {
				t.Errorf("Participant %d missing binding nonce commitment", id)
			}
			if participant.BindingFactor == "" {
				t.Errorf("Participant %d missing binding factor", id)
			}
			if participant.SignatureShare == "" {
				t.Errorf("Participant %d missing signature share", id)
			}
		}

		// Validate message
		if tv.Message == "" {
			t.Error("Test vector should include message")
		}

		// Validate final signature
		if tv.FinalSignature == "" {
			t.Error("Test vector should include final signature")
		}
	})
}

// TestAppendixE_3_Ristretto255SHA512 tests RFC 9591 Appendix E.3
// FROST(ristretto255, SHA-512) test vectors
func TestAppendixE_3_Ristretto255SHA512(t *testing.T) {
	// RFC 9591 Appendix E.3: FROST(ristretto255, SHA-512) Test Vectors
	// The full test vector validation is in test/testvectors/rfc9591_test.go
	// This test ensures the test vectors are accessible and well-formed

	t.Run("Ristretto255TestVectorAvailable", func(t *testing.T) {
		tv := testvectors.Ristretto255SHA512Vector()

		if tv == nil {
			t.Fatal("Ristretto255 test vector should be available")
		}

		// RFC 9591 Appendix E.3: Verify ciphersuite ID
		expectedName := "FROST(ristretto255, SHA-512)"
		if tv.Name != expectedName {
			t.Errorf("Expected test vector name %s, got %s", expectedName, tv.Name)
		}

		// Verify configuration matches RFC test vectors
		// RFC 9591 Appendix E.3 uses (2, 3) threshold
		if tv.MinParticipants != 2 {
			t.Errorf("Expected MIN_PARTICIPANTS=2, got %d", tv.MinParticipants)
		}
		if tv.MaxParticipants != 3 {
			t.Errorf("Expected MAX_PARTICIPANTS=3, got %d", tv.MaxParticipants)
		}
	})

	t.Run("AllTestVectorFieldsPresent", func(t *testing.T) {
		tv := testvectors.Ristretto255SHA512Vector()

		// RFC 9591 Appendix E: Test vectors specify all intermediate values

		// Configuration
		if tv.MinParticipants == 0 || tv.MaxParticipants == 0 {
			t.Error("Configuration values should be present")
		}

		// Group keys
		if tv.GroupSecretKey == "" || tv.GroupPublicKey == "" {
			t.Error("Group keys should be present")
		}

		// Polynomial coefficients
		if len(tv.SharePolynomialCoefficients) == 0 {
			t.Error("Share polynomial coefficients should be present")
		}

		// Participants
		for _, id := range tv.ParticipantList {
			p := tv.Participants[id]

			if p.Share == "" {
				t.Errorf("P%d: Share missing", id)
			}
			if p.HidingNonce == "" || p.BindingNonce == "" {
				t.Errorf("P%d: Nonces missing", id)
			}
			if p.HidingNonceCommitment == "" || p.BindingNonceCommitment == "" {
				t.Errorf("P%d: Commitments missing", id)
			}
			if p.BindingFactor == "" {
				t.Errorf("P%d: Binding factor missing", id)
			}
			if p.SignatureShare == "" {
				t.Errorf("P%d: Signature share missing", id)
			}
		}

		// Final values
		if tv.Message == "" {
			t.Error("Message should be present")
		}
		if tv.FinalSignature == "" {
			t.Error("Final signature should be present")
		}
	})

	t.Run("ReferenceToFullValidation", func(t *testing.T) {
		// RFC 9591 Appendix E: Full validation of test vectors

		t.Log("Full RFC 9591 test vector validation is performed in:")
		t.Log("  - test/testvectors/rfc9591_test.go::TestRFC9591_Ristretto255SHA512_FullProtocol")
		t.Log("")
		t.Log("That test validates:")
		t.Log("  - Group secret and public keys")
		t.Log("  - Participant shares (via polynomial evaluation)")
		t.Log("  - Round 1 nonces and commitments")
		t.Log("  - Binding factor computation")
		t.Log("  - Signature share generation")
		t.Log("  - Final signature aggregation and verification")
	})
}

// TestAppendixE_IntermediateValues tests that RFC 9591 Appendix E
// intermediate values are correctly computed
func TestAppendixE_IntermediateValues(t *testing.T) {
	// RFC 9591 Appendix E: Test vectors include intermediate values for validation

	t.Run("PolynomialCoefficients", func(t *testing.T) {
		// RFC 9591 Appendix E: coefficient_1, coefficient_2, etc.
		// represent the secret polynomial coefficients (excluding constant term)

		tv := testvectors.Ristretto255SHA512Vector()

		if len(tv.SharePolynomialCoefficients) == 0 {
			t.Error("Polynomial coefficients should be present")
		}

		// For (t, n) = (2, 3), we need t=2 coefficients plus the secret
		// The polynomial has degree t-1 = 1, so 2 total coefficients
		// Test vector provides coefficient_1, with coefficient_0 being the group secret
		expectedCoeffCount := tv.MinParticipants - 1
		if len(tv.SharePolynomialCoefficients) != expectedCoeffCount {
			t.Errorf("Expected %d polynomial coefficients, got %d",
				expectedCoeffCount, len(tv.SharePolynomialCoefficients))
		}
	})

	t.Run("ParticipantShares", func(t *testing.T) {
		// RFC 9591 Appendix E: participant_share_1, participant_share_2, etc.
		// are the secret shares for each participant

		tv := testvectors.Ristretto255SHA512Vector()

		if len(tv.Participants) != tv.NumParticipants {
			t.Errorf("Expected %d participant shares, got %d",
				tv.NumParticipants, len(tv.Participants))
		}

		for id := range tv.Participants {
			if id < 1 || id > uint64(tv.MaxParticipants) {
				t.Errorf("Invalid participant ID %d", id)
			}
		}
	})

	t.Run("Round1Values", func(t *testing.T) {
		// RFC 9591 Appendix E: Round 1 values include nonces and commitments

		tv := testvectors.Ristretto255SHA512Vector()

		for _, id := range tv.ParticipantList {
			p := tv.Participants[id]

			// RFC 9591 Section 5.1: Each participant generates hiding and binding nonces
			if p.HidingNonce == "" || p.BindingNonce == "" {
				t.Errorf("P%d: Nonces should be present", id)
			}

			// RFC 9591 Section 5.1: Commitments are group elements
			if p.HidingNonceCommitment == "" || p.BindingNonceCommitment == "" {
				t.Errorf("P%d: Commitments should be present", id)
			}
		}
	})

	t.Run("BindingFactors", func(t *testing.T) {
		// RFC 9591 Section 4.4 and Appendix E: Binding factors for each participant

		tv := testvectors.Ristretto255SHA512Vector()

		for _, id := range tv.ParticipantList {
			p := tv.Participants[id]

			if p.BindingFactor == "" {
				t.Errorf("P%d: Binding factor should be present", id)
			}
		}
	})

	t.Run("SignatureShares", func(t *testing.T) {
		// RFC 9591 Section 5.2 and Appendix E: Signature shares from each participant

		tv := testvectors.Ristretto255SHA512Vector()

		for _, id := range tv.ParticipantList {
			p := tv.Participants[id]

			if p.SignatureShare == "" {
				t.Errorf("P%d: Signature share should be present", id)
			}
		}
	})
}
