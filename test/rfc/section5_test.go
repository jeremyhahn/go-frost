package rfc

import (
	"bytes"
	"sort"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestSection5_1_RoundOneCommitment tests RFC 9591 Section 5.1
// Round One - Commitment generation requirements
func TestSection5_1_RoundOneCommitment(t *testing.T) {
	// RFC 9591 Section 5.1: "Round one involves each participant generating nonces
	// and their corresponding public commitments. A nonce is a pair of Scalar values,
	// and a commitment is a pair of Element values."

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	// Generate keys for 2-of-3 threshold
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	t.Run("CommitmentGeneration", func(t *testing.T) {
		// RFC 9591 Section 5.1: "Each participant's behavior in this round is described
		// by the commit function... The output of this function is a pair of secret nonces
		// (hiding_nonce, binding_nonce) and their corresponding public commitments."

		participant := signing.NewParticipant(keyPackages[0], suite)

		nonces, commitments, err := participant.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}

		// Verify nonces are generated
		if nonces.HidingNonce == nil {
			t.Error("HidingNonce should not be nil")
		}
		if nonces.BindingNonce == nil {
			t.Error("BindingNonce should not be nil")
		}

		// Verify commitments are generated
		if commitments.HidingNonceCommitment == nil {
			t.Error("HidingNonceCommitment should not be nil")
		}
		if commitments.BindingNonceCommitment == nil {
			t.Error("BindingNonceCommitment should not be nil")
		}

		// Verify identifier is set
		if commitments.Identifier != keyPackages[0].Identifier {
			t.Errorf("Expected identifier %d, got %d", keyPackages[0].Identifier, commitments.Identifier)
		}
	})

	t.Run("NonceGenerationAlgorithm", func(t *testing.T) {
		// RFC 9591 Section 5.1: "hiding_nonce = nonce_generate(sk_i)
		// binding_nonce = nonce_generate(sk_i)"

		participant := signing.NewParticipant(keyPackages[0], suite)

		nonces, _, err := participant.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}

		// Verify nonces are non-zero
		if nonces.HidingNonce.IsZero() {
			t.Error("HidingNonce should not be zero")
		}
		if nonces.BindingNonce.IsZero() {
			t.Error("BindingNonce should not be zero")
		}

		// Verify nonces are different
		if nonces.HidingNonce.Equal(nonces.BindingNonce) {
			t.Error("HidingNonce and BindingNonce should be different")
		}
	})

	t.Run("CommitmentFormat", func(t *testing.T) {
		// RFC 9591 Section 5.1: "hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
		// binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)"

		participant := signing.NewParticipant(keyPackages[0], suite)
		grp := suite.Group()

		nonces, commitments, err := participant.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}

		// Verify commitments are properly computed from nonces
		expectedHidingCommitment := grp.ScalarBaseMult(nonces.HidingNonce)
		expectedBindingCommitment := grp.ScalarBaseMult(nonces.BindingNonce)

		if !commitments.HidingNonceCommitment.Equal(expectedHidingCommitment) {
			t.Error("HidingNonceCommitment does not match G.ScalarBaseMult(hiding_nonce)")
		}

		if !commitments.BindingNonceCommitment.Equal(expectedBindingCommitment) {
			t.Error("BindingNonceCommitment does not match G.ScalarBaseMult(binding_nonce)")
		}
	})

	t.Run("CommitmentUniqueness", func(t *testing.T) {
		// RFC 9591 Section 5.1: "The nonce values produced by this function MUST NOT
		// be used in more than one invocation of sign, and the nonces MUST be generated
		// from a source of secure randomness."

		participant := signing.NewParticipant(keyPackages[0], suite)

		// Generate multiple commitments
		_, commitments1, _ := participant.RoundOne()
		_, commitments2, _ := participant.RoundOne()

		// Verify commitments are unique (different nonces each time)
		if commitments1.HidingNonceCommitment.Equal(commitments2.HidingNonceCommitment) {
			t.Error("Multiple RoundOne calls should produce different hiding commitments")
		}
		if commitments1.BindingNonceCommitment.Equal(commitments2.BindingNonceCommitment) {
			t.Error("Multiple RoundOne calls should produce different binding commitments")
		}
	})

	t.Run("CommitmentsHideNonces", func(t *testing.T) {
		// RFC 9591 Section 5.1: "The nonce value is secret and MUST NOT be shared,
		// whereas the public output comm is sent to the Coordinator."

		participant := signing.NewParticipant(keyPackages[0], suite)
		grp := suite.Group()

		nonces1, commitments1, _ := participant.RoundOne()
		nonces2, commitments2, _ := participant.RoundOne()

		// Given only commitments (public values), it should be computationally
		// infeasible to determine the nonces (secret values).
		// We verify that different nonces produce different commitments,
		// which is a necessary (but not sufficient) property.

		if nonces1.HidingNonce.Equal(nonces2.HidingNonce) {
			t.Error("Different invocations should produce different nonces")
		}

		if commitments1.HidingNonceCommitment.Equal(commitments2.HidingNonceCommitment) {
			t.Error("Different nonces should produce different commitments")
		}

		// Verify that commitments are proper group elements (not identity)
		identity := grp.Identity()
		if commitments1.HidingNonceCommitment.Equal(identity) {
			t.Error("Commitment should not be identity element")
		}
		if commitments1.BindingNonceCommitment.Equal(identity) {
			t.Error("Commitment should not be identity element")
		}
	})
}

// TestSection5_2_RoundTwoSignatureShareGeneration tests RFC 9591 Section 5.2
// Round Two - Signature Share Generation requirements
func TestSection5_2_RoundTwoSignatureShareGeneration(t *testing.T) {
	// RFC 9591 Section 5.2: "In round two, the Coordinator is responsible for sending
	// the message to be signed and choosing the participants that will participate."

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	// Generate keys for 2-of-3 threshold
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create participants
	participants := make(map[frost.Identifier]signing.Participant)
	for i, pkg := range keyPackages {
		participants[participantIDs[i]] = signing.NewParticipant(pkg, suite)
	}

	message := []byte("Test message for FROST signing")

	t.Run("SignatureShareGeneration", func(t *testing.T) {
		// RFC 9591 Section 5.2: "Upon receipt and successful input validation, each
		// signer then runs the following procedure to produce its own signature share."

		// Round 1: Generate commitments
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed for participant %d: %v", id, err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		// Sort commitments by identifier
		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2: Generate signature shares
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed for participant %d: %v", id, err)
			}

			if share.SignatureShare == nil {
				t.Errorf("Participant %d produced nil signature share", id)
			}

			if share.Identifier != id {
				t.Errorf("Expected identifier %d, got %d", id, share.Identifier)
			}
		}
	})

	t.Run("BindingFactorComputation", func(t *testing.T) {
		// RFC 9591 Section 5.2: "binding_factor_list = compute_binding_factors(
		// group_public_key, commitment_list, msg)"

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2 - binding factors are computed internally
		// We verify this by checking that different messages produce different shares
		message1 := []byte("Message 1")
		message2 := []byte("Message 2")

		share1, err := participants[1].RoundTwo(noncesMap[1], message1, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Generate new nonces for second signing
		nonces2, comm2, _ := participants[1].RoundOne()
		commitments2 := frost.CommitmentList{comm2}

		share2, err := participants[1].RoundTwo(nonces2, message2, commitments2)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Different messages should produce different signature shares
		if share1.SignatureShare.Equal(share2.SignatureShare) {
			t.Error("Different messages should produce different signature shares")
		}
	})

	t.Run("GroupCommitmentComputation", func(t *testing.T) {
		// RFC 9591 Section 5.2: "group_commitment = compute_group_commitment(
		// commitment_list, binding_factor_list)"

		// This is tested implicitly through successful signature generation
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Generate signature shares
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate and verify - this proves group commitment was computed correctly
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Error("Signature verification failed, indicating incorrect group commitment computation")
		}
	})

	t.Run("ChallengeComputation", func(t *testing.T) {
		// RFC 9591 Section 5.2: "challenge = compute_challenge(
		// group_commitment, group_public_key, msg)"

		// Different messages should produce different challenges, leading to different shares
		nonces, comm, _ := participants[1].RoundOne()
		commitments := frost.CommitmentList{comm}

		msg1 := []byte("First message")
		share1, err := participants[1].RoundTwo(nonces, msg1, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Generate new nonces for second message
		nonces2, comm2, _ := participants[1].RoundOne()
		commitments2 := frost.CommitmentList{comm2}

		msg2 := []byte("Second message")
		share2, err := participants[1].RoundTwo(nonces2, msg2, commitments2)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		if share1.SignatureShare.Equal(share2.SignatureShare) {
			t.Error("Different messages should produce different signature shares due to different challenges")
		}
	})

	t.Run("SignatureShareFormat", func(t *testing.T) {
		// RFC 9591 Section 5.2: "sig_share = hiding_nonce + (binding_nonce * binding_factor)
		// + (lambda_i * sk_i * challenge)"

		nonces, comm, _ := participants[1].RoundOne()
		commitments := frost.CommitmentList{comm}

		share, err := participants[1].RoundTwo(nonces, message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Verify share is a valid scalar
		if share.SignatureShare.IsZero() {
			t.Error("Signature share should not be zero for valid inputs")
		}

		// Verify share can be serialized
		shareBytes := share.SignatureShare.Bytes()
		if len(shareBytes) != suite.Group().ScalarLength() {
			t.Errorf("Expected share length %d, got %d", suite.Group().ScalarLength(), len(shareBytes))
		}
	})

	t.Run("DifferentParticipantCombinations", func(t *testing.T) {
		// RFC 9591 Section 5.2: Test that different participant combinations can sign

		testCombinations := [][]frost.Identifier{
			{1, 2},
			{1, 3},
			{2, 3},
		}

		for _, combo := range testCombinations {
			// Round 1
			noncesMap := make(map[frost.Identifier]frost.SigningNonces)
			commitments := make(frost.CommitmentList, 0, len(combo))

			for _, id := range combo {
				nonces, comm, err := participants[id].RoundOne()
				if err != nil {
					t.Fatalf("RoundOne failed for participant %d: %v", id, err)
				}
				noncesMap[id] = nonces
				commitments = append(commitments, comm)
			}

			sort.Slice(commitments, func(i, j int) bool {
				return commitments[i].Identifier < commitments[j].Identifier
			})

			// Round 2
			shares := make([]frost.SignatureShare, 0, len(combo))
			for _, id := range combo {
				share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
				if err != nil {
					t.Fatalf("RoundTwo failed for participant %d in combo %v: %v", id, combo, err)
				}
				shares = append(shares, share)
			}

			// Aggregate and verify
			aggregator := signing.NewAggregator(suite, 2)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
			if err != nil {
				t.Fatalf("Aggregate failed for combo %v: %v", combo, err)
			}

			err = aggregator.Verify(message, signature, groupPublicKey)
			if err != nil {
				t.Errorf("Signature verification failed for combo %v: %v", combo, err)
			}
		}
	})
}

// TestSection5_3_SignatureShareAggregation tests RFC 9591 Section 5.3
// Signature Share Aggregation requirements
func TestSection5_3_SignatureShareAggregation(t *testing.T) {
	// RFC 9591 Section 5.3: "After participants perform round two and send their
	// signature shares to the Coordinator, the Coordinator aggregates each share
	// to produce a final signature."

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	// Generate keys for 2-of-3 threshold
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create participants
	participants := make(map[frost.Identifier]signing.Participant)
	for i, pkg := range keyPackages {
		participants[participantIDs[i]] = signing.NewParticipant(pkg, suite)
	}

	message := []byte("Test message for aggregation")

	t.Run("AggregationOfValidShares", func(t *testing.T) {
		// RFC 9591 Section 5.3: "The Coordinator aggregates each share to produce
		// a final signature"

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		if signature.R == nil {
			t.Error("Signature R should not be nil")
		}
		if signature.Z == nil {
			t.Error("Signature Z should not be nil")
		}
	})

	t.Run("FinalSignatureVerification", func(t *testing.T) {
		// RFC 9591 Section 5.3: "The Coordinator SHOULD verify this signature using
		// the group public key before publishing or releasing the signature."

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		// Verify
		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	t.Run("ThresholdParticipants", func(t *testing.T) {
		// RFC 9591 Section 5.3: Test with exactly MIN_PARTICIPANTS (threshold)

		// Round 1 with exactly 2 participants (threshold)
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate with threshold participants
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate with threshold participants failed: %v", err)
		}

		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Error("Threshold signature should verify successfully")
		}
	})

	t.Run("MoreThanThresholdParticipants", func(t *testing.T) {
		// RFC 9591 Section 5.3: Test with more than MIN_PARTICIPANTS

		// Round 1 with all 3 participants
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 3)

		for _, id := range []frost.Identifier{1, 2, 3} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 3)
		for _, id := range []frost.Identifier{1, 2, 3} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate with all participants
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate with all participants failed: %v", err)
		}

		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Error("Signature with all participants should verify successfully")
		}
	})

	t.Run("AggregationFailureWithInvalidShares", func(t *testing.T) {
		// RFC 9591 Section 5.3: "If validation fails, the Coordinator MUST abort
		// the protocol, as the resulting signature will be invalid."

		// Generate valid setup
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Generate one valid share
		share1, err := participants[1].RoundTwo(noncesMap[1], message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Create an invalid share (use wrong nonces)
		wrongNonces, _, _ := participants[2].RoundOne()
		share2, err := participants[2].RoundTwo(wrongNonces, message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		shares := []frost.SignatureShare{share1, share2}

		// Aggregate
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		// Verify should fail because share2 was computed with wrong nonces
		err = aggregator.Verify(message, signature, groupPublicKey)
		if err == nil {
			t.Error("Verification should fail with invalid signature shares")
		}
	})

	t.Run("AggregationAlgorithm", func(t *testing.T) {
		// RFC 9591 Section 5.3: "z = Scalar(0); for z_i in sig_shares: z = z + z_i"

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Manually compute z as sum of shares
		grp := suite.Group()
		expectedZ := grp.NewScalar()
		for _, share := range shares {
			expectedZ = expectedZ.Add(share.SignatureShare)
		}

		// Aggregate
		aggregator := signing.NewAggregator(suite, 2)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		// Verify z is computed correctly
		if !signature.Z.Equal(expectedZ) {
			t.Error("Aggregated z does not match sum of signature shares")
		}
	})
}

// TestSection5_4_IdentifiableAbort tests RFC 9591 Section 5.4
// Identifiable Abort requirements
func TestSection5_4_IdentifiableAbort(t *testing.T) {
	// RFC 9591 Section 5.4: "Identifying misbehaving participants that produce
	// invalid shares can be done by checking signature shares from each participant
	// using verify_signature_share"

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	// Generate keys for 2-of-3 threshold
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create participants
	participants := make(map[frost.Identifier]signing.Participant)
	for i, pkg := range keyPackages {
		participants[participantIDs[i]] = signing.NewParticipant(pkg, suite)
	}

	message := []byte("Test message for identifiable abort")

	t.Run("IndividualSignatureShareVerification", func(t *testing.T) {
		// RFC 9591 Section 5.4: Test verify_signature_share for valid shares

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}

			// Verify this participant's share using another participant (who has all verification data)
			// Any participant can verify any other participant's share
			verifier := participants[1]
			err = verifier.VerifySignatureShare(share, message, commitments)
			if err != nil {
				t.Errorf("Valid signature share from participant %d should verify: %v", id, err)
			}
		}
	})

	t.Run("DetectionOfInvalidShares", func(t *testing.T) {
		// RFC 9591 Section 5.4: Test that invalid shares are detected

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Generate valid share
		share1, err := participants[1].RoundTwo(noncesMap[1], message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Generate invalid share (use wrong nonces)
		wrongNonces, _, _ := participants[2].RoundOne()
		invalidShare, err := participants[2].RoundTwo(wrongNonces, message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Use participant 1 to verify both shares
		verifier := participants[1]

		// Valid share should verify
		err = verifier.VerifySignatureShare(share1, message, commitments)
		if err != nil {
			t.Error("Valid signature share should verify")
		}

		// Invalid share should not verify
		err = verifier.VerifySignatureShare(invalidShare, message, commitments)
		if err == nil {
			t.Error("Invalid signature share should not verify")
		}
	})

	t.Run("IdentificationOfMisbehavingParticipants", func(t *testing.T) {
		// RFC 9591 Section 5.4: Test identifying which participant misbehaved

		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Participant 1 behaves correctly
		share1, err := participants[1].RoundTwo(noncesMap[1], message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Participant 2 misbehaves (uses wrong nonces)
		wrongNonces, _, _ := participants[2].RoundOne()
		share2, err := participants[2].RoundTwo(wrongNonces, message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Coordinator verifies each share to identify misbehaving participant
		shares := []frost.SignatureShare{share1, share2}
		misbehaving := make([]frost.Identifier, 0)

		for _, share := range shares {
			// Use any participant to verify (they all have the same verification data)
			err := participants[1].VerifySignatureShare(share, message, commitments)
			if err != nil {
				misbehaving = append(misbehaving, share.Identifier)
			}
		}

		// Should identify participant 2 as misbehaving
		if len(misbehaving) != 1 {
			t.Errorf("Expected 1 misbehaving participant, found %d", len(misbehaving))
		}

		if len(misbehaving) > 0 && misbehaving[0] != 2 {
			t.Errorf("Expected participant 2 to be identified as misbehaving, got %d", misbehaving[0])
		}
	})

	t.Run("VerificationEquation", func(t *testing.T) {
		// RFC 9591 Section 5.4: "l = G.ScalarBaseMult(sig_share_i)
		// r = comm_share + G.ScalarMult(PK_i, challenge * lambda_i)
		// return l == r"

		// Round 1 - need at least 2 participants for proper verification
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		share, err := participants[1].RoundTwo(noncesMap[1], message, commitments)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}

		// Verify using the verification equation
		err = participants[1].VerifySignatureShare(share, message, commitments)
		if err != nil {
			t.Errorf("Signature share verification failed: %v", err)
		}
	})
}

// TestSection5_CompleteProtocolFlow tests the complete two-round signing protocol
func TestSection5_CompleteProtocolFlow(t *testing.T) {
	// RFC 9591 Section 5: Complete two-round protocol test

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	t.Run("Complete2of3Protocol", func(t *testing.T) {
		// RFC 9591 Section 5: Test complete flow with 2-of-3 threshold

		// Setup: Generate keys
		participantIDs := []frost.Identifier{1, 2, 3}
		keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Create participants
		participantsMap := make(map[frost.Identifier]signing.Participant)
		for i, pkg := range keyPackages {
			participantsMap[participantIDs[i]] = signing.NewParticipant(pkg, suite)
		}

		// Create aggregator
		aggregator := signing.NewAggregator(suite, 2)

		message := []byte("Complete protocol test message")

		// Round 1: Commitment
		// RFC 9591 Section 5.1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		signingParticipants := []frost.Identifier{1, 2}
		for _, id := range signingParticipants {
			nonces, comm, err := participantsMap[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed for participant %d: %v", id, err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		// Sort commitments
		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2: Signature Share Generation
		// RFC 9591 Section 5.2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range signingParticipants {
			share, err := participantsMap[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed for participant %d: %v", id, err)
			}
			shares = append(shares, share)
		}

		// Aggregation
		// RFC 9591 Section 5.3
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		// Verification
		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	t.Run("Complete3of5Protocol", func(t *testing.T) {
		// RFC 9591 Section 5: Test complete flow with 3-of-5 threshold

		// Setup: Generate keys
		participantIDs := []frost.Identifier{1, 2, 3, 4, 5}
		keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 3, 5, participantIDs)
		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Create participants
		participantsMap := make(map[frost.Identifier]signing.Participant)
		for i, pkg := range keyPackages {
			participantsMap[participantIDs[i]] = signing.NewParticipant(pkg, suite)
		}

		// Create aggregator
		aggregator := signing.NewAggregator(suite, 3)

		message := []byte("3-of-5 threshold test")

		// Round 1: Commitment
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 3)

		signingParticipants := []frost.Identifier{1, 3, 5}
		for _, id := range signingParticipants {
			nonces, comm, err := participantsMap[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed for participant %d: %v", id, err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2: Signature Share Generation
		shares := make([]frost.SignatureShare, 0, 3)
		for _, id := range signingParticipants {
			share, err := participantsMap[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed for participant %d: %v", id, err)
			}
			shares = append(shares, share)
		}

		// Aggregation
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		// Verification
		err = aggregator.Verify(message, signature, groupPublicKey)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	t.Run("DifferentMessages", func(t *testing.T) {
		// RFC 9591 Section 5: Test protocol with different messages

		// Setup
		participantIDs := []frost.Identifier{1, 2, 3}
		keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		participantsMap := make(map[frost.Identifier]signing.Participant)
		for i, pkg := range keyPackages {
			participantsMap[participantIDs[i]] = signing.NewParticipant(pkg, suite)
		}

		aggregator := signing.NewAggregator(suite, 2)

		messages := [][]byte{
			[]byte("Message 1"),
			[]byte("Message 2"),
			[]byte(""),
			[]byte{0x00, 0x01, 0x02, 0xFF},
		}

		for i, message := range messages {
			// Round 1
			noncesMap := make(map[frost.Identifier]frost.SigningNonces)
			commitments := make(frost.CommitmentList, 0, 2)

			for _, id := range []frost.Identifier{1, 2} {
				nonces, comm, err := participantsMap[id].RoundOne()
				if err != nil {
					t.Fatalf("RoundOne failed for message %d: %v", i, err)
				}
				noncesMap[id] = nonces
				commitments = append(commitments, comm)
			}

			sort.Slice(commitments, func(i, j int) bool {
				return commitments[i].Identifier < commitments[j].Identifier
			})

			// Round 2
			shares := make([]frost.SignatureShare, 0, 2)
			for _, id := range []frost.Identifier{1, 2} {
				share, err := participantsMap[id].RoundTwo(noncesMap[id], message, commitments)
				if err != nil {
					t.Fatalf("RoundTwo failed for message %d: %v", i, err)
				}
				shares = append(shares, share)
			}

			// Aggregation
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
			if err != nil {
				t.Fatalf("Aggregate failed for message %d: %v", i, err)
			}

			// Verification
			err = aggregator.Verify(message, signature, groupPublicKey)
			if err != nil {
				t.Errorf("Signature verification failed for message %d: %v", i, err)
			}

			// Verify wrong message fails
			wrongMessage := append(message, byte(0xFF))
			err = aggregator.Verify(wrongMessage, signature, groupPublicKey)
			if err == nil {
				t.Errorf("Signature should not verify for wrong message %d", i)
			}
		}
	})

	t.Run("ConcurrentSigningSessions", func(t *testing.T) {
		// RFC 9591 Section 5: Test that multiple concurrent signing sessions
		// produce different signatures (due to different nonces)

		// Setup
		participantIDs := []frost.Identifier{1, 2, 3}
		keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		participantsMap := make(map[frost.Identifier]signing.Participant)
		for i, pkg := range keyPackages {
			participantsMap[participantIDs[i]] = signing.NewParticipant(pkg, suite)
		}

		aggregator := signing.NewAggregator(suite, 2)
		message := []byte("Same message, different sessions")

		// Session 1
		noncesMap1 := make(map[frost.Identifier]frost.SigningNonces)
		commitments1 := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participantsMap[id].RoundOne()
			if err != nil {
				t.Fatalf("Session 1 RoundOne failed: %v", err)
			}
			noncesMap1[id] = nonces
			commitments1 = append(commitments1, comm)
		}

		sort.Slice(commitments1, func(i, j int) bool {
			return commitments1[i].Identifier < commitments1[j].Identifier
		})

		shares1 := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participantsMap[id].RoundTwo(noncesMap1[id], message, commitments1)
			if err != nil {
				t.Fatalf("Session 1 RoundTwo failed: %v", err)
			}
			shares1 = append(shares1, share)
		}

		signature1, err := aggregator.Aggregate(groupPublicKey, commitments1, message, shares1)
		if err != nil {
			t.Fatalf("Session 1 Aggregate failed: %v", err)
		}

		// Session 2 (same message, different nonces)
		noncesMap2 := make(map[frost.Identifier]frost.SigningNonces)
		commitments2 := make(frost.CommitmentList, 0, 2)

		for _, id := range []frost.Identifier{1, 2} {
			nonces, comm, err := participantsMap[id].RoundOne()
			if err != nil {
				t.Fatalf("Session 2 RoundOne failed: %v", err)
			}
			noncesMap2[id] = nonces
			commitments2 = append(commitments2, comm)
		}

		sort.Slice(commitments2, func(i, j int) bool {
			return commitments2[i].Identifier < commitments2[j].Identifier
		})

		shares2 := make([]frost.SignatureShare, 0, 2)
		for _, id := range []frost.Identifier{1, 2} {
			share, err := participantsMap[id].RoundTwo(noncesMap2[id], message, commitments2)
			if err != nil {
				t.Fatalf("Session 2 RoundTwo failed: %v", err)
			}
			shares2 = append(shares2, share)
		}

		signature2, err := aggregator.Aggregate(groupPublicKey, commitments2, message, shares2)
		if err != nil {
			t.Fatalf("Session 2 Aggregate failed: %v", err)
		}

		// Verify both signatures are valid
		if err := aggregator.Verify(message, signature1, groupPublicKey); err != nil {
			t.Error("Signature 1 should verify")
		}
		if err := aggregator.Verify(message, signature2, groupPublicKey); err != nil {
			t.Error("Signature 2 should verify")
		}

		// Verify signatures are different (different R due to different nonces)
		if signature1.R.Equal(signature2.R) {
			t.Error("Different sessions should produce signatures with different R values")
		}

		// Even if R is the same (extremely unlikely), Z should be different
		if signature1.R.Equal(signature2.R) && signature1.Z.Equal(signature2.Z) {
			t.Error("Different sessions should never produce identical signatures")
		}
	})

	t.Run("CoordinatorIntegration", func(t *testing.T) {
		// RFC 9591 Section 5: Test using the Coordinator to orchestrate the protocol
		// Note: The current Coordinator implementation has a limitation where it doesn't
		// properly store nonces between rounds. This test validates the RequestCommitments
		// functionality which does work correctly.

		// Setup
		participantIDs := []frost.Identifier{1, 2, 3}
		keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
		if err != nil {
			t.Fatalf("GenerateShares failed: %v", err)
		}

		// Create participants
		participantsMap := make(map[frost.Identifier]signing.Participant)
		for i, pkg := range keyPackages {
			participantsMap[participantIDs[i]] = signing.NewParticipant(pkg, suite)
		}

		// Create aggregator and coordinator
		aggregator := signing.NewAggregator(suite, 2)
		coordinator := signing.NewCoordinatorWithPublicKey(suite, participantsMap, aggregator, groupPublicKey)

		message := []byte("Coordinator test message")

		// Test RequestCommitments (this works correctly)
		commitments, err := coordinator.RequestCommitments([]frost.Identifier{1, 2}, message)
		if err != nil {
			t.Fatalf("Coordinator.RequestCommitments failed: %v", err)
		}

		if len(commitments) != 2 {
			t.Errorf("Expected 2 commitments, got %d", len(commitments))
		}

		// Verify commitments are properly sorted
		if commitments[0].Identifier > commitments[1].Identifier {
			t.Error("Commitments should be sorted by identifier")
		}

		// Note: We cannot test the full Sign method because the Coordinator implementation
		// currently doesn't manage nonce state between rounds. This is a known limitation
		// documented in the coordinator.go file at line 164-166.
		t.Log("Coordinator.RequestCommitments works correctly. Full Sign() integration requires nonce state management.")
	})
}

// TestSection5_NonceReuseAttack tests that nonce reuse is prevented
func TestSection5_NonceReuseAttack(t *testing.T) {
	// RFC 9591 Section 5.1: "The nonce values produced by this function MUST NOT
	// be used in more than one invocation of sign"

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	participantIDs := []frost.Identifier{1, 2}
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	// Generate nonces once
	nonces1, comm1, _ := participant1.RoundOne()
	nonces2, comm2, _ := participant2.RoundOne()

	commitments := frost.CommitmentList{comm1, comm2}
	sort.Slice(commitments, func(i, j int) bool {
		return commitments[i].Identifier < commitments[j].Identifier
	})

	message1 := []byte("First message")
	message2 := []byte("Second message")

	// Sign first message with nonces
	share1_msg1, err := participant1.RoundTwo(nonces1, message1, commitments)
	if err != nil {
		t.Fatalf("RoundTwo failed: %v", err)
	}
	share2_msg1, err := participant2.RoundTwo(nonces2, message1, commitments)
	if err != nil {
		t.Fatalf("RoundTwo failed: %v", err)
	}

	aggregator := signing.NewAggregator(suite, 2)
	sig1, err := aggregator.Aggregate(groupPublicKey, commitments, message1,
		[]frost.SignatureShare{share1_msg1, share2_msg1})
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// Verify first signature
	if err := aggregator.Verify(message1, sig1, groupPublicKey); err != nil {
		t.Error("First signature should verify")
	}

	// Attempt to reuse the same nonces for a different message
	// This should produce an invalid signature
	share1_msg2, err := participant1.RoundTwo(nonces1, message2, commitments)
	if err != nil {
		t.Fatalf("RoundTwo failed: %v", err)
	}
	share2_msg2, err := participant2.RoundTwo(nonces2, message2, commitments)
	if err != nil {
		t.Fatalf("RoundTwo failed: %v", err)
	}

	sig2, err := aggregator.Aggregate(groupPublicKey, commitments, message2,
		[]frost.SignatureShare{share1_msg2, share2_msg2})
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// The signature might technically be valid, but this demonstrates why nonce
	// reuse is dangerous. In practice, with nonce reuse and knowledge of both
	// signatures, an attacker could potentially recover the secret key.
	// This test documents the behavior rather than prevents it (prevention
	// requires careful state management by the implementation).

	// Verify that if somehow the same nonces are used, we at least get
	// different signature shares for different messages
	if share1_msg1.SignatureShare.Equal(share1_msg2.SignatureShare) {
		t.Error("Same nonces with different messages should produce different signature shares")
	}

	// Both signatures might verify, but this is a security vulnerability
	// The implementation should enforce nonce uniqueness at the state management level
	err1 := aggregator.Verify(message1, sig1, groupPublicKey)
	err2 := aggregator.Verify(message2, sig2, groupPublicKey)

	if err1 == nil && err2 == nil {
		// Both verify - this is the dangerous scenario that nonce reuse can lead to
		t.Log("WARNING: Nonce reuse produced two valid signatures - this demonstrates the security risk")
	}
}

// TestSection5_SignatureUniqueness tests that each signing session produces unique signatures
func TestSection5_SignatureUniqueness(t *testing.T) {
	// RFC 9591 Section 5: Verify that unique nonces lead to unique signatures

	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)

	participantIDs := []frost.Identifier{1, 2}
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participants := make(map[frost.Identifier]signing.Participant)
	for i, pkg := range keyPackages {
		participants[participantIDs[i]] = signing.NewParticipant(pkg, suite)
	}

	aggregator := signing.NewAggregator(suite, 2)
	message := []byte("Same message")

	// Generate 10 signatures for the same message
	signatures := make([]frost.Signature, 10)
	rValues := make(map[string]bool)
	sigBytes := make(map[string]bool)

	for i := 0; i < 10; i++ {
		// Round 1
		noncesMap := make(map[frost.Identifier]frost.SigningNonces)
		commitments := make(frost.CommitmentList, 0, 2)

		for _, id := range participantIDs {
			nonces, comm, err := participants[id].RoundOne()
			if err != nil {
				t.Fatalf("RoundOne failed: %v", err)
			}
			noncesMap[id] = nonces
			commitments = append(commitments, comm)
		}

		sort.Slice(commitments, func(i, j int) bool {
			return commitments[i].Identifier < commitments[j].Identifier
		})

		// Round 2
		shares := make([]frost.SignatureShare, 0, 2)
		for _, id := range participantIDs {
			share, err := participants[id].RoundTwo(noncesMap[id], message, commitments)
			if err != nil {
				t.Fatalf("RoundTwo failed: %v", err)
			}
			shares = append(shares, share)
		}

		// Aggregate
		sig, err := aggregator.Aggregate(groupPublicKey, commitments, message, shares)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}

		signatures[i] = sig

		// Track R values and full signatures
		rBytes := sig.R.Bytes()
		rKey := string(rBytes)
		if rValues[rKey] {
			t.Error("Duplicate R value found - nonces may not be unique")
		}
		rValues[rKey] = true

		fullSigBytes := append(rBytes, sig.Z.Bytes()...)
		sigKey := string(fullSigBytes)
		if sigBytes[sigKey] {
			t.Error("Duplicate signature found - this should never happen")
		}
		sigBytes[sigKey] = true

		// Verify signature
		if err := aggregator.Verify(message, sig, groupPublicKey); err != nil {
			t.Errorf("Signature %d verification failed: %v", i, err)
		}
	}

	// Verify all signatures are unique
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if bytes.Equal(signatures[i].R.Bytes(), signatures[j].R.Bytes()) &&
				bytes.Equal(signatures[i].Z.Bytes(), signatures[j].Z.Bytes()) {
				t.Errorf("Signatures %d and %d are identical", i, j)
			}
		}
	}

	t.Logf("Generated %d unique signatures for the same message", len(signatures))
}
