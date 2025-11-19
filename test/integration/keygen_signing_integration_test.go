//go:build integration

// Package integration provides end-to-end integration tests for the FROST protocol.
package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestKeygenSigningIntegration_2of3 tests the complete end-to-end workflow
// for a 2-of-3 threshold with dealer keygen and multiple signing sessions.
//
// This test validates:
// 1. Dealer generates valid shares for all participants
// 2. Multiple signing sessions with the same keys work correctly
// 3. All participant combinations can create valid signatures
// 4. Signatures verify correctly
func TestKeygenSigningIntegration_2of3(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Configure 2-of-3 threshold
	minSigners := uint32(2)
	maxSigners := uint32(3)
	participants := []frost.Identifier{1, 2, 3}

	// Generate keys using dealer
	dealer := keygen.NewDealer(suite)
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	t.Logf("Generated %d key packages", len(keyPackages))
	t.Logf("Group public key: %s", hex.EncodeToString(groupPublicKey.Bytes()))

	// Test signing with multiple messages
	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message"),
	}

	for i, message := range messages {
		t.Run(fmt.Sprintf("message_%d", i), func(t *testing.T) {
			// Use different participant combinations
			signerCombinations := [][]int{
				{0, 1}, // P1, P2
				{0, 2}, // P1, P3
				{1, 2}, // P2, P3
			}

			for j, combo := range signerCombinations {
				t.Run(fmt.Sprintf("signers_P%d_P%d", combo[0]+1, combo[1]+1), func(t *testing.T) {
					signingPackages := []frost.KeyPackage{
						keyPackages[combo[0]],
						keyPackages[combo[1]],
					}

					// Round 1: Generate nonces and commitments
					participantObjs := make([]signing.Participant, len(signingPackages))
					nonces := make([]frost.SigningNonces, len(signingPackages))
					commitments := make(frost.CommitmentList, len(signingPackages))

					for k, pkg := range signingPackages {
						participantObjs[k] = signing.NewParticipant(pkg, suite)
						n, c, err := participantObjs[k].RoundOne()
						if err != nil {
							t.Fatalf("Failed to generate nonce: %v", err)
						}
						nonces[k] = n
						commitments[k] = c
					}

					// Round 2: Create signature shares
					signatureShares := make([]frost.SignatureShare, len(signingPackages))
					for k, participant := range participantObjs {
						share, err := participant.RoundTwo(nonces[k], message, commitments)
						if err != nil {
							t.Fatalf("Failed to sign: %v", err)
						}
						signatureShares[k] = share
					}

					// Aggregate signature
					aggregator := signing.NewAggregator(suite, minSigners)
					signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
					if err != nil {
						t.Fatalf("Failed to aggregate signature: %v", err)
					}

					// Verify signature
					sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
					err = suite.VerifySignature(message, sigBytes, groupPublicKey)
					if err != nil {
						t.Fatalf("Signature verification failed: %v", err)
					}

					t.Logf("✓ Message %d, combination %d verified successfully", i, j)
				})
			}
		})
	}
}

// TestKeygenSigningIntegration_3of5 tests a 3-of-5 threshold configuration
// with multiple signing sessions and participant combinations.
func TestKeygenSigningIntegration_3of5(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Configure 3-of-5 threshold
	minSigners := uint32(3)
	maxSigners := uint32(5)
	participants := []frost.Identifier{1, 2, 3, 4, 5}

	// Generate keys using dealer
	dealer := keygen.NewDealer(suite)
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	t.Logf("Generated %d key packages", len(keyPackages))
	t.Logf("Group public key: %s", hex.EncodeToString(groupPublicKey.Bytes()))

	// Test with multiple messages
	messages := [][]byte{
		[]byte("Transaction 1"),
		[]byte("Transaction 2"),
		[]byte("Transaction 3"),
	}

	// Test different signer combinations
	signerCombinations := [][]int{
		{0, 1, 2}, // P1, P2, P3
		{0, 2, 4}, // P1, P3, P5
		{1, 3, 4}, // P2, P4, P5
		{0, 1, 3}, // P1, P2, P4
		{2, 3, 4}, // P3, P4, P5
	}

	for i, message := range messages {
		t.Run(fmt.Sprintf("message_%d", i), func(t *testing.T) {
			for j, combo := range signerCombinations {
				t.Run(fmt.Sprintf("signers_%d", j), func(t *testing.T) {
					signingPackages := []frost.KeyPackage{
						keyPackages[combo[0]],
						keyPackages[combo[1]],
						keyPackages[combo[2]],
					}

					// Round 1: Generate nonces and commitments
					participantObjs := make([]signing.Participant, len(signingPackages))
					nonces := make([]frost.SigningNonces, len(signingPackages))
					commitments := make(frost.CommitmentList, len(signingPackages))

					for k, pkg := range signingPackages {
						participantObjs[k] = signing.NewParticipant(pkg, suite)
						n, c, err := participantObjs[k].RoundOne()
						if err != nil {
							t.Fatalf("Failed to generate nonce: %v", err)
						}
						nonces[k] = n
						commitments[k] = c
					}

					// Round 2: Create signature shares
					signatureShares := make([]frost.SignatureShare, len(signingPackages))
					for k, participant := range participantObjs {
						share, err := participant.RoundTwo(nonces[k], message, commitments)
						if err != nil {
							t.Fatalf("Failed to sign: %v", err)
						}
						signatureShares[k] = share
					}

					// Aggregate signature
					aggregator := signing.NewAggregator(suite, minSigners)
					signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
					if err != nil {
						t.Fatalf("Failed to aggregate signature: %v", err)
					}

					// Verify signature
					sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
					err = suite.VerifySignature(message, sigBytes, groupPublicKey)
					if err != nil {
						t.Fatalf("Signature verification failed: %v", err)
					}

					t.Logf("✓ Verified: message %d with signers P%d,P%d,P%d",
						i, combo[0]+1, combo[1]+1, combo[2]+1)
				})
			}
		})
	}
}

// TestKeygenSigningIntegration_SameKeysMultipleMessages verifies that
// the same keys can be used to sign multiple different messages and
// each signature is unique and valid.
func TestKeygenSigningIntegration_SameKeysMultipleMessages(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Configure 2-of-3 threshold
	minSigners := uint32(2)
	maxSigners := uint32(3)
	participants := []frost.Identifier{1, 2, 3}

	// Generate keys
	dealer := keygen.NewDealer(suite)
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	// Sign 10 different messages with the same keys
	numMessages := 10
	signatures := make([]frost.Signature, numMessages)

	for i := 0; i < numMessages; i++ {
		message := []byte(fmt.Sprintf("Message number %d", i))

		// Use P1 and P2
		signingPackages := keyPackages[:2]

		// Round 1: Generate nonces
		participantObjs := make([]signing.Participant, len(signingPackages))
		nonces := make([]frost.SigningNonces, len(signingPackages))
		commitments := make(frost.CommitmentList, len(signingPackages))

		for j, pkg := range signingPackages {
			participantObjs[j] = signing.NewParticipant(pkg, suite)
			n, c, err := participantObjs[j].RoundOne()
			if err != nil {
				t.Fatalf("Message %d: Failed to generate nonce: %v", i, err)
			}
			nonces[j] = n
			commitments[j] = c
		}

		// Round 2: Sign
		signatureShares := make([]frost.SignatureShare, len(signingPackages))
		for j, participant := range participantObjs {
			share, err := participant.RoundTwo(nonces[j], message, commitments)
			if err != nil {
				t.Fatalf("Message %d: Failed to sign: %v", i, err)
			}
			signatureShares[j] = share
		}

		// Aggregate
		aggregator := signing.NewAggregator(suite, minSigners)
		signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
		if err != nil {
			t.Fatalf("Message %d: Failed to aggregate: %v", i, err)
		}

		// Verify
		sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
		err = suite.VerifySignature(message, sigBytes, groupPublicKey)
		if err != nil {
			t.Fatalf("Message %d: Verification failed: %v", i, err)
		}

		signatures[i] = signature
		t.Logf("✓ Message %d signed and verified", i)
	}

	// Verify all signatures are unique (different nonces)
	for i := 0; i < numMessages; i++ {
		for j := i + 1; j < numMessages; j++ {
			if signatures[i].R.Equal(signatures[j].R) {
				t.Errorf("Signatures %d and %d have identical R values", i, j)
			}
		}
	}

	t.Logf("✓ All %d signatures are unique", numMessages)
}

// TestKeygenSigningIntegration_WithService tests the integration using
// the FrostService wrapper.
func TestKeygenSigningIntegration_WithService(t *testing.T) {
	suite := ristretto255_sha512.New()
	frostService := service.NewFrostService(suite)

	tests := []struct {
		name       string
		minSigners uint32
		maxSigners uint32
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-7", 5, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Configure
			config := frost.Configuration{
				MinSigners: tt.minSigners,
				MaxSigners: tt.maxSigners,
				Group:      suite.Group(),
			}

			// Generate participant IDs
			participants := make([]frost.Identifier, tt.maxSigners)
			for i := uint32(0); i < tt.maxSigners; i++ {
				participants[i] = frost.Identifier(i + 1)
			}

			// Generate keys
			keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participants)
			if err != nil {
				t.Fatalf("GenerateKeys failed: %v", err)
			}

			// Sign multiple messages
			messages := [][]byte{
				[]byte("Message A"),
				[]byte("Message B"),
				[]byte("Message C"),
			}

			for i, message := range messages {
				// Use minimum signers
				signingPackages := keyPackages[:tt.minSigners]

				signature, err := frostService.Sign(signingPackages, message)
				if err != nil {
					t.Fatalf("Sign message %d failed: %v", i, err)
				}

				err = frostService.Verify(message, signature, groupPubKey)
				if err != nil {
					t.Fatalf("Verify message %d failed: %v", i, err)
				}

				t.Logf("✓ Message %d signed and verified", i)
			}
		})
	}
}

// TestKeygenSigningIntegration_RandomMessages tests signing with
// random messages of varying sizes.
func TestKeygenSigningIntegration_RandomMessages(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Configure 2-of-3 threshold
	minSigners := uint32(2)
	maxSigners := uint32(3)
	participants := []frost.Identifier{1, 2, 3}

	// Generate keys
	dealer := keygen.NewDealer(suite)
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	// Test with random messages of different sizes
	messageSizes := []int{0, 1, 10, 100, 1000, 10000}

	for _, size := range messageSizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			// Generate random message
			message := make([]byte, size)
			if size > 0 {
				_, err := rand.Read(message)
				if err != nil {
					t.Fatalf("Failed to generate random message: %v", err)
				}
			}

			// Sign with P1 and P2
			signingPackages := keyPackages[:2]

			// Round 1
			participantObjs := make([]signing.Participant, len(signingPackages))
			nonces := make([]frost.SigningNonces, len(signingPackages))
			commitments := make(frost.CommitmentList, len(signingPackages))

			for i, pkg := range signingPackages {
				participantObjs[i] = signing.NewParticipant(pkg, suite)
				n, c, err := participantObjs[i].RoundOne()
				if err != nil {
					t.Fatalf("Failed to generate nonce: %v", err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participantObjs {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("Failed to sign: %v", err)
				}
				signatureShares[i] = share
			}

			// Aggregate
			aggregator := signing.NewAggregator(suite, minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
			if err != nil {
				t.Fatalf("Failed to aggregate: %v", err)
			}

			// Verify
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(message, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Verification failed: %v", err)
			}

			t.Logf("✓ Random message of size %d verified", size)
		})
	}
}

// TestKeygenSigningIntegration_AllParticipantCombinations tests that
// all valid combinations of participants can create valid signatures.
func TestKeygenSigningIntegration_AllParticipantCombinations(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Configure 2-of-4 threshold
	minSigners := uint32(2)
	maxSigners := uint32(4)
	participants := []frost.Identifier{1, 2, 3, 4}

	// Generate keys
	dealer := keygen.NewDealer(suite)
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	message := []byte("Test all combinations")

	// All possible 2-of-4 combinations (C(4,2) = 6)
	combinations := [][2]int{
		{0, 1}, {0, 2}, {0, 3},
		{1, 2}, {1, 3},
		{2, 3},
	}

	for _, combo := range combinations {
		t.Run(fmt.Sprintf("P%d_P%d", combo[0]+1, combo[1]+1), func(t *testing.T) {
			signingPackages := []frost.KeyPackage{
				keyPackages[combo[0]],
				keyPackages[combo[1]],
			}

			// Round 1
			participantObjs := make([]signing.Participant, len(signingPackages))
			nonces := make([]frost.SigningNonces, len(signingPackages))
			commitments := make(frost.CommitmentList, len(signingPackages))

			for i, pkg := range signingPackages {
				participantObjs[i] = signing.NewParticipant(pkg, suite)
				n, c, err := participantObjs[i].RoundOne()
				if err != nil {
					t.Fatalf("Failed to generate nonce: %v", err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participantObjs {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("Failed to sign: %v", err)
				}
				signatureShares[i] = share
			}

			// Aggregate
			aggregator := signing.NewAggregator(suite, minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
			if err != nil {
				t.Fatalf("Failed to aggregate: %v", err)
			}

			// Verify
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(message, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Verification failed: %v", err)
			}

			t.Logf("✓ Combination P%d,P%d verified", combo[0]+1, combo[1]+1)
		})
	}

	t.Logf("✓ All %d combinations verified successfully", len(combinations))
}
