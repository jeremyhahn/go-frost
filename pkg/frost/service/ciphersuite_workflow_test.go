// Package integration provides comprehensive multi-ciphersuite integration tests
// that verify all 5 RFC 9591 ciphersuites work identically.
package service

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestMultiCiphersuite_BasicWorkflow tests the complete FROST workflow
// (keygen -> sign -> verify) for all 5 RFC 9591 ciphersuites.
//
// This ensures all ciphersuites work identically through:
// 1. Dealer-based key generation
// 2. Round 1: Nonce generation and commitments
// 3. Round 2: frost.Signature share generation
// 4. frost.Signature aggregation
// 5. frost.Signature verification
func TestMultiCiphersuite_BasicWorkflow(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
			grp := suite.Group()

			// Configure 2-of-3 threshold
			minSigners := uint32(2)
			maxSigners := uint32(3)
			participants := []frost.Identifier{1, 2, 3}

			// Step 1: Generate keys using dealer
			dealer := keygen.NewDealer(suite)
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			if len(keyPackages) != int(maxSigners) {
				t.Fatalf("Expected %d key packages, got %d", maxSigners, len(keyPackages))
			}

			t.Logf("Generated %d key packages", len(keyPackages))
			t.Logf("Group public key: %s", hex.EncodeToString(groupPublicKey.Bytes()))

			// Step 2-5: Sign and verify a message
			message := []byte("Test message for " + tc.name)
			signingPackages := keyPackages[:2] // Use P1 and P2

			// Round 1: Generate nonces and commitments
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

			// Round 2: Create signature shares
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participantObjs {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("Failed to sign: %v", err)
				}
				signatureShares[i] = share
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
				t.Fatalf("frost.Signature verification failed: %v", err)
			}

			t.Logf("✓ Complete workflow verified successfully")
		})
	}
}

// TestMultiCiphersuite_DifferentParticipants tests that different combinations
// of participants can create valid signatures for all ciphersuites.
//
// This verifies that the Lagrange interpolation and binding factors work
// correctly with different signer sets.
func TestMultiCiphersuite_DifferentParticipants(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
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

			message := []byte("Test different participants")

			// Test all possible 2-of-3 combinations
			signerCombinations := [][]int{
				{0, 1}, // P1, P2
				{0, 2}, // P1, P3
				{1, 2}, // P2, P3
			}

			for _, combo := range signerCombinations {
				t.Run(fmt.Sprintf("P%d_P%d", combo[0]+1, combo[1]+1), func(t *testing.T) {
					signingPackages := []frost.KeyPackage{
						keyPackages[combo[0]],
						keyPackages[combo[1]],
					}

					// Round 1: Generate nonces and commitments
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

					// Round 2: Create signature shares
					signatureShares := make([]frost.SignatureShare, len(signingPackages))
					for i, participant := range participantObjs {
						share, err := participant.RoundTwo(nonces[i], message, commitments)
						if err != nil {
							t.Fatalf("Failed to sign: %v", err)
						}
						signatureShares[i] = share
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
						t.Fatalf("frost.Signature verification failed: %v", err)
					}

					t.Logf("✓ Combination P%d,P%d verified", combo[0]+1, combo[1]+1)
				})
			}

			t.Logf("✓ All participant combinations verified")
		})
	}
}

// TestMultiCiphersuite_InvalidSignature tests that signature tampering
// is correctly detected for all ciphersuites.
//
// This ensures the verification logic properly rejects invalid signatures.
func TestMultiCiphersuite_InvalidSignature(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
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

			message := []byte("Original message")
			signingPackages := keyPackages[:2]

			// Round 1: Generate nonces and commitments
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

			// Round 2: Create signature shares
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participantObjs {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("Failed to sign: %v", err)
				}
				signatureShares[i] = share
			}

			// Aggregate signature
			aggregator := signing.NewAggregator(suite, minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
			if err != nil {
				t.Fatalf("Failed to aggregate signature: %v", err)
			}

			// Tamper with the signature by modifying the Z component
			randomScalar, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate random scalar: %v", err)
			}
			tamperedZ := signature.Z.Add(randomScalar)
			tamperedSignature := frost.Signature{
				R: signature.R,
				Z: tamperedZ,
			}

			// Verify tampered signature should fail
			tamperedSigBytes := append(tamperedSignature.R.Bytes(), tamperedSignature.Z.Bytes()...)
			err = suite.VerifySignature(message, tamperedSigBytes, groupPublicKey)
			if err == nil {
				t.Fatalf("Expected verification to fail for tampered signature, but it succeeded")
			}

			t.Logf("✓ Tampered signature correctly rejected")

			// Verify original signature still works
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(message, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Original signature verification failed: %v", err)
			}

			t.Logf("✓ Original signature still valid")
		})
	}
}

// TestMultiCiphersuite_MessageIntegrity tests that different messages
// produce different signatures for all ciphersuites.
//
// This ensures that signatures are message-dependent and unique.
func TestMultiCiphersuite_MessageIntegrity(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
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

			// Sign multiple different messages
			messages := [][]byte{
				[]byte("First message"),
				[]byte("Second message"),
				[]byte("Third message"),
			}

			signatures := make([]frost.Signature, len(messages))
			signingPackages := keyPackages[:2]

			for i, message := range messages {
				// Round 1: Generate nonces and commitments
				participantObjs := make([]signing.Participant, len(signingPackages))
				nonces := make([]frost.SigningNonces, len(signingPackages))
				commitments := make(frost.CommitmentList, len(signingPackages))

				for j, pkg := range signingPackages {
					participantObjs[j] = signing.NewParticipant(pkg, suite)
					n, c, err := participantObjs[j].RoundOne()
					if err != nil {
						t.Fatalf("Failed to generate nonce: %v", err)
					}
					nonces[j] = n
					commitments[j] = c
				}

				// Round 2: Create signature shares
				signatureShares := make([]frost.SignatureShare, len(signingPackages))
				for j, participant := range participantObjs {
					share, err := participant.RoundTwo(nonces[j], message, commitments)
					if err != nil {
						t.Fatalf("Failed to sign: %v", err)
					}
					signatureShares[j] = share
				}

				// Aggregate signature
				aggregator := signing.NewAggregator(suite, minSigners)
				signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
				if err != nil {
					t.Fatalf("Failed to aggregate signature: %v", err)
				}

				signatures[i] = signature

				// Verify signature
				sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
				err = suite.VerifySignature(message, sigBytes, groupPublicKey)
				if err != nil {
					t.Fatalf("frost.Signature verification failed: %v", err)
				}
			}

			// Verify all signatures are different
			for i := 0; i < len(signatures); i++ {
				for j := i + 1; j < len(signatures); j++ {
					if signatures[i].Z.Equal(signatures[j].Z) {
						t.Errorf("Signatures %d and %d have identical Z values", i, j)
					}
					// Note: R values might differ due to different nonces
				}
			}

			t.Logf("✓ All %d messages produced unique signatures", len(messages))
		})
	}
}

// TestMultiCiphersuite_WrongMessageFails tests that a signature fails
// verification when used with a different message for all ciphersuites.
//
// This ensures message binding in the signature scheme.
func TestMultiCiphersuite_WrongMessageFails(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
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

			originalMessage := []byte("Original message")
			wrongMessage := []byte("Wrong message")
			signingPackages := keyPackages[:2]

			// Round 1: Generate nonces and commitments
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

			// Round 2: Create signature shares for original message
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participantObjs {
				share, err := participant.RoundTwo(nonces[i], originalMessage, commitments)
				if err != nil {
					t.Fatalf("Failed to sign: %v", err)
				}
				signatureShares[i] = share
			}

			// Aggregate signature
			aggregator := signing.NewAggregator(suite, minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, originalMessage, signatureShares)
			if err != nil {
				t.Fatalf("Failed to aggregate signature: %v", err)
			}

			// Verify with original message should succeed
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(originalMessage, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Original message verification failed: %v", err)
			}

			t.Logf("✓ Original message verification succeeded")

			// Verify with wrong message should fail
			err = suite.VerifySignature(wrongMessage, sigBytes, groupPublicKey)
			if err == nil {
				t.Fatalf("Expected verification to fail with wrong message, but it succeeded")
			}

			t.Logf("✓ Wrong message correctly rejected")
		})
	}
}

// TestMultiCiphersuite_RandomMessages tests all ciphersuites with
// random messages of varying sizes to ensure robust handling.
func TestMultiCiphersuite_RandomMessages(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	messageSizes := []int{0, 1, 10, 100, 1000, 10000}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
			grp := suite.Group()

			// Configure 2-of-3 threshold
			minSigners := uint32(2)
			maxSigners := uint32(3)
			participants := []frost.Identifier{1, 2, 3}

			// Generate keys once for all message sizes
			dealer := keygen.NewDealer(suite)
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

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

					signingPackages := keyPackages[:2]

					// Round 1: Generate nonces and commitments
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

					// Round 2: Create signature shares
					signatureShares := make([]frost.SignatureShare, len(signingPackages))
					for i, participant := range participantObjs {
						share, err := participant.RoundTwo(nonces[i], message, commitments)
						if err != nil {
							t.Fatalf("Failed to sign: %v", err)
						}
						signatureShares[i] = share
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
						t.Fatalf("frost.Signature verification failed: %v", err)
					}

					t.Logf("✓ Random message of size %d verified", size)
				})
			}
		})
	}
}

// TestMultiCiphersuite_3of5Threshold tests all ciphersuites with a
// more complex 3-of-5 threshold configuration.
//
// This ensures the protocol works correctly with larger thresholds
// and validates proper Lagrange coefficient computation.
func TestMultiCiphersuite_3of5Threshold(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
			grp := suite.Group()

			// Configure 3-of-5 threshold
			minSigners := uint32(3)
			maxSigners := uint32(5)
			participants := []frost.Identifier{1, 2, 3, 4, 5}

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

			message := []byte("3-of-5 threshold test")

			// Test different 3-of-5 combinations
			signerCombinations := [][]int{
				{0, 1, 2}, // P1, P2, P3
				{0, 2, 4}, // P1, P3, P5
				{1, 3, 4}, // P2, P4, P5
				{0, 1, 3}, // P1, P2, P4
				{2, 3, 4}, // P3, P4, P5
			}

			for _, combo := range signerCombinations {
				t.Run(fmt.Sprintf("P%d_P%d_P%d", combo[0]+1, combo[1]+1, combo[2]+1), func(t *testing.T) {
					signingPackages := []frost.KeyPackage{
						keyPackages[combo[0]],
						keyPackages[combo[1]],
						keyPackages[combo[2]],
					}

					// Round 1: Generate nonces and commitments
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

					// Round 2: Create signature shares
					signatureShares := make([]frost.SignatureShare, len(signingPackages))
					for i, participant := range participantObjs {
						share, err := participant.RoundTwo(nonces[i], message, commitments)
						if err != nil {
							t.Fatalf("Failed to sign: %v", err)
						}
						signatureShares[i] = share
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
						t.Fatalf("frost.Signature verification failed: %v", err)
					}

					t.Logf("✓ Combination P%d,P%d,P%d verified", combo[0]+1, combo[1]+1, combo[2]+1)
				})
			}

			t.Logf("✓ All 3-of-5 combinations verified")
		})
	}
}

// TestMultiCiphersuite_SignatureUniqueness verifies that each signing
// operation produces a unique signature (due to fresh nonces) across
// all ciphersuites.
func TestMultiCiphersuite_SignatureUniqueness(t *testing.T) {
	testCases := []struct {
		name        string
		ciphersuite ciphersuite.Ciphersuite
	}{
		{"ristretto255-sha512", ristretto255_sha512.New()},
		{"ed25519-sha512", ed25519_sha512.New()},
		{"p256-sha256", p256_sha256.New()},
		{"secp256k1-sha256", secp256k1_sha256.New()},
		{"ed448-shake256", ed448_shake256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.ciphersuite
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

			// Sign the same message multiple times
			message := []byte("Same message, different signatures")
			numSignatures := 5
			signatures := make([]frost.Signature, numSignatures)
			signingPackages := keyPackages[:2]

			for i := 0; i < numSignatures; i++ {
				// Round 1: Generate nonces and commitments
				participantObjs := make([]signing.Participant, len(signingPackages))
				nonces := make([]frost.SigningNonces, len(signingPackages))
				commitments := make(frost.CommitmentList, len(signingPackages))

				for j, pkg := range signingPackages {
					participantObjs[j] = signing.NewParticipant(pkg, suite)
					n, c, err := participantObjs[j].RoundOne()
					if err != nil {
						t.Fatalf("Failed to generate nonce: %v", err)
					}
					nonces[j] = n
					commitments[j] = c
				}

				// Round 2: Create signature shares
				signatureShares := make([]frost.SignatureShare, len(signingPackages))
				for j, participant := range participantObjs {
					share, err := participant.RoundTwo(nonces[j], message, commitments)
					if err != nil {
						t.Fatalf("Failed to sign: %v", err)
					}
					signatureShares[j] = share
				}

				// Aggregate signature
				aggregator := signing.NewAggregator(suite, minSigners)
				signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
				if err != nil {
					t.Fatalf("Failed to aggregate signature: %v", err)
				}

				signatures[i] = signature

				// Verify signature
				sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
				err = suite.VerifySignature(message, sigBytes, groupPublicKey)
				if err != nil {
					t.Fatalf("frost.Signature %d verification failed: %v", i, err)
				}
			}

			// Verify all signatures are unique (different R values due to different nonces)
			for i := 0; i < numSignatures; i++ {
				for j := i + 1; j < numSignatures; j++ {
					rBytesI := signatures[i].R.Bytes()
					rBytesJ := signatures[j].R.Bytes()
					if bytes.Equal(rBytesI, rBytesJ) {
						t.Errorf("Signatures %d and %d have identical R values", i, j)
					}
				}
			}

			t.Logf("✓ All %d signatures are unique", numSignatures)
		})
	}
}
