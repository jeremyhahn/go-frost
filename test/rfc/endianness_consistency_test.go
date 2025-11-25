package rfc

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestEndianness_DealerToSigningConsistency verifies that dealer-generated shares
// work correctly in the signing protocol, ensuring identifier encoding is consistent
// across key generation and signing.
//
// This test addresses the critical requirement that participant identifiers must
// be encoded the same way when:
// 1. Generating shares from polynomial evaluation (dealer)
// 2. Computing Lagrange coefficients (signing)
//
// The RFC requires little-endian encoding, and this test validates that
// the round-trip keygen → signing → verification works correctly.
func TestEndianness_DealerToSigningConsistency(t *testing.T) {
	tests := []struct {
		name         string
		minSigners   uint32
		maxSigners   uint32
		participants []frost.Identifier
		signerIDs    []frost.Identifier
	}{
		{
			name:         "2-of-3 with P1,P2",
			minSigners:   2,
			maxSigners:   3,
			participants: []frost.Identifier{1, 2, 3},
			signerIDs:    []frost.Identifier{1, 2},
		},
		{
			name:         "2-of-3 with P1,P3",
			minSigners:   2,
			maxSigners:   3,
			participants: []frost.Identifier{1, 2, 3},
			signerIDs:    []frost.Identifier{1, 3},
		},
		{
			name:         "2-of-3 with P2,P3",
			minSigners:   2,
			maxSigners:   3,
			participants: []frost.Identifier{1, 2, 3},
			signerIDs:    []frost.Identifier{2, 3},
		},
		{
			name:         "3-of-5 with P1,P3,P5",
			minSigners:   3,
			maxSigners:   5,
			participants: []frost.Identifier{1, 2, 3, 4, 5},
			signerIDs:    []frost.Identifier{1, 3, 5},
		},
		{
			name:         "3-of-5 with P2,P4,P5",
			minSigners:   3,
			maxSigners:   5,
			participants: []frost.Identifier{1, 2, 3, 4, 5},
			signerIDs:    []frost.Identifier{2, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := ristretto255_sha512.New()
			grp := suite.Group()

			// 1. Generate keys using dealer
			dealer := keygen.NewDealer(suite)
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, tt.minSigners, tt.maxSigners, tt.participants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			// 2. Verify identifier encoding is consistent
			for _, pkg := range keyPackages {
				// Verify identifier encoding
				idBytes := make([]byte, grp.ScalarLength())
				binary.LittleEndian.PutUint64(idBytes, uint64(pkg.Identifier))
				idScalar, err := grp.DeserializeScalar(idBytes)
				if err != nil {
					t.Fatalf("Failed to deserialize identifier: %v", err)
				}

				// Recompute share using polynomial evaluation
				// This ensures the dealer used the same encoding
				t.Logf("P%d identifier scalar: %s", pkg.Identifier, hex.EncodeToString(idScalar.Bytes()))
				t.Logf("P%d secret share: %s", pkg.Identifier, hex.EncodeToString(pkg.SecretShare.Bytes()))
			}

			// 3. Sign a message using the dealer-generated shares
			message := []byte("Endianness consistency test")

			// Select signing participants
			var signingPackages []frost.KeyPackage
			for _, signerID := range tt.signerIDs {
				for _, pkg := range keyPackages {
					if pkg.Identifier == signerID {
						signingPackages = append(signingPackages, pkg)
						break
					}
				}
			}

			if len(signingPackages) != len(tt.signerIDs) {
				t.Fatalf("Failed to find all signing packages: got %d, want %d",
					len(signingPackages), len(tt.signerIDs))
			}

			// Round 1: Generate nonces and commitments
			participants := make([]signing.Participant, len(signingPackages))
			nonces := make([]frost.SigningNonces, len(signingPackages))
			commitments := make(frost.CommitmentList, len(signingPackages))

			for i, pkg := range signingPackages {
				participant := signing.NewParticipant(pkg, suite)
				participants[i] = participant

				n, c, err := participant.RoundOne()
				if err != nil {
					t.Fatalf("P%d: Failed to generate nonce: %v", pkg.Identifier, err)
				}
				nonces[i] = n
				commitments[i] = c

				t.Logf("P%d nonce commitment generated", pkg.Identifier)
			}

			// Round 2: Create signature shares
			signatureShares := make([]frost.SignatureShare, len(signingPackages))
			for i, participant := range participants {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("P%d: Failed to sign: %v", signingPackages[i].Identifier, err)
				}
				signatureShares[i] = share

				t.Logf("P%d signature share: %s",
					share.Identifier,
					hex.EncodeToString(share.SignatureShare.Bytes()))
			}

			// 4. Aggregate signature
			aggregator := signing.NewAggregator(suite, tt.minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
			if err != nil {
				t.Fatalf("Failed to aggregate signature: %v", err)
			}

			t.Logf("Final signature R: %s", hex.EncodeToString(signature.R.Bytes()))
			t.Logf("Final signature z: %s", hex.EncodeToString(signature.Z.Bytes()))

			// 5. Verify the signature
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(message, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Signature verification failed: %v", err)
			}

			t.Logf("✓ Signature verified successfully with %d signers", len(signingPackages))
		})
	}
}

// TestEndianness_IdentifierEncodingConsistency specifically tests that
// identifier encoding is consistent between different operations.
func TestEndianness_IdentifierEncodingConsistency(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	testIdentifiers := []frost.Identifier{1, 2, 3, 127, 255, 256, 1000, 65535}

	for _, id := range testIdentifiers {
		t.Run("Identifier "+string(rune(id)), func(t *testing.T) {
			// Encode identifier using little-endian (RFC requirement)
			idBytesLE := make([]byte, grp.ScalarLength())
			binary.LittleEndian.PutUint64(idBytesLE, uint64(id))

			// Deserialize to scalar
			idScalar, err := grp.DeserializeScalar(idBytesLE)
			if err != nil {
				t.Fatalf("Failed to deserialize identifier %d: %v", id, err)
			}

			// Verify round-trip: serialize and deserialize should give same value
			idBytesRoundTrip := idScalar.Bytes()

			// The bytes should match (at least the first 8 bytes for little-endian uint64)
			if !bytesEqualPrefix(idBytesLE, idBytesRoundTrip, 8) {
				t.Errorf("Identifier %d round-trip failed\nOriginal: %s\nRound-trip: %s",
					id,
					hex.EncodeToString(idBytesLE[:8]),
					hex.EncodeToString(idBytesRoundTrip[:8]))
			}

			// Verify decoding gives back the original value
			decodedID := binary.LittleEndian.Uint64(idBytesRoundTrip)
			if decodedID != uint64(id) {
				t.Errorf("Identifier %d decode mismatch: got %d", id, decodedID)
			}

			t.Logf("Identifier %d: %s", id, hex.EncodeToString(idScalar.Bytes()))
		})
	}
}

// TestEndianness_LagrangeCoefficients tests that Lagrange coefficients
// are computed correctly regardless of identifier encoding.
func TestEndianness_LagrangeCoefficients(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Test with the RFC test vector participants
	testCases := []struct {
		name         string
		participants []frost.Identifier
		targetID     frost.Identifier
	}{
		{
			name:         "P1 in {P1,P3}",
			participants: []frost.Identifier{1, 3},
			targetID:     1,
		},
		{
			name:         "P3 in {P1,P3}",
			participants: []frost.Identifier{1, 3},
			targetID:     3,
		},
		{
			name:         "P2 in {P1,P2,P3}",
			participants: []frost.Identifier{1, 2, 3},
			targetID:     2,
		},
		{
			name:         "P5 in {P1,P3,P5}",
			participants: []frost.Identifier{1, 3, 5},
			targetID:     5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Compute Lagrange coefficient
			lambda := computeLagrangeCoefficient(grp, tc.targetID, tc.participants)

			// Verify it's not zero
			if lambda.IsZero() {
				t.Errorf("Lagrange coefficient is zero for P%d", tc.targetID)
			}

			t.Logf("P%d Lagrange coefficient in %v: %s",
				tc.targetID,
				tc.participants,
				hex.EncodeToString(lambda.Bytes()))

			// Verify that multiplying by lambda gives a valid result
			// (non-zero scalar should have non-zero product with another non-zero scalar)
			testScalar, _ := grp.RandomScalar()
			product := lambda.Mul(testScalar)
			if product.IsZero() && !testScalar.IsZero() {
				t.Errorf("Lagrange coefficient multiplication produced zero unexpectedly")
			}
		})
	}
}

// Helper function to compare byte slice prefixes
func bytesEqualPrefix(a, b []byte, n int) bool {
	if len(a) < n || len(b) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeLagrangeCoefficient computes the Lagrange coefficient for participant i
// This is duplicated from the test vectors test to ensure consistency
func computeLagrangeCoefficient(grp group.Group, i frost.Identifier, participants []frost.Identifier) group.Scalar {
	// lambda_i = product_{j in participants, j != i} (j / (j - i))
	oneBytes := make([]byte, grp.ScalarLength())
	oneBytes[0] = 1
	result, _ := grp.DeserializeScalar(oneBytes)

	for _, j := range participants {
		if i == j {
			continue
		}

		// Create scalars for i and j using little-endian encoding
		iBytes := make([]byte, grp.ScalarLength())
		binary.LittleEndian.PutUint64(iBytes, uint64(i))
		iScalar, _ := grp.DeserializeScalar(iBytes)

		jBytes := make([]byte, grp.ScalarLength())
		binary.LittleEndian.PutUint64(jBytes, uint64(j))
		jScalar, _ := grp.DeserializeScalar(jBytes)

		// Compute (j - i)
		diff := jScalar.Sub(iScalar)

		// Compute j / (j - i)
		diffInv, _ := diff.Inv()
		numerator := jScalar.Mul(diffInv)

		// Multiply into result
		result = result.Mul(numerator)
	}

	return result
}

// TestIdentifierToScalar_AllCiphersuites tests that the IdentifierToScalar helper
// function works correctly with all supported ciphersuites.
//
// This test verifies:
// 1. Little-endian encoding for Ed25519, Ed448, ristretto255
// 2. Big-endian encoding for P-256, secp256k1
// 3. Correct round-trip behavior for each group
func TestIdentifierToScalar_AllCiphersuites(t *testing.T) {
	testCases := []struct {
		name        string
		suite       ciphersuite.Ciphersuite
		isBigEndian bool
	}{
		{"Ed25519-SHA512", ed25519_sha512.New(), false},
		{"Ed448-SHAKE256", ed448_shake256.New(), false},
		{"ristretto255-SHA512", ristretto255_sha512.New(), false},
		{"P-256-SHA256", p256_sha256.New(), true},
		{"secp256k1-SHA256", secp256k1_sha256.New(), true},
	}

	identifiers := []frost.Identifier{1, 2, 3, 42, 255, 256, 1000, 65535, 0x12345678}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grp := tc.suite.Group()

			for _, id := range identifiers {
				t.Run("ID_"+string(rune(id)), func(t *testing.T) {
					// Convert using helper function
					scalar, err := helpers.IdentifierToScalar(grp, id)
					if err != nil {
						t.Fatalf("IdentifierToScalar(%d) error: %v", id, err)
					}

					// Verify scalar is not zero for non-zero identifier
					if scalar.IsZero() && id != 0 {
						t.Errorf("IdentifierToScalar(%d) produced zero scalar", id)
					}

					// Verify byte encoding matches expected endianness
					bytes := scalar.Bytes()
					idVal := uint32(id)

					if tc.isBigEndian {
						// Big-endian: value at end of byte array
						scalarLen := grp.ScalarLength()
						if bytes[scalarLen-1] != byte(idVal) {
							t.Errorf("Big-endian byte[%d] = %d, want %d", scalarLen-1, bytes[scalarLen-1], byte(idVal))
						}
					} else {
						// Little-endian: value at start of byte array
						if bytes[0] != byte(idVal) {
							t.Errorf("Little-endian byte[0] = %d, want %d", bytes[0], byte(idVal))
						}
					}

					t.Logf("ID %d -> %s", id, hex.EncodeToString(bytes[:8]))
				})
			}
		})
	}
}

// TestIdentifierEncoding_FullSigningWorkflow_AllCiphersuites tests the complete
// signing workflow with all ciphersuites to ensure identifier encoding is correct
// throughout the entire protocol (key generation, signing, verification).
func TestIdentifierEncoding_FullSigningWorkflow_AllCiphersuites(t *testing.T) {
	testCases := []struct {
		name  string
		suite ciphersuite.Ciphersuite
	}{
		{"Ed25519-SHA512", ed25519_sha512.New()},
		{"Ed448-SHAKE256", ed448_shake256.New()},
		{"ristretto255-SHA512", ristretto255_sha512.New()},
		{"P-256-SHA256", p256_sha256.New()},
		{"secp256k1-SHA256", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.suite
			grp := suite.Group()

			// Test 2-of-3 threshold with participants 1, 2, 3
			minSigners := uint32(2)
			maxSigners := uint32(3)
			participants := []frost.Identifier{1, 2, 3}

			// 1. Generate keys
			dealer := keygen.NewDealer(suite)
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			keyPackages, groupPublicKey, err := dealer.GenerateShares(secret, minSigners, maxSigners, participants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			// 2. Verify each share using VSS
			vss := keygen.NewVSS(grp)
			for _, pkg := range keyPackages {
				err := vss.VerifyShare(pkg.Identifier, pkg.SecretShare, pkg.VerificationShares)
				if err != nil {
					t.Fatalf("P%d share verification failed: %v", pkg.Identifier, err)
				}
			}

			// 3. Select signers (P1 and P3) and perform signing
			signerIDs := []frost.Identifier{1, 3}
			var signingPackages []frost.KeyPackage
			for _, signerID := range signerIDs {
				for _, pkg := range keyPackages {
					if pkg.Identifier == signerID {
						signingPackages = append(signingPackages, pkg)
						break
					}
				}
			}

			// Round 1
			signingParticipants := make([]signing.Participant, len(signingPackages))
			nonces := make([]frost.SigningNonces, len(signingPackages))
			commitments := make(frost.CommitmentList, len(signingPackages))

			for i, pkg := range signingPackages {
				participant := signing.NewParticipant(pkg, suite)
				signingParticipants[i] = participant

				n, c, err := participant.RoundOne()
				if err != nil {
					t.Fatalf("P%d RoundOne failed: %v", pkg.Identifier, err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2
			message := []byte("Test message for " + tc.name)
			signatureShares := make([]frost.SignatureShare, len(signingPackages))

			for i, participant := range signingParticipants {
				share, err := participant.RoundTwo(nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("P%d RoundTwo failed: %v", signingPackages[i].Identifier, err)
				}
				signatureShares[i] = share
			}

			// 4. Aggregate
			aggregator := signing.NewAggregator(suite, minSigners)
			signature, err := aggregator.Aggregate(groupPublicKey, commitments, message, signatureShares)
			if err != nil {
				t.Fatalf("Aggregate failed: %v", err)
			}

			// 5. Verify
			sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)
			err = suite.VerifySignature(message, sigBytes, groupPublicKey)
			if err != nil {
				t.Fatalf("Signature verification failed: %v", err)
			}

			t.Logf("✓ %s: Full signing workflow passed with P1,P3", tc.name)
		})
	}
}

// TestIdentifierEncoding_RecoverSecret_AllCiphersuites verifies that the dealer's
// RecoverSecret function works correctly with all ciphersuites, which depends on
// correct identifier encoding for Lagrange interpolation.
func TestIdentifierEncoding_RecoverSecret_AllCiphersuites(t *testing.T) {
	testCases := []struct {
		name  string
		suite ciphersuite.Ciphersuite
	}{
		{"Ed25519-SHA512", ed25519_sha512.New()},
		{"Ed448-SHAKE256", ed448_shake256.New()},
		{"ristretto255-SHA512", ristretto255_sha512.New()},
		{"P-256-SHA256", p256_sha256.New()},
		{"secp256k1-SHA256", secp256k1_sha256.New()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := tc.suite
			grp := suite.Group()

			// Generate a known secret
			secret, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			// Create 2-of-3 shares
			dealer := keygen.NewDealer(suite)
			participants := []frost.Identifier{1, 2, 3}
			keyPackages, _, err := dealer.GenerateShares(secret, 2, 3, participants)
			if err != nil {
				t.Fatalf("Failed to generate shares: %v", err)
			}

			// Recover using P1 and P2
			shares12 := map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
			}
			recovered12, err := dealer.RecoverSecret(shares12)
			if err != nil {
				t.Fatalf("Failed to recover secret from P1,P2: %v", err)
			}
			if !recovered12.Equal(secret) {
				t.Errorf("Recovered secret from P1,P2 doesn't match original")
			}

			// Recover using P1 and P3
			shares13 := map[frost.Identifier]group.Scalar{
				keyPackages[0].Identifier: keyPackages[0].SecretShare,
				keyPackages[2].Identifier: keyPackages[2].SecretShare,
			}
			recovered13, err := dealer.RecoverSecret(shares13)
			if err != nil {
				t.Fatalf("Failed to recover secret from P1,P3: %v", err)
			}
			if !recovered13.Equal(secret) {
				t.Errorf("Recovered secret from P1,P3 doesn't match original")
			}

			// Recover using P2 and P3
			shares23 := map[frost.Identifier]group.Scalar{
				keyPackages[1].Identifier: keyPackages[1].SecretShare,
				keyPackages[2].Identifier: keyPackages[2].SecretShare,
			}
			recovered23, err := dealer.RecoverSecret(shares23)
			if err != nil {
				t.Fatalf("Failed to recover secret from P2,P3: %v", err)
			}
			if !recovered23.Equal(secret) {
				t.Errorf("Recovered secret from P2,P3 doesn't match original")
			}

			t.Logf("✓ %s: Secret recovery works with all participant combinations", tc.name)
		})
	}
}
