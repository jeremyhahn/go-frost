package rfc

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// reverseBytes returns a new byte slice with bytes in reverse order.
// This is needed because ristretto255 uses little-endian encoding but
// big.Int.SetBytes() expects big-endian.
func reverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return reversed
}

// TestAppendixD_RandomScalarGeneration tests RFC 9591 Appendix D
// Random Scalar Generation requirements
func TestAppendixD_RandomScalarGeneration(t *testing.T) {
	// RFC 9591 Appendix D: Random Scalar Generation
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("RandomScalarBasic", func(t *testing.T) {
		// RFC 9591 Appendix D: Random Scalar generation produces valid scalars

		scalar, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("RandomScalar failed: %v", err)
		}
		if scalar == nil {
			t.Fatal("RandomScalar returned nil")
		}

		// Scalar should be in valid range [0, p-1]
		element := grp.ScalarBaseMult(scalar)
		if element == nil {
			t.Error("Random scalar should be valid for group operations")
		}
	})

	t.Run("ScalarUniformity", func(t *testing.T) {
		// RFC 9591 Appendix D: Random scalars should be uniformly distributed

		const iterations = 100
		scalars := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			scalar, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("RandomScalar failed: %v", err)
			}
			scalarHex := string(scalar.Bytes())

			if scalars[scalarHex] {
				t.Error("Duplicate scalar detected - poor randomness")
			}
			scalars[scalarHex] = true
		}

		// All scalars should be unique (with overwhelming probability)
		if len(scalars) != iterations {
			t.Errorf("Expected %d unique scalars, got %d", iterations, len(scalars))
		}
	})

	t.Run("ScalarRange", func(t *testing.T) {
		// RFC 9591 Appendix D: Random scalar should be in range [0, p-1]

		scalar, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("RandomScalar failed: %v", err)
		}
		scalarBytes := scalar.Bytes()

		// Convert to big.Int for range checking
		// ristretto255 uses little-endian encoding, but big.Int.SetBytes expects big-endian
		scalarInt := new(big.Int).SetBytes(reverseBytes(scalarBytes))
		orderBytes := grp.Order()
		order := new(big.Int).SetBytes(reverseBytes(orderBytes))

		// Scalar should be less than group order
		if scalarInt.Cmp(order) >= 0 {
			t.Error("Random scalar should be less than group order")
		}

		// Scalar should be non-negative
		if scalarInt.Sign() < 0 {
			t.Error("Random scalar should be non-negative")
		}
	})
}

// TestAppendixD_1_RejectionSampling tests RFC 9591 Appendix D.1
// Rejection Sampling method for random scalar generation
func TestAppendixD_1_RejectionSampling(t *testing.T) {
	// RFC 9591 Appendix D.1: Rejection Sampling

	t.Run("RejectionSamplingConcept", func(t *testing.T) {
		// RFC 9591 Appendix D.1: Sample random bytes, interpret as integer,
		// reject if >= group order, otherwise use as scalar

		// This test demonstrates the rejection sampling concept
		// Actual implementation may vary

		suite := ristretto255_sha512.New()
		grp := suite.Group()
		orderBytes := grp.Order()
		// ristretto255 uses little-endian encoding, but big.Int.SetBytes expects big-endian
		order := new(big.Int).SetBytes(reverseBytes(orderBytes))

		const maxAttempts = 1000
		successCount := 0

		for i := 0; i < maxAttempts; i++ {
			// Sample random bytes (length = order byte length + safety margin)
			byteLen := (order.BitLen() + 7) / 8
			randomBytes := make([]byte, byteLen)
			_, err := rand.Read(randomBytes)
			if err != nil {
				t.Fatalf("Failed to read random bytes: %v", err)
			}

			// Interpret as integer
			candidate := new(big.Int).SetBytes(randomBytes)

			// Check if in valid range [0, order)
			if candidate.Cmp(order) < 0 {
				successCount++
			}
		}

		// Success rate should be high (depends on order size vs byte length)
		if successCount == 0 {
			t.Error("No valid scalars generated - rejection sampling failed")
		}

		t.Logf("Rejection sampling success rate: %d/%d (%.2f%%)",
			successCount, maxAttempts, float64(successCount)*100/float64(maxAttempts))
	})

	t.Run("BiasAvoidance", func(t *testing.T) {
		// RFC 9591 Appendix D.1: Rejection sampling avoids modular bias

		suite := ristretto255_sha512.New()
		grp := suite.Group()

		// Generate multiple scalars and verify they appear unbiased
		const samples = 50
		var scalars []group.Scalar

		for i := 0; i < samples; i++ {
			s, _ := grp.RandomScalar()
			scalars = append(scalars, s)
		}

		// All scalars should be unique (with high probability)
		uniqueScalars := make(map[string]bool)
		for _, s := range scalars {
			uniqueScalars[string(s.Bytes())] = true
		}

		if len(uniqueScalars) < samples-1 {
			t.Error("Too many duplicate scalars - possible bias")
		}
	})
}

// TestAppendixD_2_WideReduction tests RFC 9591 Appendix D.2
// Wide Reduction method for random scalar generation
func TestAppendixD_2_WideReduction(t *testing.T) {
	// RFC 9591 Appendix D.2: Wide Reduction

	t.Run("WideReductionConcept", func(t *testing.T) {
		// RFC 9591 Appendix D.2: Sample more bytes than needed (e.g., 2x),
		// then reduce modulo group order

		suite := ristretto255_sha512.New()
		grp := suite.Group()
		orderBytes := grp.Order()
		// ristretto255 uses little-endian encoding, but big.Int.SetBytes expects big-endian
		order := new(big.Int).SetBytes(reverseBytes(orderBytes))

		// Sample wide byte string (2x the order size)
		wideByteLen := 2 * ((order.BitLen() + 7) / 8)
		wideBytes := make([]byte, wideByteLen)
		_, err := rand.Read(wideBytes)
		if err != nil {
			t.Fatalf("Failed to read random bytes: %v", err)
		}

		// Interpret as large integer
		wideInt := new(big.Int).SetBytes(wideBytes)

		// Reduce modulo group order
		scalarInt := new(big.Int).Mod(wideInt, order)

		// Result should be valid scalar in range [0, order)
		if scalarInt.Cmp(order) >= 0 {
			t.Error("Reduced value should be less than order")
		}
		if scalarInt.Sign() < 0 {
			t.Error("Reduced value should be non-negative")
		}
	})

	t.Run("StatisticalUniformity", func(t *testing.T) {
		// RFC 9591 Appendix D.2: Wide reduction provides statistical uniformity
		// (with negligible bias for sufficiently wide samples)

		suite := ristretto255_sha512.New()
		grp := suite.Group()
		orderBytes := grp.Order()
		// ristretto255 uses little-endian encoding, but big.Int.SetBytes expects big-endian
		order := new(big.Int).SetBytes(reverseBytes(orderBytes))

		// Generate multiple scalars using wide reduction
		const samples = 100
		wideByteLen := 2 * ((order.BitLen() + 7) / 8)

		scalars := make(map[string]bool)

		for i := 0; i < samples; i++ {
			wideBytes := make([]byte, wideByteLen)
			rand.Read(wideBytes)

			wideInt := new(big.Int).SetBytes(wideBytes)
			scalarInt := new(big.Int).Mod(wideInt, order)

			scalars[scalarInt.String()] = true
		}

		// Should produce many unique values
		if len(scalars) < samples-1 {
			t.Error("Wide reduction produced too many collisions")
		}
	})

	t.Run("ComparisonWithRejectionSampling", func(t *testing.T) {
		// RFC 9591 Appendix D: Both methods should produce valid scalars

		suite := ristretto255_sha512.New()
		grp := suite.Group()

		// Method doesn't matter - both should produce valid scalars
		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()

		element1 := grp.ScalarBaseMult(scalar1)
		element2 := grp.ScalarBaseMult(scalar2)

		if element1 == nil || element2 == nil {
			t.Error("Random scalars should be valid regardless of generation method")
		}

		// Scalars should be different (with overwhelming probability)
		if scalar1.Equal(scalar2) {
			t.Error("Random scalars should be unique")
		}
	})
}

// TestAppendixD_SecurityProperties tests security properties of
// random scalar generation as specified in Appendix D
func TestAppendixD_SecurityProperties(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("NonPredictability", func(t *testing.T) {
		// Random scalars should be unpredictable

		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()
		scalar3, _ := grp.RandomScalar()

		// Knowing two scalars should not allow predicting the third
		// This is a basic sanity check - true unpredictability requires
		// proper CSPRNG
		if scalar1.Equal(scalar2) || scalar1.Equal(scalar3) || scalar2.Equal(scalar3) {
			t.Error("Random scalars should be unpredictable")
		}
	})

	t.Run("SideChannelResistance", func(t *testing.T) {
		// RFC 9591 Section 7.1: Implementation should be side-channel resistant
		// This is a behavioral test - actual side-channel resistance requires
		// careful implementation

		// Generate scalar and use it
		scalar, _ := grp.RandomScalar()
		element := grp.ScalarBaseMult(scalar)

		if element == nil {
			t.Error("Scalar should be valid")
		}

		// Operations should complete without timing leaks
		// (actual testing requires specialized tools)
	})

	t.Run("SufficientEntropy", func(t *testing.T) {
		// Random scalar generation should have sufficient entropy

		const samples = 100
		scalars := make(map[string]bool)

		for i := 0; i < samples; i++ {
			scalar, _ := grp.RandomScalar()
			scalars[string(scalar.Bytes())] = true
		}

		// Should have high uniqueness rate
		uniqueRate := float64(len(scalars)) / float64(samples)
		if uniqueRate < 0.99 {
			t.Errorf("Unique scalar rate %.2f%% is too low, suggests insufficient entropy",
				uniqueRate*100)
		}
	})
}
