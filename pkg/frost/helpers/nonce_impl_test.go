package helpers

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestNonceGenerator_Generate_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	// Create a test secret scalar
	secret, err := suite.Group().RandomScalar()
	if err != nil {
		t.Fatalf("failed to create random scalar: %v", err)
	}

	// Generate a nonce
	nonce, err := generator.Generate(secret)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Verify nonce is not nil
	if nonce == nil {
		t.Fatal("Generate() returned nil nonce")
	}

	// Verify nonce is not zero
	if nonce.IsZero() {
		t.Error("Generate() returned zero nonce")
	}

	// Verify nonces are different when called multiple times
	nonce2, err := generator.Generate(secret)
	if err != nil {
		t.Fatalf("Generate() second call failed: %v", err)
	}

	if nonce.Equal(nonce2) {
		t.Error("Generate() returned identical nonces on consecutive calls")
	}
}

func TestNonceGenerator_Generate_DifferentSecrets(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	// Create two different secret scalars
	secret1, err := suite.Group().RandomScalar()
	if err != nil {
		t.Fatalf("failed to create first random scalar: %v", err)
	}

	secret2, err := suite.Group().RandomScalar()
	if err != nil {
		t.Fatalf("failed to create second random scalar: %v", err)
	}

	// Generate nonces for both secrets
	nonce1, err := generator.Generate(secret1)
	if err != nil {
		t.Fatalf("Generate() failed for secret1: %v", err)
	}

	nonce2, err := generator.Generate(secret2)
	if err != nil {
		t.Fatalf("Generate() failed for secret2: %v", err)
	}

	// Nonces should be different (with overwhelming probability)
	if nonce1.Equal(nonce2) {
		t.Error("Generate() returned identical nonces for different secrets")
	}
}

func TestNonceGenerator_Generate_ZeroSecret(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	// Create a zero scalar
	zeroSecret := suite.Group().NewScalar()

	// Generate should still succeed with zero secret (it combines with randomness)
	nonce, err := generator.Generate(zeroSecret)
	if err != nil {
		t.Fatalf("Generate() failed with zero secret: %v", err)
	}

	// Verify nonce is not nil and not zero
	if nonce == nil {
		t.Fatal("Generate() returned nil nonce with zero secret")
	}

	if nonce.IsZero() {
		t.Error("Generate() returned zero nonce with zero secret")
	}
}

func TestNonceGenerator_Generate_Deterministic(t *testing.T) {
	// This test verifies that the same randomness + secret produces the same nonce
	// However, since we use crypto/rand internally, we can't easily test this
	// without modifying the implementation. This test is more for documentation.
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	secret, err := suite.Group().RandomScalar()
	if err != nil {
		t.Fatalf("failed to create random scalar: %v", err)
	}

	// Multiple calls should produce different nonces due to fresh randomness
	nonce1, err := generator.Generate(secret)
	if err != nil {
		t.Fatalf("first Generate() failed: %v", err)
	}

	nonce2, err := generator.Generate(secret)
	if err != nil {
		t.Fatalf("second Generate() failed: %v", err)
	}

	// With fresh randomness each time, nonces should be different
	if nonce1.Equal(nonce2) {
		t.Error("Generate() produced identical nonces with fresh randomness")
	}
}

func TestNonceGenerator_Generate_RandomnessQuality(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	secret, err := suite.Group().RandomScalar()
	if err != nil {
		t.Fatalf("failed to create random scalar: %v", err)
	}

	// Generate many nonces and check for uniqueness
	nonces := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		nonce, err := generator.Generate(secret)
		if err != nil {
			t.Fatalf("Generate() failed on iteration %d: %v", i, err)
		}

		nonceBytes := nonce.Bytes()
		nonceStr := string(nonceBytes)

		if nonces[nonceStr] {
			t.Errorf("Generate() produced duplicate nonce on iteration %d", i)
		}
		nonces[nonceStr] = true
	}

	if len(nonces) != iterations {
		t.Errorf("Expected %d unique nonces, got %d", iterations, len(nonces))
	}
}

// BenchmarkNonceGenerate benchmarks the nonce generation performance
func BenchmarkNonceGenerate(b *testing.B) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	secret, err := suite.Group().RandomScalar()
	if err != nil {
		b.Fatalf("failed to create random scalar: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.Generate(secret)
		if err != nil {
			b.Fatalf("Generate() failed: %v", err)
		}
	}
}

// TestNonceGenerator_Generate_BadRandom tests behavior when random source is exhausted
// This is difficult to test without mocking crypto/rand, so we document the expected behavior
func TestNonceGenerator_Generate_NilSecret(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	generator := NewNonceGenerator(suite)

	// Attempting to generate with nil secret should handle gracefully
	// The implementation should either handle nil or panic - we test for consistent behavior
	defer func() {
		if r := recover(); r != nil {
			// Panic is acceptable for nil input
			t.Logf("Generate() panicked with nil secret (expected): %v", r)
		}
	}()

	// This may panic or return an error depending on implementation
	_, err := generator.Generate(nil)
	if err != nil {
		t.Logf("Generate() returned error with nil secret (acceptable): %v", err)
	}
}
