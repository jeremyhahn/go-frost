package ed448_shake256

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
)

// TestCiphersuiteInterface verifies that Ed448SHAKE256 implements the Ciphersuite interface
func TestCiphersuiteInterface(t *testing.T) {
	suite := New()
	var _ ciphersuite.Ciphersuite = suite
}

// TestCiphersuiteID tests the ciphersuite ID
func TestCiphersuiteID(t *testing.T) {
	suite := New()

	expected := "FROST-ED448-SHAKE256-v1"
	if suite.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, suite.ID())
	}
}

// TestCiphersuiteName tests the ciphersuite name
func TestCiphersuiteName(t *testing.T) {
	suite := New()

	expected := "FROST(Ed448, SHAKE256)"
	if suite.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, suite.Name())
	}
}

// TestContextString tests the context string
func TestContextString(t *testing.T) {
	suite := New()

	expected := "FROST-ED448-SHAKE256-v1"
	if suite.ContextString() != expected {
		t.Errorf("Expected context string %s, got %s", expected, suite.ContextString())
	}
}

// TestGroup tests that the group implementation is returned
func TestGroup(t *testing.T) {
	suite := New()

	group := suite.Group()
	if group == nil {
		t.Fatal("Group() returned nil")
	}

	// Verify group properties
	if group.Name() != "ed448" {
		t.Errorf("Expected group name 'ed448', got %s", group.Name())
	}

	// Element length should be 57 bytes for Ed448
	if group.ElementLength() != 57 {
		t.Errorf("Expected element length 57, got %d", group.ElementLength())
	}

	// Scalar length should be 57 bytes for Ed448
	if group.ScalarLength() != 57 {
		t.Errorf("Expected scalar length 57, got %d", group.ScalarLength())
	}
}

// TestHash tests the underlying SHAKE256 hash function
func TestHash(t *testing.T) {
	suite := New()

	testCases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty input",
			input: []byte{},
		},
		{
			name:  "simple message",
			input: []byte("test"),
		},
		{
			name:  "longer message",
			input: []byte("The quick brown fox jumps over the lazy dog"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := suite.Hash(tc.input)

			// SHAKE256 is configured to produce 114 bytes (2x scalar size)
			if len(result) != 114 {
				t.Errorf("Expected hash length 114, got %d", len(result))
			}

			// Hash should be deterministic
			result2 := suite.Hash(tc.input)
			if !bytes.Equal(result, result2) {
				t.Error("Hash should be deterministic")
			}
		})
	}
}

// TestH1 tests the H1 hash function (binding factor)
func TestH1(t *testing.T) {
	suite := New()

	// H1 should be domain-separated with contextString + "rho"
	input := []byte("test input")
	result := suite.H1(input)

	if result == nil {
		t.Fatal("H1 returned nil")
	}

	// Result should be a scalar
	if result.IsZero() {
		t.Error("H1 result should not be zero for non-empty input")
	}

	// Same input should produce same output (deterministic)
	result2 := suite.H1(input)
	if !result.Equal(result2) {
		t.Error("H1 should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.H1([]byte("different input"))
	if result.Equal(result3) {
		t.Error("H1 should produce different outputs for different inputs")
	}
}

// TestH2 tests the H2 hash function (challenge)
func TestH2(t *testing.T) {
	suite := New()

	// CRITICAL: H2 for Ed448 does NOT use contextString prefix
	// This is for Ed448 signature compatibility
	input := []byte("test input")
	result := suite.H2(input)

	if result == nil {
		t.Fatal("H2 returned nil")
	}

	// Result should be a scalar
	if result.IsZero() {
		t.Error("H2 result should not be zero for non-empty input")
	}

	// Same input should produce same output (deterministic)
	result2 := suite.H2(input)
	if !result.Equal(result2) {
		t.Error("H2 should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.H2([]byte("different input"))
	if result.Equal(result3) {
		t.Error("H2 should produce different outputs for different inputs")
	}
}

// TestH2NoContextString tests that H2 does NOT use contextString
func TestH2NoContextString(t *testing.T) {
	suite := New()

	// Test that H2 does NOT include context string
	input := []byte("test")

	// Get the result from H2
	result := suite.H2(input)

	// Create what H1 would produce (with context string)
	h1Result := suite.H1(input)

	// H2 and H1 should produce different results for same input
	// because H2 does NOT use context string while H1 does
	if result.Equal(h1Result) {
		t.Error("H2 should NOT use context string (should differ from H1)")
	}
}

// TestH3 tests the H3 hash function (nonce generation)
func TestH3(t *testing.T) {
	suite := New()

	input := []byte("test input")
	result := suite.H3(input)

	if result == nil {
		t.Fatal("H3 returned nil")
	}

	// Result should be a scalar
	if result.IsZero() {
		t.Error("H3 result should not be zero for non-empty input")
	}

	// Same input should produce same output (deterministic)
	result2 := suite.H3(input)
	if !result.Equal(result2) {
		t.Error("H3 should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.H3([]byte("different input"))
	if result.Equal(result3) {
		t.Error("H3 should produce different outputs for different inputs")
	}
}

// TestH4 tests the H4 hash function (message hashing)
func TestH4(t *testing.T) {
	suite := New()

	input := []byte("test message")
	result := suite.H4(input)

	if len(result) == 0 {
		t.Fatal("H4 returned empty result")
	}

	// Result should be 114 bytes
	if len(result) != 114 {
		t.Errorf("Expected result length 114, got %d", len(result))
	}

	// Same input should produce same output (deterministic)
	result2 := suite.H4(input)
	if !bytes.Equal(result, result2) {
		t.Error("H4 should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.H4([]byte("different message"))
	if bytes.Equal(result, result3) {
		t.Error("H4 should produce different outputs for different inputs")
	}
}

// TestH5 tests the H5 hash function (commitment list hashing)
func TestH5(t *testing.T) {
	suite := New()

	input := []byte("test commitment list")
	result := suite.H5(input)

	if len(result) == 0 {
		t.Fatal("H5 returned empty result")
	}

	// Result should be 114 bytes
	if len(result) != 114 {
		t.Errorf("Expected result length 114, got %d", len(result))
	}

	// Same input should produce same output (deterministic)
	result2 := suite.H5(input)
	if !bytes.Equal(result, result2) {
		t.Error("H5 should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.H5([]byte("different commitment list"))
	if bytes.Equal(result, result3) {
		t.Error("H5 should produce different outputs for different inputs")
	}
}

// TestHashToCurve tests the hash-to-curve function
func TestHashToCurve(t *testing.T) {
	suite := New()

	input := []byte("test data for hash to curve")
	point, err := suite.HashToCurve(input)
	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}

	if point == nil {
		t.Fatal("HashToCurve returned nil point")
	}

	// Point should not be identity
	if point.IsIdentity() {
		t.Error("HashToCurve should not return identity point")
	}

	// Same input should produce same output (deterministic)
	point2, err := suite.HashToCurve(input)
	if err != nil {
		t.Fatalf("HashToCurve failed on second call: %v", err)
	}

	if !point.Equal(point2) {
		t.Error("HashToCurve should be deterministic")
	}

	// Different input should produce different output
	point3, err := suite.HashToCurve([]byte("different data"))
	if err != nil {
		t.Fatalf("HashToCurve failed with different input: %v", err)
	}

	if point.Equal(point3) {
		t.Error("HashToCurve should produce different outputs for different inputs")
	}
}

// TestVerifySignature tests signature verification
func TestVerifySignature(t *testing.T) {
	suite := New()
	group := suite.Group()

	// Generate a key pair for testing
	secretKey, err := group.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	publicKey := group.ScalarBaseMult(secretKey)

	// Create a test message
	message := []byte("test message for signing")

	// Generate a random nonce
	nonce, err := group.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Compute commitment R = nonce * G
	R := group.ScalarBaseMult(nonce)

	// Serialize R
	rBytes, err := group.SerializeElement(R)
	if err != nil {
		t.Fatalf("Failed to serialize R: %v", err)
	}

	// Compute challenge: c = H2(R || PK || msg)
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(rBytes)
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)

	c := suite.H2(challengeInput.Bytes())

	// Compute response: z = nonce + c * secretKey
	cSk := c.Mul(secretKey)
	z := nonce.Add(cSk)

	// Serialize z
	zBytes := group.SerializeScalar(z)

	// Create signature: R || z
	signature := append(rBytes, zBytes...)

	// Verify signature
	err = suite.VerifySignature(message, signature, publicKey)
	if err != nil {
		t.Errorf("Valid signature verification failed: %v", err)
	}
}

// TestVerifySignatureInvalid tests signature verification with invalid inputs
func TestVerifySignatureInvalid(t *testing.T) {
	suite := New()
	group := suite.Group()

	// Generate a key pair
	secretKey, _ := group.RandomScalar()
	publicKey := group.ScalarBaseMult(secretKey)
	message := []byte("test message")

	// Create a valid signature first
	nonce, _ := group.RandomScalar()
	R := group.ScalarBaseMult(nonce)
	rBytes, _ := group.SerializeElement(R)

	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(rBytes)
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)

	c := suite.H2(challengeInput.Bytes())
	z := nonce.Add(c.Mul(secretKey))
	zBytes := group.SerializeScalar(z)
	validSignature := append(rBytes, zBytes...)

	t.Run("nil public key", func(t *testing.T) {
		err := suite.VerifySignature(message, validSignature, nil)
		if err == nil {
			t.Error("Expected error for nil public key")
		}
	})

	t.Run("identity public key", func(t *testing.T) {
		identity := group.Identity()
		err := suite.VerifySignature(message, validSignature, identity)
		if err == nil {
			t.Error("Expected error for identity public key")
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		wrongSig := []byte{1, 2, 3}
		err := suite.VerifySignature(message, wrongSig, publicKey)
		if err == nil {
			t.Error("Expected error for wrong signature length")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		tamperedSig := make([]byte, len(validSignature))
		copy(tamperedSig, validSignature)
		tamperedSig[0] ^= 1 // Flip one bit

		err := suite.VerifySignature(message, tamperedSig, publicKey)
		if err == nil {
			t.Error("Expected error for tampered signature")
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		wrongMessage := []byte("wrong message")
		err := suite.VerifySignature(wrongMessage, validSignature, publicKey)
		if err == nil {
			t.Error("Expected error for wrong message")
		}
	})
}

// TestDomainSeparation tests that hash functions use proper domain separation
func TestDomainSeparation(t *testing.T) {
	suite := New()

	input := []byte("test")

	// All domain-separated functions should produce different outputs
	h1 := suite.H1(input)
	h3 := suite.H3(input)
	h4 := suite.H4(input)
	h5 := suite.H5(input)

	// H1 vs H3 (both hash-to-scalar with different domains)
	if h1.Equal(h3) {
		t.Error("H1 and H3 should produce different outputs (different domain separation)")
	}

	// H4 vs H5 (both hash-to-bytes with different domains)
	if bytes.Equal(h4, h5) {
		t.Error("H4 and H5 should produce different outputs (different domain separation)")
	}
}

// BenchmarkH1 benchmarks the H1 hash function
func BenchmarkH1(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H1(input)
	}
}

// BenchmarkH2 benchmarks the H2 hash function
func BenchmarkH2(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H2(input)
	}
}

// BenchmarkH3 benchmarks the H3 hash function
func BenchmarkH3(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H3(input)
	}
}

// BenchmarkH4 benchmarks the H4 hash function
func BenchmarkH4(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H4(input)
	}
}

// BenchmarkH5 benchmarks the H5 hash function
func BenchmarkH5(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H5(input)
	}
}

// BenchmarkHashToCurve benchmarks the hash-to-curve function
func BenchmarkHashToCurve(b *testing.B) {
	suite := New()
	input := []byte("benchmark input")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = suite.HashToCurve(input)
	}
}

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	suite := New()
	group := suite.Group()

	secretKey, _ := group.RandomScalar()
	publicKey := group.ScalarBaseMult(secretKey)
	message := []byte("benchmark message")

	nonce, _ := group.RandomScalar()
	R := group.ScalarBaseMult(nonce)
	rBytes, _ := group.SerializeElement(R)

	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(rBytes)
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)

	c := suite.H2(challengeInput.Bytes())
	z := nonce.Add(c.Mul(secretKey))
	zBytes := group.SerializeScalar(z)
	signature := append(rBytes, zBytes...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.VerifySignature(message, signature, publicKey)
	}
}
