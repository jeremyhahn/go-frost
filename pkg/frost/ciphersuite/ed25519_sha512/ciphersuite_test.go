package ed25519_sha512

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
)

// TestCiphersuiteInterface verifies that Ed25519SHA512 implements the Ciphersuite interface
func TestCiphersuiteInterface(t *testing.T) {
	suite := New()
	var _ ciphersuite.Ciphersuite = suite
}

// TestCiphersuiteID tests the ciphersuite ID
func TestCiphersuiteID(t *testing.T) {
	suite := New()

	expected := "FROST-ED25519-SHA512-v1"
	if suite.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, suite.ID())
	}
}

// TestCiphersuiteName tests the ciphersuite name
func TestCiphersuiteName(t *testing.T) {
	suite := New()

	expected := "FROST(Ed25519, SHA-512)"
	if suite.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, suite.Name())
	}
}

// TestContextString tests the context string
func TestContextString(t *testing.T) {
	suite := New()

	expected := "FROST-ED25519-SHA512-v1"
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
	if group.Name() != "ed25519" {
		t.Errorf("Expected group name 'ed25519', got %s", group.Name())
	}

	// Element length should be 32 bytes for Ed25519
	if group.ElementLength() != 32 {
		t.Errorf("Expected element length 32, got %d", group.ElementLength())
	}

	// Scalar length should be 32 bytes for Ed25519
	if group.ScalarLength() != 32 {
		t.Errorf("Expected scalar length 32, got %d", group.ScalarLength())
	}
}

// TestHash tests the underlying SHA-512 hash function
func TestHash(t *testing.T) {
	suite := New()

	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:     "simple message",
			input:    []byte("test"),
			expected: "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := suite.Hash(tc.input)

			// SHA-512 produces 64 bytes
			if len(result) != 64 {
				t.Errorf("Expected hash length 64, got %d", len(result))
			}

			// Verify hash output
			resultHex := hex.EncodeToString(result)
			if resultHex != tc.expected {
				t.Errorf("Expected hash %s, got %s", tc.expected, resultHex)
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

	// CRITICAL: H2 for Ed25519 does NOT use contextString prefix
	// This is for Ed25519 signature compatibility
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

	if result == nil {
		t.Fatal("H4 returned nil")
	}

	// SHA-512 produces 64 bytes
	if len(result) != 64 {
		t.Errorf("Expected H4 output length 64, got %d", len(result))
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

	if result == nil {
		t.Fatal("H5 returned nil")
	}

	// SHA-512 produces 64 bytes
	if len(result) != 64 {
		t.Errorf("Expected H5 output length 64, got %d", len(result))
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

// TestHashFunctionDomainSeparation tests that hash functions are properly domain-separated
func TestHashFunctionDomainSeparation(t *testing.T) {
	suite := New()

	input := []byte("test")

	h1 := suite.H1(input)
	h2 := suite.H2(input)
	h3 := suite.H3(input)

	// All hash functions should produce different outputs for same input
	// (except H2 which doesn't use context string)
	if h1.Equal(h3) {
		t.Error("H1 and H3 should produce different outputs (domain separation)")
	}

	// H2 should be different from H1 and H3
	if h2.Equal(h1) {
		t.Error("H2 and H1 should produce different outputs")
	}
	if h2.Equal(h3) {
		t.Error("H2 and H3 should produce different outputs")
	}

	// H4 and H5 return bytes, not scalars
	h4 := suite.H4(input)
	h5 := suite.H5(input)

	if bytes.Equal(h4, h5) {
		t.Error("H4 and H5 should produce different outputs (domain separation)")
	}
}

// TestHashToCurve tests the hash-to-curve function
func TestHashToCurve(t *testing.T) {
	suite := New()

	input := []byte("test input for hash to curve")
	result, err := suite.HashToCurve(input)

	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}

	if result == nil {
		t.Fatal("HashToCurve returned nil element")
	}

	// Result should not be the identity element
	if result.IsIdentity() {
		t.Error("HashToCurve should not produce identity element")
	}

	// Same input should produce same output (deterministic)
	result2, err := suite.HashToCurve(input)
	if err != nil {
		t.Fatalf("HashToCurve failed on second call: %v", err)
	}

	if !result.Equal(result2) {
		t.Error("HashToCurve should be deterministic")
	}

	// Different input should produce different output
	result3, err := suite.HashToCurve([]byte("different input"))
	if err != nil {
		t.Fatalf("HashToCurve failed on third call: %v", err)
	}

	if result.Equal(result3) {
		t.Error("HashToCurve should produce different outputs for different inputs")
	}
}

// TestVerifySignature tests signature verification
func TestVerifySignature(t *testing.T) {
	suite := New()
	group := suite.Group()

	// Create a test key pair
	secretKey, err := group.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	publicKey := group.ScalarBaseMult(secretKey)

	// Create a test message
	message := []byte("test message for signing")

	// Create a test signature using Schnorr signature scheme
	// 1. Generate random nonce
	nonce, err := group.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// 2. Compute R = nonce * G
	R := group.ScalarBaseMult(nonce)

	// 3. Compute challenge c = H2(R || PK || msg)
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)
	c := suite.H2(challengeInput.Bytes())

	// 4. Compute response z = nonce + c * secretKey
	z := nonce.Add(c.Mul(secretKey))

	// 5. Signature is (R, z)
	signature := append(R.Bytes(), z.Bytes()...)

	// Verify the signature
	err = suite.VerifySignature(message, signature, publicKey)
	if err != nil {
		t.Errorf("Valid signature failed verification: %v", err)
	}

	// Test with wrong message
	wrongMessage := []byte("wrong message")
	err = suite.VerifySignature(wrongMessage, signature, publicKey)
	if err == nil {
		t.Error("Signature should not verify with wrong message")
	}

	// Test with wrong public key
	wrongSecretKey, _ := group.RandomScalar()
	wrongPublicKey := group.ScalarBaseMult(wrongSecretKey)
	err = suite.VerifySignature(message, signature, wrongPublicKey)
	if err == nil {
		t.Error("Signature should not verify with wrong public key")
	}
}

// TestVerifySignatureInvalidInputs tests signature verification with invalid inputs
func TestVerifySignatureInvalidInputs(t *testing.T) {
	suite := New()
	group := suite.Group()

	message := []byte("test message")
	secretKey, _ := group.RandomScalar()
	publicKey := group.ScalarBaseMult(secretKey)

	// Test with nil public key
	err := suite.VerifySignature(message, make([]byte, 64), nil)
	if err == nil {
		t.Error("Should return error for nil public key")
	}

	// Test with identity public key
	identity := group.Identity()
	err = suite.VerifySignature(message, make([]byte, 64), identity)
	if err == nil {
		t.Error("Should return error for identity public key")
	}

	// Test with invalid signature length
	err = suite.VerifySignature(message, make([]byte, 32), publicKey)
	if err == nil {
		t.Error("Should return error for invalid signature length")
	}

	// Test with invalid R in signature
	invalidSig := make([]byte, 64)
	for i := 0; i < 32; i++ {
		invalidSig[i] = 0xFF // Invalid point encoding
	}
	err = suite.VerifySignature(message, invalidSig, publicKey)
	if err == nil {
		t.Error("Should return error for invalid R encoding")
	}

	// Test with invalid z in signature (valid R, invalid z)
	validR := group.Generator()
	validRBytes, _ := group.SerializeElement(validR)
	invalidZ := make([]byte, 32)
	for i := 0; i < 32; i++ {
		invalidZ[i] = 0xFF // Invalid scalar encoding
	}
	invalidSig2 := append(validRBytes, invalidZ...)
	err = suite.VerifySignature(message, invalidSig2, publicKey)
	if err == nil {
		t.Error("Should return error for invalid z encoding")
	}
}

// TestDomainSeparationConsistency tests that domain separation is consistent
func TestDomainSeparationConsistency(t *testing.T) {
	suite := New()

	// Create two instances and verify they produce same results
	suite2 := New()

	input := []byte("test consistency")

	// Test H1
	h1a := suite.H1(input)
	h1b := suite2.H1(input)
	if !h1a.Equal(h1b) {
		t.Error("H1 should be consistent across instances")
	}

	// Test H2
	h2a := suite.H2(input)
	h2b := suite2.H2(input)
	if !h2a.Equal(h2b) {
		t.Error("H2 should be consistent across instances")
	}

	// Test H3
	h3a := suite.H3(input)
	h3b := suite2.H3(input)
	if !h3a.Equal(h3b) {
		t.Error("H3 should be consistent across instances")
	}

	// Test H4
	h4a := suite.H4(input)
	h4b := suite2.H4(input)
	if !bytes.Equal(h4a, h4b) {
		t.Error("H4 should be consistent across instances")
	}

	// Test H5
	h5a := suite.H5(input)
	h5b := suite2.H5(input)
	if !bytes.Equal(h5a, h5b) {
		t.Error("H5 should be consistent across instances")
	}
}

// TestEmptyInputs tests hash functions with empty inputs
func TestEmptyInputs(t *testing.T) {
	suite := New()

	emptyInput := []byte{}

	// All hash functions should handle empty input
	h1 := suite.H1(emptyInput)
	if h1 == nil {
		t.Error("H1 should handle empty input")
	}

	h2 := suite.H2(emptyInput)
	if h2 == nil {
		t.Error("H2 should handle empty input")
	}

	h3 := suite.H3(emptyInput)
	if h3 == nil {
		t.Error("H3 should handle empty input")
	}

	h4 := suite.H4(emptyInput)
	if h4 == nil {
		t.Error("H4 should handle empty input")
	}

	h5 := suite.H5(emptyInput)
	if h5 == nil {
		t.Error("H5 should handle empty input")
	}

	_, err := suite.HashToCurve(emptyInput)
	if err != nil {
		t.Errorf("HashToCurve should handle empty input: %v", err)
	}
}

// BenchmarkH1 benchmarks the H1 hash function
func BenchmarkH1(b *testing.B) {
	suite := New()
	input := []byte("benchmark input data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H1(input)
	}
}

// TestHDKG tests the HDKG hash function for DKG operations
func TestHDKG(t *testing.T) {
	suite := New()

	input := []byte("test DKG context")
	result := suite.HDKG(input)

	if result == nil {
		t.Fatal("HDKG returned nil")
	}

	// Result should not be zero
	if result.IsZero() {
		t.Error("HDKG result should not be zero for non-empty input")
	}

	// Same input should produce same output (deterministic)
	result2 := suite.HDKG(input)
	if !result.Equal(result2) {
		t.Error("HDKG should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.HDKG([]byte("different context"))
	if result.Equal(result3) {
		t.Error("HDKG should produce different outputs for different inputs")
	}
}

// TestHID tests the HID hash function for identifier derivation
func TestHID(t *testing.T) {
	suite := New()

	input := []byte("test identifier data")
	result := suite.HID(input)

	if result == nil {
		t.Fatal("HID returned nil")
	}

	// Result should not be zero
	if result.IsZero() {
		t.Error("HID result should not be zero for non-empty input")
	}

	// Same input should produce same output (deterministic)
	result2 := suite.HID(input)
	if !result.Equal(result2) {
		t.Error("HID should be deterministic")
	}

	// Different input should produce different output
	result3 := suite.HID([]byte("different data"))
	if result.Equal(result3) {
		t.Error("HID should produce different outputs for different inputs")
	}
}

// BenchmarkH2 benchmarks the H2 hash function
func BenchmarkH2(b *testing.B) {
	suite := New()
	input := []byte("benchmark input data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H2(input)
	}
}

// BenchmarkH3 benchmarks the H3 hash function
func BenchmarkH3(b *testing.B) {
	suite := New()
	input := []byte("benchmark input data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H3(input)
	}
}

// BenchmarkHashToCurve benchmarks the HashToCurve function
func BenchmarkHashToCurve(b *testing.B) {
	suite := New()
	input := []byte("benchmark input data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = suite.HashToCurve(input)
	}
}

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	suite := New()
	group := suite.Group()

	// Setup
	secretKey, _ := group.RandomScalar()
	publicKey := group.ScalarBaseMult(secretKey)
	message := []byte("benchmark message")

	// Create signature
	nonce, _ := group.RandomScalar()
	R := group.ScalarBaseMult(nonce)
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)
	c := suite.H2(challengeInput.Bytes())
	z := nonce.Add(c.Mul(secretKey))
	signature := append(R.Bytes(), z.Bytes()...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.VerifySignature(message, signature, publicKey)
	}
}
