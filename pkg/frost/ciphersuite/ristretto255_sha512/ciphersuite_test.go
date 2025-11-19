package ristretto255_sha512

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
)

// TestCiphersuiteInterface verifies that Ristretto255SHA512 implements the Ciphersuite interface
func TestCiphersuiteInterface(t *testing.T) {
	suite := New()
	var _ ciphersuite.Ciphersuite = suite
}

// TestCiphersuiteID tests the ciphersuite ID
func TestCiphersuiteID(t *testing.T) {
	suite := New()

	expected := "FROST-RISTRETTO255-SHA512-v1"
	if suite.ID() != expected {
		t.Errorf("Expected ID %s, got %s", expected, suite.ID())
	}
}

// TestCiphersuiteName tests the ciphersuite name
func TestCiphersuiteName(t *testing.T) {
	suite := New()

	expected := "FROST(ristretto255, SHA-512)"
	if suite.Name() != expected {
		t.Errorf("Expected name %s, got %s", expected, suite.Name())
	}
}

// TestContextString tests the context string
func TestContextString(t *testing.T) {
	suite := New()

	expected := "FROST-RISTRETTO255-SHA512-v1"
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
	if group.Name() != "ristretto255" {
		t.Errorf("Expected group name 'ristretto255', got %s", group.Name())
	}

	// Element length should be 32 bytes for ristretto255
	if group.ElementLength() != 32 {
		t.Errorf("Expected element length 32, got %d", group.ElementLength())
	}

	// Scalar length should be 32 bytes for ristretto255
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

			// Verify against known SHA-512 output
			expected, _ := hex.DecodeString(tc.expected)
			if !bytes.Equal(result, expected) {
				t.Errorf("Hash mismatch\nExpected: %x\nGot:      %x", expected, result)
			}
		})
	}
}

// TestH1 tests the H1 hash function (binding factor)
func TestH1(t *testing.T) {
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
			input: []byte("test message"),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scalar := suite.H1(tc.input)

			if scalar == nil {
				t.Fatal("H1 returned nil scalar")
			}

			// Verify it's a valid scalar (32 bytes)
			scalarBytes := scalar.Bytes()
			if len(scalarBytes) != 32 {
				t.Errorf("Expected scalar length 32, got %d", len(scalarBytes))
			}

			// Verify domain separation - H1 should prepend "FROST-RISTRETTO255-SHA512-v1" || "rho"
			// We can verify the scalar is non-zero for non-trivial inputs
			if len(tc.input) > 0 && scalar.IsZero() {
				t.Error("H1 produced zero scalar for non-empty input")
			}
		})
	}
}

// TestH1Deterministic tests that H1 is deterministic
func TestH1Deterministic(t *testing.T) {
	suite := New()

	input := []byte("test message")
	scalar1 := suite.H1(input)
	scalar2 := suite.H1(input)

	if !scalar1.Equal(scalar2) {
		t.Error("H1 is not deterministic - same input produced different outputs")
	}
}

// TestH2 tests the H2 hash function (challenge)
func TestH2(t *testing.T) {
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
			name:  "challenge data",
			input: []byte("challenge message"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scalar := suite.H2(tc.input)

			if scalar == nil {
				t.Fatal("H2 returned nil scalar")
			}

			// Verify it's a valid scalar (32 bytes)
			scalarBytes := scalar.Bytes()
			if len(scalarBytes) != 32 {
				t.Errorf("Expected scalar length 32, got %d", len(scalarBytes))
			}

			// Verify non-zero for non-trivial inputs
			if len(tc.input) > 0 && scalar.IsZero() {
				t.Error("H2 produced zero scalar for non-empty input")
			}
		})
	}
}

// TestH2Deterministic tests that H2 is deterministic
func TestH2Deterministic(t *testing.T) {
	suite := New()

	input := []byte("challenge message")
	scalar1 := suite.H2(input)
	scalar2 := suite.H2(input)

	if !scalar1.Equal(scalar2) {
		t.Error("H2 is not deterministic - same input produced different outputs")
	}
}

// TestH3 tests the H3 hash function (nonce generation)
func TestH3(t *testing.T) {
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
			name:  "nonce data",
			input: []byte("nonce message"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scalar := suite.H3(tc.input)

			if scalar == nil {
				t.Fatal("H3 returned nil scalar")
			}

			// Verify it's a valid scalar (32 bytes)
			scalarBytes := scalar.Bytes()
			if len(scalarBytes) != 32 {
				t.Errorf("Expected scalar length 32, got %d", len(scalarBytes))
			}

			// Verify non-zero for non-trivial inputs
			if len(tc.input) > 0 && scalar.IsZero() {
				t.Error("H3 produced zero scalar for non-empty input")
			}
		})
	}
}

// TestH3Deterministic tests that H3 is deterministic
func TestH3Deterministic(t *testing.T) {
	suite := New()

	input := []byte("nonce message")
	scalar1 := suite.H3(input)
	scalar2 := suite.H3(input)

	if !scalar1.Equal(scalar2) {
		t.Error("H3 is not deterministic - same input produced different outputs")
	}
}

// TestH4 tests the H4 hash function (message hashing)
func TestH4(t *testing.T) {
	suite := New()

	testCases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty message",
			input: []byte{},
		},
		{
			name:  "simple message",
			input: []byte("message to hash"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := suite.H4(tc.input)

			if result == nil {
				t.Fatal("H4 returned nil")
			}

			// H4 returns raw hash output (64 bytes for SHA-512)
			if len(result) != 64 {
				t.Errorf("Expected H4 output length 64, got %d", len(result))
			}

			// Verify domain separation - H4 should prepend "FROST-RISTRETTO255-SHA512-v1" || "msg"
			expectedPrefix := append([]byte("FROST-RISTRETTO255-SHA512-v1"), []byte("msg")...)
			hashInput := append(expectedPrefix, tc.input...)
			expected := sha512.Sum512(hashInput)

			if !bytes.Equal(result, expected[:]) {
				t.Errorf("H4 output mismatch\nExpected: %x\nGot:      %x", expected, result)
			}
		})
	}
}

// TestH4Deterministic tests that H4 is deterministic
func TestH4Deterministic(t *testing.T) {
	suite := New()

	input := []byte("message to hash")
	result1 := suite.H4(input)
	result2 := suite.H4(input)

	if !bytes.Equal(result1, result2) {
		t.Error("H4 is not deterministic - same input produced different outputs")
	}
}

// TestH5 tests the H5 hash function (commitment list hashing)
func TestH5(t *testing.T) {
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
			name:  "commitment data",
			input: []byte("commitment list data"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := suite.H5(tc.input)

			if result == nil {
				t.Fatal("H5 returned nil")
			}

			// H5 returns raw hash output (64 bytes for SHA-512)
			if len(result) != 64 {
				t.Errorf("Expected H5 output length 64, got %d", len(result))
			}

			// Verify domain separation - H5 should prepend "FROST-RISTRETTO255-SHA512-v1" || "com"
			expectedPrefix := append([]byte("FROST-RISTRETTO255-SHA512-v1"), []byte("com")...)
			hashInput := append(expectedPrefix, tc.input...)
			expected := sha512.Sum512(hashInput)

			if !bytes.Equal(result, expected[:]) {
				t.Errorf("H5 output mismatch\nExpected: %x\nGot:      %x", expected, result)
			}
		})
	}
}

// TestH5Deterministic tests that H5 is deterministic
func TestH5Deterministic(t *testing.T) {
	suite := New()

	input := []byte("commitment list data")
	result1 := suite.H5(input)
	result2 := suite.H5(input)

	if !bytes.Equal(result1, result2) {
		t.Error("H5 is not deterministic - same input produced different outputs")
	}
}

// TestHashFunctionDomainSeparation tests that all hash functions are domain separated
func TestHashFunctionDomainSeparation(t *testing.T) {
	suite := New()

	input := []byte("test data")

	// Get outputs from all hash functions
	h1 := suite.H1(input)
	h2 := suite.H2(input)
	h3 := suite.H3(input)
	h4 := suite.H4(input)
	h5 := suite.H5(input)

	// H1, H2, H3 return scalars - verify they're different
	if h1.Equal(h2) {
		t.Error("H1 and H2 produced the same scalar - domain separation failed")
	}
	if h1.Equal(h3) {
		t.Error("H1 and H3 produced the same scalar - domain separation failed")
	}
	if h2.Equal(h3) {
		t.Error("H2 and H3 produced the same scalar - domain separation failed")
	}

	// H4 and H5 return byte arrays - verify they're different
	if bytes.Equal(h4, h5) {
		t.Error("H4 and H5 produced the same output - domain separation failed")
	}
}

// TestHashToCurve tests the hash-to-curve functionality
func TestHashToCurve(t *testing.T) {
	suite := New()

	testCases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "simple input",
			input: []byte("test"),
		},
		{
			name:  "empty input",
			input: []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			elem, err := suite.HashToCurve(tc.input)
			if err != nil {
				t.Fatalf("HashToCurve failed: %v", err)
			}

			if elem == nil {
				t.Fatal("HashToCurve returned nil element")
			}

			// Verify the element is not the identity
			if elem.IsIdentity() {
				t.Error("HashToCurve returned identity element")
			}

			// Verify element serialization
			elemBytes := elem.Bytes()
			if len(elemBytes) != 32 {
				t.Errorf("Expected element bytes length 32, got %d", len(elemBytes))
			}
		})
	}
}

// TestHashToCurveDeterministic tests that HashToCurve is deterministic
func TestHashToCurveDeterministic(t *testing.T) {
	suite := New()

	input := []byte("test data")
	elem1, err1 := suite.HashToCurve(input)
	elem2, err2 := suite.HashToCurve(input)

	if err1 != nil || err2 != nil {
		t.Fatalf("HashToCurve failed: %v, %v", err1, err2)
	}

	if !elem1.Equal(elem2) {
		t.Error("HashToCurve is not deterministic - same input produced different elements")
	}
}

// TestVerifySignature tests basic signature verification
func TestVerifySignature(t *testing.T) {
	suite := New()

	// This is a basic test - we'll need actual signature data for full testing
	// For now, test error cases

	t.Run("invalid signature length", func(t *testing.T) {
		message := []byte("test message")
		signature := []byte("invalid")
		publicKey := suite.Group().Generator()

		err := suite.VerifySignature(message, signature, publicKey)
		if err == nil {
			t.Error("Expected error for invalid signature length, got nil")
		}
	})

	t.Run("nil public key", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, 64) // Valid length but invalid content

		err := suite.VerifySignature(message, signature, nil)
		if err == nil {
			t.Error("Expected error for nil public key, got nil")
		}
	})

	t.Run("invalid R element", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, 64)
		// Set R to invalid bytes (all 0xff is not a valid ristretto255 point)
		for i := 0; i < 32; i++ {
			signature[i] = 0xff
		}
		publicKey := suite.Group().Generator()

		err := suite.VerifySignature(message, signature, publicKey)
		if err == nil {
			t.Error("Expected error for invalid R element, got nil")
		}
	})

	t.Run("invalid z scalar", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, 64)
		// R is valid (all zeros = identity, which will fail deserialization)
		// z is invalid (all 0xff is not a valid scalar)
		for i := 32; i < 64; i++ {
			signature[i] = 0xff
		}
		publicKey := suite.Group().Generator()

		err := suite.VerifySignature(message, signature, publicKey)
		if err == nil {
			t.Error("Expected error for invalid signature components, got nil")
		}
	})

	t.Run("valid signature structure but wrong signature", func(t *testing.T) {
		// Create a valid-looking but incorrect signature
		message := []byte("test message")
		publicKey := suite.Group().Generator()

		// Create valid R (generator point)
		R := suite.Group().Generator()
		rBytes := R.Bytes()

		// Create valid z (scalar = 1)
		z := suite.Group().NewScalar()
		one, _ := suite.Group().DeserializeScalar([]byte{
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		})
		z = one
		zBytes := z.Bytes()

		// Combine to create signature
		signature := append(rBytes, zBytes...)

		// This should fail verification because it's not a valid signature
		err := suite.VerifySignature(message, signature, publicKey)
		if err == nil {
			t.Error("Expected verification to fail for invalid signature, got nil")
		}
	})
}

// TestVerifySignatureWithIdentityKey tests that identity public key is rejected
func TestVerifySignatureWithIdentityKey(t *testing.T) {
	suite := New()

	message := []byte("test message")
	signature := make([]byte, 64)
	publicKey := suite.Group().Identity()

	err := suite.VerifySignature(message, signature, publicKey)
	if err == nil {
		t.Error("Expected error for identity public key, got nil")
	}

	// The error should be a VerificationError wrapping ErrIdentityElement
	// We can check if it contains the identity element error
	if err == nil {
		t.Error("Expected error for identity public key, got nil")
	}
}

// TestNew tests the constructor
func TestNew(t *testing.T) {
	suite := New()

	if suite == nil {
		t.Fatal("New() returned nil")
	}

	// Verify all required methods are available
	if suite.ID() == "" {
		t.Error("ID() returned empty string")
	}
	if suite.Name() == "" {
		t.Error("Name() returned empty string")
	}
	if suite.ContextString() == "" {
		t.Error("ContextString() returned empty string")
	}
	if suite.Group() == nil {
		t.Error("Group() returned nil")
	}
}

// TestInvalidInputs tests error handling for invalid inputs
func TestInvalidInputs(t *testing.T) {
	suite := New()

	t.Run("H1 with nil input", func(t *testing.T) {
		// Should not panic with nil input
		scalar := suite.H1(nil)
		if scalar == nil {
			t.Error("H1 returned nil for nil input")
		}
	})

	t.Run("H2 with nil input", func(t *testing.T) {
		scalar := suite.H2(nil)
		if scalar == nil {
			t.Error("H2 returned nil for nil input")
		}
	})

	t.Run("H3 with nil input", func(t *testing.T) {
		scalar := suite.H3(nil)
		if scalar == nil {
			t.Error("H3 returned nil for nil input")
		}
	})

	t.Run("H4 with nil input", func(t *testing.T) {
		result := suite.H4(nil)
		if result == nil {
			t.Error("H4 returned nil for nil input")
		}
	})

	t.Run("H5 with nil input", func(t *testing.T) {
		result := suite.H5(nil)
		if result == nil {
			t.Error("H5 returned nil for nil input")
		}
	})

	t.Run("HashToCurve with nil input", func(t *testing.T) {
		elem, err := suite.HashToCurve(nil)
		if err != nil {
			t.Errorf("HashToCurve failed with nil input: %v", err)
		}
		if elem == nil {
			t.Error("HashToCurve returned nil element for nil input")
		}
	})
}

// BenchmarkH1 benchmarks the H1 hash function
func BenchmarkH1(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for H1 hash function")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H1(input)
	}
}

// BenchmarkH2 benchmarks the H2 hash function
func BenchmarkH2(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for H2 hash function")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H2(input)
	}
}

// BenchmarkH3 benchmarks the H3 hash function
func BenchmarkH3(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for H3 hash function")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H3(input)
	}
}

// BenchmarkH4 benchmarks the H4 hash function
func BenchmarkH4(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for H4 hash function")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H4(input)
	}
}

// BenchmarkH5 benchmarks the H5 hash function
func BenchmarkH5(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for H5 hash function")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.H5(input)
	}
}

// BenchmarkHashToCurve benchmarks the hash-to-curve function
func BenchmarkHashToCurve(b *testing.B) {
	suite := New()
	input := []byte("benchmark data for hash-to-curve")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = suite.HashToCurve(input)
	}
}

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	suite := New()
	message := []byte("benchmark message")
	signature := make([]byte, 64)
	publicKey := suite.Group().Generator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.VerifySignature(message, signature, publicKey)
	}
}
