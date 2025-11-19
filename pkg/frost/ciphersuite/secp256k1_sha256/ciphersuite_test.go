package secp256k1_sha256

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
)

// TestCiphersuiteInterface verifies that Secp256k1SHA256 implements the Ciphersuite interface.
func TestCiphersuiteInterface(t *testing.T) {
	var _ ciphersuite.Ciphersuite = (*Secp256k1SHA256)(nil)
}

// TestNew tests ciphersuite initialization.
func TestNew(t *testing.T) {
	cs := New()
	if cs == nil {
		t.Fatal("New returned nil")
	}

	if cs.group == nil {
		t.Fatal("group is nil")
	}
}

// TestID tests the ID method.
func TestID(t *testing.T) {
	cs := New()
	id := cs.ID()

	if id != contextString {
		t.Errorf("ID = %q, want %q", id, contextString)
	}

	if id != "FROST-secp256k1-SHA256-v1" {
		t.Errorf("ID = %q, want %q", id, "FROST-secp256k1-SHA256-v1")
	}
}

// TestName tests the Name method.
func TestName(t *testing.T) {
	cs := New()
	name := cs.Name()

	expected := "FROST(secp256k1, SHA-256)"
	if name != expected {
		t.Errorf("Name = %q, want %q", name, expected)
	}
}

// TestContextString tests the ContextString method.
func TestContextString(t *testing.T) {
	cs := New()
	ctx := cs.ContextString()

	if ctx != contextString {
		t.Errorf("ContextString = %q, want %q", ctx, contextString)
	}
}

// TestGroup tests the Group method.
func TestGroup(t *testing.T) {
	cs := New()
	g := cs.Group()

	if g == nil {
		t.Fatal("Group returned nil")
	}

	if g.Name() != "secp256k1" {
		t.Errorf("Group name = %q, want %q", g.Name(), "secp256k1")
	}
}

// TestHash tests the Hash method.
func TestHash(t *testing.T) {
	cs := New()

	input := []byte("test data")
	hash := cs.Hash(input)

	// Verify hash length
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}

	// Verify it matches SHA-256
	expected := sha256.Sum256(input)
	if !bytes.Equal(hash, expected[:]) {
		t.Error("hash does not match SHA-256 output")
	}

	// Verify deterministic
	hash2 := cs.Hash(input)
	if !bytes.Equal(hash, hash2) {
		t.Error("hash should be deterministic")
	}

	// Verify different inputs produce different hashes
	input2 := []byte("different data")
	hash3 := cs.Hash(input2)
	if bytes.Equal(hash, hash3) {
		t.Error("different inputs should produce different hashes")
	}
}

// TestH1 tests the H1 hash-to-scalar function.
func TestH1(t *testing.T) {
	cs := New()

	input := []byte("binding factor test")
	scalar := cs.H1(input)

	if scalar == nil {
		t.Fatal("H1 returned nil")
	}

	if scalar.IsZero() {
		t.Error("H1 should not return zero (statistically unlikely)")
	}

	// Verify deterministic
	scalar2 := cs.H1(input)
	if !scalar.Equal(scalar2) {
		t.Error("H1 should be deterministic")
	}

	// Verify different inputs produce different scalars
	input2 := []byte("different binding factor test")
	scalar3 := cs.H1(input2)
	if scalar.Equal(scalar3) {
		t.Error("H1 with different inputs should produce different scalars")
	}

	// Verify domain separation from H2
	scalar4 := cs.H2(input)
	if scalar.Equal(scalar4) {
		t.Error("H1 and H2 should be domain separated")
	}
}

// TestH2 tests the H2 hash-to-scalar function.
func TestH2(t *testing.T) {
	cs := New()

	input := []byte("challenge test")
	scalar := cs.H2(input)

	if scalar == nil {
		t.Fatal("H2 returned nil")
	}

	if scalar.IsZero() {
		t.Error("H2 should not return zero (statistically unlikely)")
	}

	// Verify deterministic
	scalar2 := cs.H2(input)
	if !scalar.Equal(scalar2) {
		t.Error("H2 should be deterministic")
	}

	// Verify different inputs produce different scalars
	input2 := []byte("different challenge test")
	scalar3 := cs.H2(input2)
	if scalar.Equal(scalar3) {
		t.Error("H2 with different inputs should produce different scalars")
	}

	// Verify domain separation from H1
	scalar4 := cs.H1(input)
	if scalar.Equal(scalar4) {
		t.Error("H2 and H1 should be domain separated")
	}

	// Verify domain separation from H3
	scalar5 := cs.H3(input)
	if scalar.Equal(scalar5) {
		t.Error("H2 and H3 should be domain separated")
	}
}

// TestH3 tests the H3 hash-to-scalar function.
func TestH3(t *testing.T) {
	cs := New()

	input := []byte("nonce test")
	scalar := cs.H3(input)

	if scalar == nil {
		t.Fatal("H3 returned nil")
	}

	if scalar.IsZero() {
		t.Error("H3 should not return zero (statistically unlikely)")
	}

	// Verify deterministic
	scalar2 := cs.H3(input)
	if !scalar.Equal(scalar2) {
		t.Error("H3 should be deterministic")
	}

	// Verify different inputs produce different scalars
	input2 := []byte("different nonce test")
	scalar3 := cs.H3(input2)
	if scalar.Equal(scalar3) {
		t.Error("H3 with different inputs should produce different scalars")
	}

	// Verify domain separation from H1
	scalar4 := cs.H1(input)
	if scalar.Equal(scalar4) {
		t.Error("H3 and H1 should be domain separated")
	}

	// Verify domain separation from H2
	scalar5 := cs.H2(input)
	if scalar.Equal(scalar5) {
		t.Error("H3 and H2 should be domain separated")
	}
}

// TestH4 tests the H4 hash function.
func TestH4(t *testing.T) {
	cs := New()

	input := []byte("message test")
	hash := cs.H4(input)

	if len(hash) != 32 {
		t.Errorf("H4 hash length = %d, want 32", len(hash))
	}

	// Verify deterministic
	hash2 := cs.H4(input)
	if !bytes.Equal(hash, hash2) {
		t.Error("H4 should be deterministic")
	}

	// Verify different inputs produce different hashes
	input2 := []byte("different message test")
	hash3 := cs.H4(input2)
	if bytes.Equal(hash, hash3) {
		t.Error("H4 with different inputs should produce different hashes")
	}

	// Verify domain separation from H5
	hash4 := cs.H5(input)
	if bytes.Equal(hash, hash4) {
		t.Error("H4 and H5 should be domain separated")
	}

	// Verify domain separation from raw Hash
	hash5 := cs.Hash(input)
	if bytes.Equal(hash, hash5) {
		t.Error("H4 and Hash should be domain separated")
	}
}

// TestH5 tests the H5 hash function.
func TestH5(t *testing.T) {
	cs := New()

	input := []byte("commitment list test")
	hash := cs.H5(input)

	if len(hash) != 32 {
		t.Errorf("H5 hash length = %d, want 32", len(hash))
	}

	// Verify deterministic
	hash2 := cs.H5(input)
	if !bytes.Equal(hash, hash2) {
		t.Error("H5 should be deterministic")
	}

	// Verify different inputs produce different hashes
	input2 := []byte("different commitment list test")
	hash3 := cs.H5(input2)
	if bytes.Equal(hash, hash3) {
		t.Error("H5 with different inputs should produce different hashes")
	}

	// Verify domain separation from H4
	hash4 := cs.H4(input)
	if bytes.Equal(hash, hash4) {
		t.Error("H5 and H4 should be domain separated")
	}

	// Verify domain separation from raw Hash
	hash5 := cs.Hash(input)
	if bytes.Equal(hash, hash5) {
		t.Error("H5 and Hash should be domain separated")
	}
}

// TestHashToCurve tests the HashToCurve function.
func TestHashToCurve(t *testing.T) {
	cs := New()

	input := []byte("hash to curve test")
	elem, err := cs.HashToCurve(input)

	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}

	if elem == nil {
		t.Fatal("HashToCurve returned nil element")
	}

	if elem.IsIdentity() {
		t.Error("HashToCurve should not return identity (statistically unlikely)")
	}

	// Verify deterministic
	elem2, err := cs.HashToCurve(input)
	if err != nil {
		t.Fatalf("HashToCurve failed on second call: %v", err)
	}

	if !elem.Equal(elem2) {
		t.Error("HashToCurve should be deterministic")
	}

	// Verify different inputs produce different elements
	input2 := []byte("different hash to curve test")
	elem3, err := cs.HashToCurve(input2)
	if err != nil {
		t.Fatalf("HashToCurve failed with different input: %v", err)
	}

	if elem.Equal(elem3) {
		t.Error("HashToCurve with different inputs should produce different elements")
	}
}

// TestHashToCurveEmpty tests HashToCurve with empty input.
func TestHashToCurveEmpty(t *testing.T) {
	cs := New()

	elem, err := cs.HashToCurve([]byte{})
	if err != nil {
		t.Fatalf("HashToCurve with empty input failed: %v", err)
	}

	if elem == nil {
		t.Fatal("HashToCurve returned nil element")
	}
}

// TestVerifySignature tests signature verification.
func TestVerifySignature(t *testing.T) {
	cs := New()
	g := cs.Group()

	// Generate a random private key
	privKey, _ := g.RandomScalar()

	// Compute public key
	pubKey := g.ScalarBaseMult(privKey)

	// Message to sign
	message := []byte("test message")

	// Generate a random nonce
	nonce, _ := g.RandomScalar()

	// Compute commitment R = nonce * G
	R := g.ScalarBaseMult(nonce)

	// Compute challenge c = H2(R || PK || msg)
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(pubKey.Bytes())
	challengeInput.Write(message)
	c := cs.H2(challengeInput.Bytes())

	// Compute response z = nonce + c * privKey
	cPrivKey := c.Mul(privKey)
	z := nonce.Add(cPrivKey)

	// Create signature
	rBytes, _ := g.SerializeElement(R)
	zBytes := g.SerializeScalar(z)
	signature := append(rBytes, zBytes...)

	// Verify signature
	err := cs.VerifySignature(message, signature, pubKey)
	if err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

// TestVerifySignatureInvalid tests signature verification with invalid signature.
func TestVerifySignatureInvalid(t *testing.T) {
	cs := New()
	g := cs.Group()

	// Generate a random public key
	privKey, _ := g.RandomScalar()
	pubKey := g.ScalarBaseMult(privKey)

	// Message
	message := []byte("test message")

	// Create an invalid signature (wrong z value)
	nonce, _ := g.RandomScalar()
	R := g.ScalarBaseMult(nonce)
	wrongZ, _ := g.RandomScalar() // Wrong z value

	rBytes, _ := g.SerializeElement(R)
	zBytes := g.SerializeScalar(wrongZ)
	signature := append(rBytes, zBytes...)

	// Verify signature should fail
	err := cs.VerifySignature(message, signature, pubKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid signature")
	}
}

// TestVerifySignatureNilPublicKey tests signature verification with nil public key.
func TestVerifySignatureNilPublicKey(t *testing.T) {
	cs := New()

	message := []byte("test message")
	signature := make([]byte, 65) // 33 + 32

	err := cs.VerifySignature(message, signature, nil)
	if err == nil {
		t.Error("VerifySignature should fail with nil public key")
	}
}

// TestVerifySignatureIdentityPublicKey tests signature verification with identity public key.
func TestVerifySignatureIdentityPublicKey(t *testing.T) {
	cs := New()
	g := cs.Group()

	message := []byte("test message")
	signature := make([]byte, 65) // 33 + 32
	identity := g.Identity()

	err := cs.VerifySignature(message, signature, identity)
	if err == nil {
		t.Error("VerifySignature should fail with identity public key")
	}

	if err != nil && err.Error() == "" {
		t.Error("Error should have a message")
	}
}

// TestVerifySignatureInvalidLength tests signature verification with invalid length.
func TestVerifySignatureInvalidLength(t *testing.T) {
	cs := New()
	g := cs.Group()

	privKey, _ := g.RandomScalar()
	pubKey := g.ScalarBaseMult(privKey)
	message := []byte("test message")

	// Too short
	err := cs.VerifySignature(message, []byte{0x01, 0x02, 0x03}, pubKey)
	if err == nil {
		t.Error("VerifySignature should fail with too short signature")
	}

	// Too long
	longSig := make([]byte, 100)
	err = cs.VerifySignature(message, longSig, pubKey)
	if err == nil {
		t.Error("VerifySignature should fail with too long signature")
	}
}

// TestVerifySignatureInvalidR tests signature verification with invalid R.
func TestVerifySignatureInvalidR(t *testing.T) {
	cs := New()
	g := cs.Group()

	privKey, _ := g.RandomScalar()
	pubKey := g.ScalarBaseMult(privKey)
	message := []byte("test message")

	// Create signature with invalid R
	invalidR := make([]byte, 33)
	invalidR[0] = 0x01 // Invalid prefix
	z, _ := g.RandomScalar()
	zBytes := g.SerializeScalar(z)
	signature := append(invalidR, zBytes...)

	err := cs.VerifySignature(message, signature, pubKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid R")
	}
}

// TestVerifySignatureInvalidZ tests signature verification with invalid z.
func TestVerifySignatureInvalidZ(t *testing.T) {
	cs := New()
	g := cs.Group()

	privKey, _ := g.RandomScalar()
	pubKey := g.ScalarBaseMult(privKey)
	message := []byte("test message")

	// Create signature with valid R but invalid z
	nonce, _ := g.RandomScalar()
	R := g.ScalarBaseMult(nonce)
	rBytes, _ := g.SerializeElement(R)

	// Invalid z (all 0xFF bytes - exceeds order)
	invalidZ := make([]byte, 32)
	for i := range invalidZ {
		invalidZ[i] = 0xFF
	}
	signature := append(rBytes, invalidZ...)

	err := cs.VerifySignature(message, signature, pubKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid z")
	}
}

// TestDomainSeparation tests that all hash functions are properly domain separated.
func TestDomainSeparation(t *testing.T) {
	cs := New()

	input := []byte("test data")

	// Test that H1, H2, H3 produce different outputs
	s1 := cs.H1(input)
	s2 := cs.H2(input)
	s3 := cs.H3(input)

	if s1.Equal(s2) {
		t.Error("H1 and H2 should produce different outputs (domain separation)")
	}

	if s1.Equal(s3) {
		t.Error("H1 and H3 should produce different outputs (domain separation)")
	}

	if s2.Equal(s3) {
		t.Error("H2 and H3 should produce different outputs (domain separation)")
	}

	// Test that H4 and H5 produce different outputs
	h4 := cs.H4(input)
	h5 := cs.H5(input)

	if bytes.Equal(h4, h5) {
		t.Error("H4 and H5 should produce different outputs (domain separation)")
	}

	// Test that hash functions include context string
	rawHash := cs.Hash(input)

	if bytes.Equal(h4, rawHash) {
		t.Error("H4 should be different from raw hash (context string)")
	}

	if bytes.Equal(h5, rawHash) {
		t.Error("H5 should be different from raw hash (context string)")
	}
}

// TestHashToScalarDistribution tests that hash-to-scalar produces valid scalars.
func TestHashToScalarDistribution(t *testing.T) {
	cs := New()
	g := cs.Group()

	// Generate several scalars and verify they're all valid
	for i := 0; i < 100; i++ {
		input := []byte{byte(i)}
		scalar := cs.H1(input)

		// Verify scalar is valid (can be serialized and deserialized)
		bytes := g.SerializeScalar(scalar)
		scalar2, err := g.DeserializeScalar(bytes)
		if err != nil {
			t.Errorf("Hash-to-scalar produced invalid scalar at iteration %d: %v", i, err)
		}

		if !scalar.Equal(scalar2) {
			t.Errorf("Scalar serialization/deserialization mismatch at iteration %d", i)
		}
	}
}

// BenchmarkH1 benchmarks the H1 hash-to-scalar function.
func BenchmarkH1(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H1(input)
	}
}

// BenchmarkH2 benchmarks the H2 hash-to-scalar function.
func BenchmarkH2(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H2(input)
	}
}

// BenchmarkH3 benchmarks the H3 hash-to-scalar function.
func BenchmarkH3(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H3(input)
	}
}

// BenchmarkH4 benchmarks the H4 hash function.
func BenchmarkH4(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H4(input)
	}
}

// BenchmarkH5 benchmarks the H5 hash function.
func BenchmarkH5(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H5(input)
	}
}

// BenchmarkHashToCurve benchmarks the HashToCurve function.
func BenchmarkHashToCurve(b *testing.B) {
	cs := New()
	input := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cs.HashToCurve(input)
	}
}

// BenchmarkVerifySignature benchmarks signature verification.
func BenchmarkVerifySignature(b *testing.B) {
	cs := New()
	g := cs.Group()

	// Setup
	privKey, _ := g.RandomScalar()
	pubKey := g.ScalarBaseMult(privKey)
	message := []byte("benchmark message")
	nonce, _ := g.RandomScalar()
	R := g.ScalarBaseMult(nonce)

	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(pubKey.Bytes())
	challengeInput.Write(message)
	c := cs.H2(challengeInput.Bytes())

	z := nonce.Add(c.Mul(privKey))
	rBytes, _ := g.SerializeElement(R)
	zBytes := g.SerializeScalar(z)
	signature := append(rBytes, zBytes...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.VerifySignature(message, signature, pubKey)
	}
}
