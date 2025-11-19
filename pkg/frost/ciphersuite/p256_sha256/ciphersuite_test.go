package p256_sha256

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
)

// TestCiphersuiteInterface verifies that P256SHA256 implements the Ciphersuite interface.
func TestCiphersuiteInterface(t *testing.T) {
	var _ ciphersuite.Ciphersuite = (*P256SHA256)(nil)
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

	if id != "FROST-P256-SHA256-v1" {
		t.Errorf("ID = %q, want %q", id, "FROST-P256-SHA256-v1")
	}
}

// TestName tests the Name method.
func TestName(t *testing.T) {
	cs := New()
	name := cs.Name()

	expected := "FROST(P-256, SHA-256)"
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

	if g.Name() != "p256" {
		t.Errorf("Group name = %q, want %q", g.Name(), "p256")
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

	// Verify domain separation from H3
	scalar4 := cs.H3(input)
	if scalar.Equal(scalar4) {
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
}

// TestH4 tests the H4 hash function.
func TestH4(t *testing.T) {
	cs := New()

	msg := []byte("message test")
	hash := cs.H4(msg)

	if len(hash) != 32 {
		t.Errorf("H4 hash length = %d, want 32", len(hash))
	}

	// Verify deterministic
	hash2 := cs.H4(msg)
	if !bytes.Equal(hash, hash2) {
		t.Error("H4 should be deterministic")
	}

	// Verify different inputs produce different hashes
	msg2 := []byte("different message test")
	hash3 := cs.H4(msg2)
	if bytes.Equal(hash, hash3) {
		t.Error("H4 with different inputs should produce different hashes")
	}

	// Verify domain separation from H5
	hash4 := cs.H5(msg)
	if bytes.Equal(hash, hash4) {
		t.Error("H4 and H5 should be domain separated")
	}

	// Verify domain separation from raw Hash
	rawHash := cs.Hash(msg)
	if bytes.Equal(hash, rawHash) {
		t.Error("H4 should be domain separated from raw Hash")
	}
}

// TestH5 tests the H5 hash function.
func TestH5(t *testing.T) {
	cs := New()

	data := []byte("commitment list test")
	hash := cs.H5(data)

	if len(hash) != 32 {
		t.Errorf("H5 hash length = %d, want 32", len(hash))
	}

	// Verify deterministic
	hash2 := cs.H5(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("H5 should be deterministic")
	}

	// Verify different inputs produce different hashes
	data2 := []byte("different commitment list test")
	hash3 := cs.H5(data2)
	if bytes.Equal(hash, hash3) {
		t.Error("H5 with different inputs should produce different hashes")
	}

	// Verify domain separation from H4
	hash4 := cs.H4(data)
	if bytes.Equal(hash, hash4) {
		t.Error("H5 and H4 should be domain separated")
	}
}

// TestHashToCurve tests the HashToCurve function.
func TestHashToCurve(t *testing.T) {
	cs := New()

	data := []byte("hash to curve test")
	elem, err := cs.HashToCurve(data)
	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}

	if elem == nil {
		t.Fatal("HashToCurve returned nil element")
	}

	if elem.IsIdentity() {
		t.Error("HashToCurve should not return identity element")
	}

	// Verify deterministic
	elem2, err := cs.HashToCurve(data)
	if err != nil {
		t.Fatalf("HashToCurve failed on second call: %v", err)
	}

	if !elem.Equal(elem2) {
		t.Error("HashToCurve should be deterministic")
	}

	// Verify different inputs produce different elements
	data2 := []byte("different hash to curve test")
	elem3, err := cs.HashToCurve(data2)
	if err != nil {
		t.Fatalf("HashToCurve with different input failed: %v", err)
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

	if elem.IsIdentity() {
		t.Error("HashToCurve should not return identity element")
	}
}

// TestVerifySignature tests signature verification.
func TestVerifySignature(t *testing.T) {
	cs := New()
	g := cs.Group()

	// Generate a key pair
	secretKey, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	publicKey := g.ScalarBaseMult(secretKey)

	// Create a test message
	message := []byte("test message for signature")

	// Generate a valid signature (simplified Schnorr signature)
	// In practice, this would be done by the FROST signing protocol
	k, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	R := g.ScalarBaseMult(k)

	// Compute challenge
	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)
	c := cs.H2(challengeInput.Bytes())

	// Compute response: z = k + c * secretKey
	cSecret := c.Mul(secretKey)
	z := k.Add(cSecret)

	// Serialize signature
	RBytes, err := g.SerializeElement(R)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}
	zBytes := g.SerializeScalar(z)
	signature := append(RBytes, zBytes...)

	// Verify signature
	err = cs.VerifySignature(message, signature, publicKey)
	if err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

// TestVerifySignatureInvalidLength tests signature verification with invalid length.
func TestVerifySignatureInvalidLength(t *testing.T) {
	cs := New()
	g := cs.Group()

	publicKey := g.Generator()
	message := []byte("test message")
	invalidSignature := []byte{0x00, 0x01, 0x02}

	err := cs.VerifySignature(message, invalidSignature, publicKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid length")
	}
}

// TestVerifySignatureNilPublicKey tests signature verification with nil public key.
func TestVerifySignatureNilPublicKey(t *testing.T) {
	cs := New()

	message := []byte("test message")
	signature := make([]byte, 65)

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
	signature := make([]byte, 65)
	identity := g.Identity()

	err := cs.VerifySignature(message, signature, identity)
	if err == nil {
		t.Error("VerifySignature should fail with identity public key")
	}
}

// TestVerifySignatureInvalidR tests signature verification with invalid R.
func TestVerifySignatureInvalidR(t *testing.T) {
	cs := New()
	g := cs.Group()

	publicKey := g.Generator()
	message := []byte("test message")

	// Create signature with invalid R
	invalidR := make([]byte, 33)
	validZ := g.SerializeScalar(g.NewScalar())
	signature := append(invalidR, validZ...)

	err := cs.VerifySignature(message, signature, publicKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid R")
	}
}

// TestVerifySignatureInvalidZ tests signature verification with invalid z.
func TestVerifySignatureInvalidZ(t *testing.T) {
	cs := New()
	g := cs.Group()

	publicKey := g.Generator()
	message := []byte("test message")

	// Create signature with valid R but invalid z
	R := g.Generator()
	RBytes, _ := g.SerializeElement(R)
	invalidZ := make([]byte, 32)
	for i := range invalidZ {
		invalidZ[i] = 0xFF
	}
	signature := append(RBytes, invalidZ...)

	err := cs.VerifySignature(message, signature, publicKey)
	if err == nil {
		t.Error("VerifySignature should fail with invalid z")
	}
}

// TestVerifySignatureWrongSignature tests signature verification with wrong signature.
func TestVerifySignatureWrongSignature(t *testing.T) {
	cs := New()
	g := cs.Group()

	// Generate a key pair
	secretKey, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	publicKey := g.ScalarBaseMult(secretKey)
	message := []byte("test message")

	// Generate a random (invalid) signature
	R := g.Generator()
	RBytes, _ := g.SerializeElement(R)
	z, _ := g.RandomScalar()
	zBytes := g.SerializeScalar(z)
	signature := append(RBytes, zBytes...)

	// Verification should fail
	err = cs.VerifySignature(message, signature, publicKey)
	if err == nil {
		t.Error("VerifySignature should fail with wrong signature")
	}
}

// TestDomainSeparation tests that all hash functions are properly domain separated.
func TestDomainSeparation(t *testing.T) {
	cs := New()

	input := []byte("domain separation test")

	// Test H1, H2, H3 are different
	h1 := cs.H1(input)
	h2 := cs.H2(input)
	h3 := cs.H3(input)

	if h1.Equal(h2) {
		t.Error("H1 and H2 should be domain separated")
	}

	if h1.Equal(h3) {
		t.Error("H1 and H3 should be domain separated")
	}

	if h2.Equal(h3) {
		t.Error("H2 and H3 should be domain separated")
	}

	// Test H4, H5 are different
	h4 := cs.H4(input)
	h5 := cs.H5(input)

	if bytes.Equal(h4, h5) {
		t.Error("H4 and H5 should be domain separated")
	}

	// Test hash functions are different from raw Hash
	rawHash := cs.Hash(input)
	if bytes.Equal(h4, rawHash) {
		t.Error("H4 should be domain separated from raw Hash")
	}

	if bytes.Equal(h5, rawHash) {
		t.Error("H5 should be domain separated from raw Hash")
	}
}

// TestScalarFieldSize tests that scalars are in the correct field.
func TestScalarFieldSize(t *testing.T) {
	cs := New()

	// Generate random scalar
	scalar, err := cs.Group().RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}

	// Serialize and check size
	bytes := cs.Group().SerializeScalar(scalar)
	if len(bytes) != 32 {
		t.Errorf("scalar size = %d, want 32", len(bytes))
	}
}

// TestElementFieldSize tests that elements have the correct size.
func TestElementFieldSize(t *testing.T) {
	cs := New()

	// Get generator
	gen := cs.Group().Generator()

	// Serialize and check size
	bytes, err := cs.Group().SerializeElement(gen)
	if err != nil {
		t.Fatalf("SerializeElement failed: %v", err)
	}

	if len(bytes) != 33 {
		t.Errorf("element size = %d, want 33", len(bytes))
	}
}

// BenchmarkHash benchmarks the Hash function.
func BenchmarkHash(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for hashing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.Hash(data)
	}
}

// BenchmarkH1 benchmarks the H1 hash-to-scalar function.
func BenchmarkH1(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for H1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H1(data)
	}
}

// BenchmarkH2 benchmarks the H2 hash-to-scalar function.
func BenchmarkH2(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for H2")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H2(data)
	}
}

// BenchmarkH3 benchmarks the H3 hash-to-scalar function.
func BenchmarkH3(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for H3")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H3(data)
	}
}

// BenchmarkH4 benchmarks the H4 hash function.
func BenchmarkH4(b *testing.B) {
	cs := New()
	msg := []byte("benchmark message for H4")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H4(msg)
	}
}

// BenchmarkH5 benchmarks the H5 hash function.
func BenchmarkH5(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for H5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.H5(data)
	}
}

// BenchmarkHashToCurve benchmarks the HashToCurve function.
func BenchmarkHashToCurve(b *testing.B) {
	cs := New()
	data := []byte("benchmark data for hash to curve")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cs.HashToCurve(data)
	}
}

// BenchmarkVerifySignature benchmarks signature verification.
func BenchmarkVerifySignature(b *testing.B) {
	cs := New()
	g := cs.Group()

	// Setup
	secretKey, _ := g.RandomScalar()
	publicKey := g.ScalarBaseMult(secretKey)
	message := []byte("benchmark message")

	k, _ := g.RandomScalar()
	R := g.ScalarBaseMult(k)

	challengeInput := bytes.NewBuffer(nil)
	challengeInput.Write(R.Bytes())
	challengeInput.Write(publicKey.Bytes())
	challengeInput.Write(message)
	c := cs.H2(challengeInput.Bytes())

	cSecret := c.Mul(secretKey)
	z := k.Add(cSecret)

	RBytes, _ := g.SerializeElement(R)
	zBytes := g.SerializeScalar(z)
	signature := append(RBytes, zBytes...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.VerifySignature(message, signature, publicKey)
	}
}
