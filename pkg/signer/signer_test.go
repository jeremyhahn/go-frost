package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

func TestNewEd25519Signer(t *testing.T) {
	// Generate a valid key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test valid private key
	signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil")
	}

	// Test invalid private key size
	_, err = NewEd25519Signer([]byte("too short"))
	if err == nil {
		t.Error("expected error for invalid private key size")
	}
}

func TestGenerateEd25519Signer(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil")
	}

	// Verify public key is valid
	pubKey := signer.PublicKeyBytes()
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
}

func TestEd25519Signer_Public(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() should not return nil")
	}

	pubKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public() should return ed25519.PublicKey")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
}

func TestEd25519Signer_Sign(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}

	message := []byte("test message")
	sig, err := signer.(*Ed25519Signer).Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify signature
	pub := signer.PublicKeyBytes()
	if !ed25519.Verify(pub, message, sig) {
		t.Error("signature verification failed")
	}
}

func TestEd25519Signer_SignBytes(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}

	message := []byte("test message")
	sig, err := signer.SignBytes(message)
	if err != nil {
		t.Fatalf("SignBytes failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify signature
	pub := signer.PublicKeyBytes()
	if !ed25519.Verify(pub, message, sig) {
		t.Error("signature verification failed")
	}
}

func TestEd25519Signer_PrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer failed: %v", err)
	}

	ed25519Signer := signer.(*Ed25519Signer)
	retrievedPriv := ed25519Signer.PrivateKey()
	if len(retrievedPriv) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(retrievedPriv))
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("test message")
	sig := ed25519.Sign(priv, message)

	// Test valid signature
	if !VerifySignature(pub, message, sig) {
		t.Error("valid signature should verify")
	}

	// Test invalid signature
	invalidSig := make([]byte, ed25519.SignatureSize)
	if VerifySignature(pub, message, invalidSig) {
		t.Error("invalid signature should not verify")
	}

	// Test wrong message
	if VerifySignature(pub, []byte("wrong message"), sig) {
		t.Error("signature should not verify for wrong message")
	}
}

func TestFromCryptoSigner_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ed25519Signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer failed: %v", err)
	}

	// Test wrapping an already wrapped Signer
	wrapped, err := FromCryptoSigner(ed25519Signer)
	if err != nil {
		t.Fatalf("FromCryptoSigner failed: %v", err)
	}
	if wrapped != ed25519Signer {
		t.Error("wrapping a Signer should return the same instance")
	}
}

// mockCryptoSigner is a mock crypto.Signer for testing
type mockCryptoSigner struct {
	pub ed25519.PublicKey
}

func (m *mockCryptoSigner) Public() crypto.PublicKey {
	return m.pub
}

func (m *mockCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestFromCryptoSigner_Adapter(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mockSigner := &mockCryptoSigner{pub: pub}
	wrapped, err := FromCryptoSigner(mockSigner)
	if err != nil {
		t.Fatalf("FromCryptoSigner failed: %v", err)
	}

	// Test Public()
	wrappedPub := wrapped.Public().(ed25519.PublicKey)
	mockPub := mockSigner.Public().(ed25519.PublicKey)
	if !wrappedPub.Equal(mockPub) {
		t.Error("Public() should delegate to wrapped signer")
	}

	// Test PublicKeyBytes()
	pubBytes := wrapped.PublicKeyBytes()
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pubBytes))
	}

	// Test Sign()
	sig, err := wrapped.SignBytes([]byte("test"))
	if err != nil {
		t.Fatalf("SignBytes failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}
}

// mockNonEd25519Signer is a mock crypto.Signer with a non-Ed25519 key
type mockNonEd25519Signer struct{}

func (m *mockNonEd25519Signer) Public() crypto.PublicKey {
	return "not a real public key"
}

func (m *mockNonEd25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("signature"), nil
}

func TestFromCryptoSigner_NonEd25519(t *testing.T) {
	mockSigner := &mockNonEd25519Signer{}
	wrapped, err := FromCryptoSigner(mockSigner)
	if err != nil {
		t.Fatalf("FromCryptoSigner failed: %v", err)
	}

	// Test PublicKeyBytes() returns nil for non-Ed25519
	pubBytes := wrapped.PublicKeyBytes()
	if pubBytes != nil {
		t.Error("PublicKeyBytes() should return nil for non-Ed25519 keys")
	}

	// Test SignBytes() still works
	sig, err := wrapped.SignBytes([]byte("test"))
	if err != nil {
		t.Fatalf("SignBytes failed: %v", err)
	}
	if sig == nil {
		t.Error("SignBytes should return signature")
	}
}

func TestMultiSigner(t *testing.T) {
	ms := NewMultiSigner()
	if ms == nil {
		t.Fatal("NewMultiSigner should not return nil")
	}

	// Generate signers
	signer1, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}
	signer2, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer failed: %v", err)
	}

	// Test AddSigner and HasSigner
	ms.AddSigner(1, signer1)
	ms.AddSigner(2, signer2)

	if !ms.HasSigner(1) {
		t.Error("HasSigner(1) should return true")
	}
	if !ms.HasSigner(2) {
		t.Error("HasSigner(2) should return true")
	}
	if ms.HasSigner(3) {
		t.Error("HasSigner(3) should return false")
	}

	// Test GetSigner
	if ms.GetSigner(1) != signer1 {
		t.Error("GetSigner(1) should return signer1")
	}
	if ms.GetSigner(2) != signer2 {
		t.Error("GetSigner(2) should return signer2")
	}
	if ms.GetSigner(3) != nil {
		t.Error("GetSigner(3) should return nil")
	}

	// Test PublicKeys
	keys := ms.PublicKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if keys[1] == nil {
		t.Error("keys[1] should not be nil")
	}
	if keys[2] == nil {
		t.Error("keys[2] should not be nil")
	}

	// Test Ed25519PublicKeys
	ed25519Keys := ms.Ed25519PublicKeys()
	if len(ed25519Keys) != 2 {
		t.Errorf("expected 2 Ed25519 keys, got %d", len(ed25519Keys))
	}

	// Test RemoveSigner
	ms.RemoveSigner(1)
	if ms.HasSigner(1) {
		t.Error("HasSigner(1) should return false after removal")
	}
	if !ms.HasSigner(2) {
		t.Error("HasSigner(2) should still return true")
	}
}

func TestMultiSigner_Ed25519PublicKeys_WithNilBytes(t *testing.T) {
	ms := NewMultiSigner()

	// Add a signer with nil public key bytes
	mockSigner := &mockNonEd25519Signer{}
	wrapped, _ := FromCryptoSigner(mockSigner)
	ms.AddSigner(1, wrapped)

	// Ed25519PublicKeys should skip signers with nil public key bytes
	keys := ms.Ed25519PublicKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys (nil filtered out), got %d", len(keys))
	}
}

// TestCryptoSignerAdapter_Sign directly tests the Sign method on the adapter
func TestCryptoSignerAdapter_Sign(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mockSigner := &mockCryptoSigner{pub: pub}
	wrapped, err := FromCryptoSigner(mockSigner)
	if err != nil {
		t.Fatalf("FromCryptoSigner failed: %v", err)
	}

	// Get the adapter and call Sign directly
	adapter, ok := wrapped.(*cryptoSignerAdapter)
	if !ok {
		t.Fatal("wrapped should be *cryptoSignerAdapter")
	}

	// Test the Sign method directly
	message := []byte("test message")
	sig, err := adapter.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}
}

// TestCryptoSignerAdapter_Sign_WithOpts tests Sign with various SignerOpts
func TestCryptoSignerAdapter_Sign_WithOpts(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mockSigner := &mockCryptoSigner{pub: pub}
	wrapped, err := FromCryptoSigner(mockSigner)
	if err != nil {
		t.Fatalf("FromCryptoSigner failed: %v", err)
	}

	adapter := wrapped.(*cryptoSignerAdapter)

	// Test with nil opts
	sig, err := adapter.Sign(rand.Reader, []byte("test"), nil)
	if err != nil {
		t.Fatalf("Sign with nil opts failed: %v", err)
	}
	if sig == nil {
		t.Error("signature should not be nil")
	}

	// Test with SHA256 opts
	sig, err = adapter.Sign(rand.Reader, []byte("test"), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign with SHA256 opts failed: %v", err)
	}
	if sig == nil {
		t.Error("signature should not be nil")
	}
}
