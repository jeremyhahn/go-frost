// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package signer provides crypto.Signer-compatible signers for software, HSM, TPM and KMS keys.
package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Signer extends crypto.Signer with PublicKeyBytes and SignBytes for FROST authentication.
type Signer interface {
	crypto.Signer

	// PublicKeyBytes returns the public key as raw bytes.
	// For Ed25519, this returns the 32-byte public key.
	PublicKeyBytes() []byte

	// SignBytes signs message through crypto.Signer.Sign.
	SignBytes(message []byte) ([]byte, error)
}

// Ed25519Signer signs with an Ed25519 key held in memguard memory; Destroy erases it.
type Ed25519Signer struct {
	secret    *secmem.SecretBytes
	publicKey ed25519.PublicKey
}

// NewEd25519Signer returns a Signer for a 64-byte Ed25519 private key.
func NewEd25519Signer(privateKey ed25519.PrivateKey) (Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(privateKey))
	}

	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(publicKey, privateKey.Public().(ed25519.PublicKey))

	// Store the private key in secure memory (mlock'd, encrypted at rest)
	secret := secmem.NewSecretBytes(privateKey)

	return &Ed25519Signer{
		secret:    secret,
		publicKey: publicKey,
	}, nil
}

// GenerateEd25519Signer returns a Signer for a new Ed25519 key pair.
func GenerateEd25519Signer() (Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// Store the private key in secure memory
	secret := secmem.NewSecretBytes(priv)

	return &Ed25519Signer{
		secret:    secret,
		publicKey: pub,
	}, nil
}

// Public implements crypto.Signer.Public.
func (s *Ed25519Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer.Sign; rand and opts are ignored, the key is decrypted only for signing.
func (s *Ed25519Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	var signature []byte
	err := secmem.WithSecret(s.secret, func(keyBytes []byte) error {
		// Copy to a Go heap-allocated slice because ed25519.Sign uses internal
		// caching (weak pointers) that requires Go-managed heap memory.
		// The memguard LockedBuffer uses mmap'd memory which is incompatible.
		key := make(ed25519.PrivateKey, len(keyBytes))
		copy(key, keyBytes)
		signature = ed25519.Sign(key, digest)
		secmem.ZeroBytes(key)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signature, nil
}

// PublicKeyBytes implements Signer.PublicKeyBytes.
func (s *Ed25519Signer) PublicKeyBytes() []byte {
	return s.publicKey
}

// SignBytes implements Signer.SignBytes.
func (s *Ed25519Signer) SignBytes(message []byte) ([]byte, error) {
	return s.Sign(nil, message, crypto.Hash(0))
}

// PrivateKey returns a copy of the Ed25519 private key; zero it with secmem.ZeroBytes.
//
// Deprecated: exposes raw key material; use Sign or SignBytes.
func (s *Ed25519Signer) PrivateKey() ed25519.PrivateKey {
	log.Println("WARNING: Ed25519Signer.PrivateKey() exposes raw key material in unprotected memory")
	var key ed25519.PrivateKey
	err := secmem.WithSecret(s.secret, func(keyBytes []byte) error {
		key = make(ed25519.PrivateKey, len(keyBytes))
		copy(key, keyBytes)
		return nil
	})
	if err != nil {
		return nil
	}
	return key
}

// Destroy permanently destroys the private key material in secure memory.
// After calling Destroy, all signing operations will fail.
func (s *Ed25519Signer) Destroy() {
	if s.secret != nil {
		s.secret.Destroy()
	}
}

// VerifySignature reports whether signature is a valid Ed25519 signature of message by publicKey.
func VerifySignature(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// FromCryptoSigner wraps any crypto.Signer, HSM or TPM backed included, as a Signer.
func FromCryptoSigner(cryptoSigner crypto.Signer) (Signer, error) {
	// Check if it's already our Signer type
	if s, ok := cryptoSigner.(Signer); ok {
		return s, nil
	}

	// Wrap the crypto.Signer
	return &cryptoSignerAdapter{
		signer: cryptoSigner,
	}, nil
}

// cryptoSignerAdapter adapts a crypto.Signer to implement Signer.
type cryptoSignerAdapter struct {
	signer crypto.Signer
}

// Public implements crypto.Signer.Public.
func (a *cryptoSignerAdapter) Public() crypto.PublicKey {
	return a.signer.Public()
}

// Sign implements crypto.Signer.Sign.
func (a *cryptoSignerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return a.signer.Sign(rand, digest, opts)
}

// PublicKeyBytes implements Signer.PublicKeyBytes.
func (a *cryptoSignerAdapter) PublicKeyBytes() []byte {
	pub := a.signer.Public()

	// Try to extract bytes based on key type
	switch key := pub.(type) {
	case ed25519.PublicKey:
		return key
	default:
		// For other key types, try to use encoding
		// This may need to be extended for specific HSM/TPM implementations
		return nil
	}
}

// SignBytes implements Signer.SignBytes.
func (a *cryptoSignerAdapter) SignBytes(message []byte) ([]byte, error) {
	// Use appropriate hash for the key type
	// For Ed25519, crypto.Hash(0) means no hashing
	var opts crypto.SignerOpts

	switch a.signer.Public().(type) {
	case ed25519.PublicKey:
		opts = crypto.Hash(0) // Ed25519 doesn't hash
	default:
		// For other algorithms, might need SHA256 or other hash
		// This can be customized based on the signer type
		opts = crypto.Hash(0)
	}

	return a.signer.Sign(rand.Reader, message, opts)
}

// MultiSigner holds the authentication signers of several participants.
type MultiSigner struct {
	signers map[uint32]Signer // Map participant ID to signer
}

// NewMultiSigner creates a new multi-signer.
func NewMultiSigner() *MultiSigner {
	return &MultiSigner{
		signers: make(map[uint32]Signer),
	}
}

// AddSigner adds a signer for a participant.
func (m *MultiSigner) AddSigner(participantID uint32, signer Signer) {
	m.signers[participantID] = signer
}

// GetSigner retrieves a signer for a participant.
//
// Returns nil if the participant doesn't have a signer registered.
func (m *MultiSigner) GetSigner(participantID uint32) Signer {
	return m.signers[participantID]
}

// RemoveSigner removes a signer for a participant.
func (m *MultiSigner) RemoveSigner(participantID uint32) {
	delete(m.signers, participantID)
}

// HasSigner returns true if a signer is registered for the participant.
func (m *MultiSigner) HasSigner(participantID uint32) bool {
	_, exists := m.signers[participantID]
	return exists
}

// PublicKeys returns all public keys as a map.
func (m *MultiSigner) PublicKeys() map[uint32][]byte {
	keys := make(map[uint32][]byte)
	for id, signer := range m.signers {
		keys[id] = signer.PublicKeyBytes()
	}
	return keys
}

// Ed25519PublicKeys returns the Ed25519 public keys by participant, or nil for non-Ed25519 signers.
func (m *MultiSigner) Ed25519PublicKeys() map[uint32]ed25519.PublicKey {
	keys := make(map[uint32]ed25519.PublicKey)
	for id, signer := range m.signers {
		if pub := signer.PublicKeyBytes(); pub != nil {
			keys[id] = ed25519.PublicKey(pub)
		}
	}
	return keys
}
