// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package signer provides cryptographic signer abstractions compatible with
// crypto.Signer for use with HSM, TPM, and other hardware-backed keys.
//
// This package allows go-frost to work with keys stored in:
//   - Software (standard crypto/ed25519)
//   - Hardware Security Modules (HSM)
//   - Trusted Platform Modules (TPM)
//   - Cloud Key Management Systems (KMS)
//   - go-keychain backed signers
//
// All signer implementations are compatible with Go's crypto.Signer interface.
package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// Signer defines the interface for cryptographic signing operations.
//
// This interface extends crypto.Signer with additional methods specific
// to FROST authentication needs.
//
// Compatible implementations:
//   - Ed25519 software keys (crypto/ed25519)
//   - HSM-backed signers
//   - TPM-backed signers
//   - Cloud KMS signers (AWS KMS, Google Cloud KMS, Azure Key Vault)
//   - go-keychain signers
type Signer interface {
	crypto.Signer

	// PublicKeyBytes returns the public key as raw bytes.
	// For Ed25519, this returns the 32-byte public key.
	PublicKeyBytes() []byte

	// SignBytes signs the given message and returns the signature.
	// This is a convenience method that wraps crypto.Signer.Sign.
	//
	// Parameters:
	//   - message: The message to sign
	//
	// Returns:
	//   - signature: The signature bytes
	//   - error: Any error that occurred during signing
	SignBytes(message []byte) ([]byte, error)
}

// Ed25519Signer implements Signer for Ed25519 software keys.
//
// This signer uses crypto/ed25519 for signing operations and is suitable
// for development, testing, and production use where hardware backing is
// not required.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewEd25519Signer creates a new Ed25519 signer from a private key.
//
// Parameters:
//   - privateKey: Ed25519 private key (64 bytes)
//
// Returns:
//   - Signer: Ed25519 signer implementation
//   - error: Any error that occurred during initialization
//
// Example:
//
//	pub, priv, err := ed25519.GenerateKey(rand.Reader)
//	if err != nil {
//	    return err
//	}
//
//	signer, err := signer.NewEd25519Signer(priv)
//	if err != nil {
//	    return err
//	}
//
//	signature, err := signer.SignBytes(message)
func NewEd25519Signer(privateKey ed25519.PrivateKey) (Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(privateKey))
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// GenerateEd25519Signer generates a new Ed25519 key pair and returns a signer.
//
// Returns:
//   - Signer: Ed25519 signer implementation
//   - error: Any error that occurred during key generation
//
// Example:
//
//	signer, err := signer.GenerateEd25519Signer()
//	if err != nil {
//	    return err
//	}
func GenerateEd25519Signer() (Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	return &Ed25519Signer{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// Public implements crypto.Signer.Public.
func (s *Ed25519Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer.Sign.
//
// For Ed25519, the opts parameter is ignored and can be nil.
// The rand parameter is also ignored as Ed25519 signing is deterministic.
func (s *Ed25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Ed25519 signing is deterministic and doesn't use the rand parameter
	return ed25519.Sign(s.privateKey, digest), nil
}

// PublicKeyBytes implements Signer.PublicKeyBytes.
func (s *Ed25519Signer) PublicKeyBytes() []byte {
	return s.publicKey
}

// SignBytes implements Signer.SignBytes.
func (s *Ed25519Signer) SignBytes(message []byte) ([]byte, error) {
	return s.Sign(nil, message, crypto.Hash(0))
}

// PrivateKey returns the underlying Ed25519 private key.
//
// WARNING: This exposes the raw private key material. Use with caution.
// This method is provided for compatibility with existing code that requires
// direct access to the private key.
func (s *Ed25519Signer) PrivateKey() ed25519.PrivateKey {
	return s.privateKey
}

// VerifySignature verifies an Ed25519 signature.
//
// This is a utility function for verifying signatures without needing
// to create a Signer instance.
//
// Parameters:
//   - publicKey: Ed25519 public key (32 bytes)
//   - message: The message that was signed
//   - signature: The signature to verify
//
// Returns:
//   - bool: true if the signature is valid, false otherwise
func VerifySignature(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// FromCryptoSigner wraps a crypto.Signer to implement the Signer interface.
//
// This adapter allows any crypto.Signer (including HSM/TPM backed signers)
// to be used with go-frost.
//
// Parameters:
//   - cryptoSigner: A crypto.Signer implementation
//
// Returns:
//   - Signer: Wrapped signer
//   - error: Any error that occurred (e.g., unsupported key type)
//
// Example using an HSM-backed signer:
//
//	// Assuming you have an HSM-backed crypto.Signer
//	hsmSigner := getHSMSigner()
//
//	// Wrap it for use with go-frost
//	signer, err := signer.FromCryptoSigner(hsmSigner)
//	if err != nil {
//	    return err
//	}
//
//	// Use with FROST authentication
//	signature, err := signer.SignBytes(message)
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

// MultiSigner manages multiple signers for different participants.
//
// This is useful for coordinator implementations that need to manage
// authentication keys for multiple participants.
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

// Ed25519PublicKeys returns all Ed25519 public keys as a map.
//
// This is a convenience method for use with Ed25519Authenticator.
// Returns nil for non-Ed25519 signers.
func (m *MultiSigner) Ed25519PublicKeys() map[uint32]ed25519.PublicKey {
	keys := make(map[uint32]ed25519.PublicKey)
	for id, signer := range m.signers {
		if pub := signer.PublicKeyBytes(); pub != nil {
			keys[id] = ed25519.PublicKey(pub)
		}
	}
	return keys
}
