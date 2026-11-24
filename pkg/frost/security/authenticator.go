// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

// ParticipantAuthenticator authenticates FROST commitments and signature shares (RFC 9591 Section 7.2).
type ParticipantAuthenticator interface {
	// AuthenticateCommitment verifies that participantID produced the commitment, using proof.
	AuthenticateCommitment(participantID frost.Identifier, commitment frost.SigningCommitments, proof []byte) error

	// AuthenticateSignatureShare verifies that participantID produced the share, using proof.
	AuthenticateSignatureShare(participantID frost.Identifier, share frost.SignatureShare, proof []byte) error
}

// NoOpAuthenticator performs no verification; only for tests or when another layer authenticates.
type NoOpAuthenticator struct{}

// NewNoOpAuthenticator creates a new no-op authenticator.
func NewNoOpAuthenticator() *NoOpAuthenticator {
	return &NoOpAuthenticator{}
}

// AuthenticateCommitment implements ParticipantAuthenticator.AuthenticateCommitment.
// Always returns nil (no authentication performed).
func (a *NoOpAuthenticator) AuthenticateCommitment(_ frost.Identifier, _ frost.SigningCommitments, _ []byte) error {
	return nil
}

// AuthenticateSignatureShare implements ParticipantAuthenticator.AuthenticateSignatureShare.
// Always returns nil (no authentication performed).
func (a *NoOpAuthenticator) AuthenticateSignatureShare(_ frost.Identifier, _ frost.SignatureShare, _ []byte) error {
	return nil
}

// Ed25519Authenticator verifies participants' Ed25519 signatures on their messages.
type Ed25519Authenticator struct {
	// publicKeys maps participant identifiers to their Ed25519 public keys
	publicKeys map[frost.Identifier]ed25519.PublicKey
}

// NewEd25519Authenticator returns an authenticator for the given, already verified, participant public keys.
func NewEd25519Authenticator(publicKeys map[frost.Identifier]ed25519.PublicKey) *Ed25519Authenticator {
	return &Ed25519Authenticator{
		publicKeys: publicKeys,
	}
}

// AuthenticateCommitment verifies an Ed25519 signature over participantID || hiding_commitment || binding_commitment.
func (a *Ed25519Authenticator) AuthenticateCommitment(participantID frost.Identifier, commitment frost.SigningCommitments, proof []byte) error {
	// Get participant's public key
	publicKey, exists := a.publicKeys[participantID]
	if !exists {
		return frost.NewParticipantError(participantID, "public key not found", ErrAuthenticationFailed)
	}

	// Construct message to verify
	message := a.serializeCommitment(participantID, commitment)

	// Verify signature
	if !ed25519.Verify(publicKey, message, proof) {
		return frost.NewParticipantError(participantID, "commitment signature verification failed", ErrAuthenticationFailed)
	}

	return nil
}

// AuthenticateSignatureShare verifies an Ed25519 signature over participantID || signature_share_bytes.
func (a *Ed25519Authenticator) AuthenticateSignatureShare(participantID frost.Identifier, share frost.SignatureShare, proof []byte) error {
	// Get participant's public key
	publicKey, exists := a.publicKeys[participantID]
	if !exists {
		return frost.NewParticipantError(participantID, "public key not found", ErrAuthenticationFailed)
	}

	// Construct message to verify
	message := a.serializeSignatureShare(participantID, share)

	// Verify signature
	if !ed25519.Verify(publicKey, message, proof) {
		return frost.NewParticipantError(participantID, "signature share signature verification failed", ErrAuthenticationFailed)
	}

	return nil
}

// serializeCommitment creates a canonical serialization of a commitment for signing.
func (a *Ed25519Authenticator) serializeCommitment(participantID frost.Identifier, commitment frost.SigningCommitments) []byte {
	// Format: participantID (4 bytes) || hiding_commitment || binding_commitment
	idBytes := make([]byte, 4)
	idBytes[0] = byte(participantID)
	idBytes[1] = byte(participantID >> 8)
	idBytes[2] = byte(participantID >> 16)
	idBytes[3] = byte(participantID >> 24)

	hidingBytes := commitment.HidingNonceCommitment.Bytes()
	bindingBytes := commitment.BindingNonceCommitment.Bytes()

	message := make([]byte, 0, 4+len(hidingBytes)+len(bindingBytes))
	message = append(message, idBytes...)
	message = append(message, hidingBytes...)
	message = append(message, bindingBytes...)

	return message
}

// serializeSignatureShare creates a canonical serialization of a signature share for signing.
func (a *Ed25519Authenticator) serializeSignatureShare(participantID frost.Identifier, share frost.SignatureShare) []byte {
	// Format: participantID (4 bytes) || signature_share_bytes
	idBytes := make([]byte, 4)
	idBytes[0] = byte(participantID)
	idBytes[1] = byte(participantID >> 8)
	idBytes[2] = byte(participantID >> 16)
	idBytes[3] = byte(participantID >> 24)

	shareBytes := share.SignatureShare.Bytes()

	message := make([]byte, 0, 4+len(shareBytes))
	message = append(message, idBytes...)
	message = append(message, shareBytes...)

	return message
}

// AddPublicKey adds or replaces a participant's public key, verified out of band.
func (a *Ed25519Authenticator) AddPublicKey(participantID frost.Identifier, publicKey ed25519.PublicKey) {
	a.publicKeys[participantID] = publicKey
}

// RemovePublicKey removes a participant's public key.
//
// This should be called when a participant leaves the protocol.
func (a *Ed25519Authenticator) RemovePublicKey(participantID frost.Identifier) {
	delete(a.publicKeys, participantID)
}

// GetPublicKey retrieves a participant's public key.
//
// Returns nil if the participant is not registered.
func (a *Ed25519Authenticator) GetPublicKey(participantID frost.Identifier) ed25519.PublicKey {
	return a.publicKeys[participantID]
}

// ParticipantCount returns the number of registered participants.
func (a *Ed25519Authenticator) ParticipantCount() int {
	return len(a.publicKeys)
}

// AuthenticationProof represents a proof of authenticity for a FROST message.
type AuthenticationProof struct {
	// ParticipantID is the claimed sender of the message
	ParticipantID frost.Identifier

	// Signature is the Ed25519 signature over the message
	Signature []byte

	// Timestamp is the Unix timestamp when the proof was created (optional)
	Timestamp int64
}

// SignCommitment creates an authentication proof for a commitment.
//
// This is a helper function for participants to sign their commitments.
func SignCommitment(participantID frost.Identifier, commitment frost.SigningCommitments, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	auth := &Ed25519Authenticator{}
	message := auth.serializeCommitment(participantID, commitment)
	signature := ed25519.Sign(privateKey, message)

	return signature, nil
}

// SignSignatureShare creates an authentication proof for a signature share.
//
// This is a helper function for participants to sign their signature shares.
func SignSignatureShare(participantID frost.Identifier, share frost.SignatureShare, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	auth := &Ed25519Authenticator{}
	message := auth.serializeSignatureShare(participantID, share)
	signature := ed25519.Sign(privateKey, message)

	return signature, nil
}

// SerializeCommitment creates a canonical serialization of a commitment for testing.
//
// This is a helper function for tests to create consistent serializations.
func SerializeCommitment(commitment frost.SigningCommitments) ([]byte, error) {
	hidingBytes := commitment.HidingNonceCommitment.Bytes()
	bindingBytes := commitment.BindingNonceCommitment.Bytes()

	message := make([]byte, 0, len(hidingBytes)+len(bindingBytes))
	message = append(message, hidingBytes...)
	message = append(message, bindingBytes...)

	return message, nil
}

// SerializeSignatureShare creates a canonical serialization of a signature share for testing.
//
// This is a helper function for tests to create consistent serializations.
func SerializeSignatureShare(share frost.SignatureShare) ([]byte, error) {
	shareBytes := share.SignatureShare.Bytes()
	return shareBytes, nil
}

// SignCommitmentWithSigner returns an authentication proof for a commitment signed with any crypto.Signer (software, HSM, TPM, KMS).
func SignCommitmentWithSigner(participantID frost.Identifier, commitment frost.SigningCommitments, signer crypto.Signer) ([]byte, error) {
	auth := &Ed25519Authenticator{}
	message := auth.serializeCommitment(participantID, commitment)

	// Sign using crypto.Signer interface
	// For Ed25519, opts can be nil or crypto.Hash(0)
	signature, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign commitment: %w", err)
	}

	return signature, nil
}

// SignSignatureShareWithSigner returns an authentication proof for a signature share signed with any crypto.Signer (software, HSM, TPM, KMS).
func SignSignatureShareWithSigner(participantID frost.Identifier, share frost.SignatureShare, signer crypto.Signer) ([]byte, error) {
	auth := &Ed25519Authenticator{}
	message := auth.serializeSignatureShare(participantID, share)

	// Sign using crypto.Signer interface
	// For Ed25519, opts can be nil or crypto.Hash(0)
	signature, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign signature share: %w", err)
	}

	return signature, nil
}
