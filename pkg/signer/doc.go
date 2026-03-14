// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package signer provides cryptographic signer abstractions for use with
// Hardware Security Modules (HSM), Trusted Platform Modules (TPM), and
// other hardware-backed cryptographic devices.
//
// # Overview
//
// This package allows go-frost to work with keys stored in various backends:
//   - Software keys (crypto/ed25519)
//   - Hardware Security Modules (HSM)
//   - Trusted Platform Modules (TPM)
//   - Cloud Key Management Systems (AWS KMS, Google Cloud KMS, Azure Key Vault)
//   - go-xkms backed signers
//
// All signer implementations are compatible with Go's crypto.Signer interface,
// allowing seamless integration with existing cryptographic libraries and
// hardware devices.
//
// # Key Concepts
//
// The Signer interface extends crypto.Signer with methods specific to FROST:
//   - PublicKeyBytes(): Returns raw public key bytes for verification
//   - SignBytes(message): Convenience method for signing messages
//
// The crypto.Signer interface from Go's standard library:
//   - Public(): Returns the public key
//   - Sign(rand, digest, opts): Signs a digest with optional parameters
//
// # Provided Implementations
//
// Ed25519Signer:
//   - Software-based Ed25519 signing using crypto/ed25519
//   - Suitable for development, testing, and production
//   - Deterministic signatures (RFC 8032)
//   - No hardware requirements
//
// cryptoSignerAdapter:
//   - Wraps any crypto.Signer for use with go-frost
//   - Enables HSM, TPM, and cloud KMS integration
//   - Transparent to FROST protocols
//
// MultiSigner:
//   - Manages multiple signers for different participants
//   - Useful for coordinator implementations
//   - Thread-safe signer management
//
// # Usage Examples
//
// Using software Ed25519 keys:
//
//	import (
//	    "crypto/ed25519"
//	    "crypto/rand"
//	    "github.com/jeremyhahn/go-frost/pkg/signer"
//	)
//
//	// Generate a new key pair
//	signer, err := signer.GenerateEd25519Signer()
//	if err != nil {
//	    return err
//	}
//
//	// Sign a message
//	message := []byte("Hello, FROST!")
//	signature, err := signer.SignBytes(message)
//	if err != nil {
//	    return err
//	}
//
//	// Verify the signature
//	pubKey := signer.Public().(ed25519.PublicKey)
//	valid := signer.VerifySignature(pubKey, message, signature)
//
// Using existing Ed25519 private key:
//
//	// Load or generate private key
//	pub, priv, err := ed25519.GenerateKey(rand.Reader)
//	if err != nil {
//	    return err
//	}
//
//	// Create signer from private key
//	signer, err := signer.NewEd25519Signer(priv)
//	if err != nil {
//	    return err
//	}
//
//	signature, err := signer.SignBytes(message)
//
// Using HSM-backed keys:
//
//	// Assuming you have an HSM-backed crypto.Signer
//	// This could be from PKCS#11, AWS CloudHSM, etc.
//	hsmSigner := getHSMCryptoSigner()
//
//	// Wrap it for use with go-frost
//	signer, err := signer.FromCryptoSigner(hsmSigner)
//	if err != nil {
//	    return err
//	}
//
//	// Use normally with FROST
//	signature, err := signer.SignBytes(message)
//
// Using with FROST authentication:
//
//	import (
//	    "github.com/jeremyhahn/go-frost/pkg/frost"
//	    "github.com/jeremyhahn/go-frost/pkg/frost/security"
//	    "github.com/jeremyhahn/go-frost/pkg/signer"
//	)
//
//	// Create signers for participants
//	participantSigners := make(map[frost.Identifier]signer.Signer)
//	for i := 1; i <= numParticipants; i++ {
//	    s, err := signer.GenerateEd25519Signer()
//	    if err != nil {
//	        return err
//	    }
//	    participantSigners[frost.Identifier(i)] = s
//	}
//
//	// Create authenticator with public keys
//	publicKeys := make(map[frost.Identifier]ed25519.PublicKey)
//	for id, s := range participantSigners {
//	    publicKeys[id] = s.Public().(ed25519.PublicKey)
//	}
//	authenticator := security.NewEd25519Authenticator(publicKeys)
//
//	// Sign a commitment
//	commitment := ... // FROST signing commitment
//	participantID := frost.Identifier(1)
//	s := participantSigners[participantID]
//
//	// Use signer with security functions
//	proof, err := security.SignCommitmentWithSigner(participantID, commitment, s)
//
// Using MultiSigner for coordinator:
//
//	// Create multi-signer manager
//	multiSigner := signer.NewMultiSigner()
//
//	// Add signers for each participant
//	for i := uint32(1); i <= 5; i++ {
//	    s, err := signer.GenerateEd25519Signer()
//	    if err != nil {
//	        return err
//	    }
//	    multiSigner.AddSigner(i, s)
//	}
//
//	// Get all public keys for authenticator
//	publicKeys := multiSigner.Ed25519PublicKeys()
//
//	// Sign for a specific participant
//	participantSigner := multiSigner.GetSigner(1)
//	signature, err := participantSigner.SignBytes(message)
//
// # Integration with go-xkms
//
// If using go-xkms's crypto.Signer implementation:
//
//	import (
//	    "github.com/jeremyhahn/go-xkms/pkg/keystore"
//	    "github.com/jeremyhahn/go-frost/pkg/signer"
//	)
//
//	// Get signer from go-xkms (implements crypto.Signer)
//	keychainSigner, err := keystore.GetSigner("my-key-id")
//	if err != nil {
//	    return err
//	}
//
//	// Wrap for use with go-frost
//	frostSigner, err := signer.FromCryptoSigner(keychainSigner)
//	if err != nil {
//	    return err
//	}
//
//	// Use with FROST protocols
//	signature, err := frostSigner.SignBytes(message)
//
// # Security Considerations
//
// Software Keys (Ed25519Signer):
//   - Private keys are stored in process memory
//   - Vulnerable to memory dumps and process inspection
//   - Suitable for development and testing
//   - For production, consider hardware backing
//
// Hardware-Backed Keys (HSM/TPM):
//   - Private keys never leave the hardware device
//   - Resistant to extraction and cloning
//   - May require special permissions and setup
//   - Recommended for production use with sensitive keys
//
// Key Storage:
//   - Use go-frost's storage package for key material
//   - Consider encrypting private keys at rest
//   - Use appropriate file permissions (0600)
//   - Implement key rotation policies
//
// # Thread Safety
//
// All Signer implementations should be thread-safe. The provided
// Ed25519Signer and cryptoSignerAdapter are thread-safe.
//
// The MultiSigner is NOT thread-safe by default. Wrap calls in a mutex
// if accessing from multiple goroutines.
//
// # Compatibility
//
// This package is compatible with:
//   - crypto.Signer (Go standard library)
//   - crypto/ed25519 (Go standard library)
//   - github.com/jeremyhahn/go-xkms (if it provides crypto.Signer)
//   - PKCS#11 implementations (via crypto.Signer wrappers)
//   - Cloud KMS SDKs (via crypto.Signer wrappers)
//
// # Future Extensions
//
// Potential future additions:
//   - ECDSA signer support (P-256, secp256k1)
//   - Direct PKCS#11 integration
//   - Direct TPM integration (via go-attestation or similar)
//   - Key derivation functions (BIP32/BIP44)
//   - Threshold signing for authentication keys
package signer
