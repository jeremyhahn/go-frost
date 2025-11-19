// Package helpers provides helper functions for FROST protocol operations.
// These include nonce generation, polynomial operations, binding factors,
// group commitments, and signature challenges.
package helpers

import (
	cryptorand "crypto/rand"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// NonceGenerator provides functionality for generating signing nonces.
type NonceGenerator interface {
	// Generate creates a new random nonce using the participant's secret key
	// and fresh randomness. This hedges against bad RNGs by combining both.
	//
	// Inputs:
	// - secret: The participant's secret key share
	//
	// Outputs:
	// - nonce: A random scalar to be used as a nonce
	//
	// The function samples 32 bytes of fresh randomness to ensure nonce reuse
	// probability is at most 2^-128 for up to 2^64 signatures per participant.
	Generate(secret group.Scalar) (group.Scalar, error)
}

// NewNonceGenerator creates a new nonce generator for the given ciphersuite.
func NewNonceGenerator(suite ciphersuite.Ciphersuite) NonceGenerator {
	return &nonceGenerator{suite: suite}
}

type nonceGenerator struct {
	suite ciphersuite.Ciphersuite
}

// Generate implements NonceGenerator.Generate
//
// Generates a random nonce using the participant's secret key and fresh randomness.
// This hedges against bad RNGs by combining both sources.
//
// Algorithm (from RFC 9591 Section 4.1):
// 1. Sample 32 bytes of randomness using crypto/rand
// 2. Serialize the secret scalar
// 3. Compute H3(random_bytes || secret_enc)
// 4. Return the resulting scalar
//
// The function samples 32 bytes of fresh randomness to ensure nonce reuse
// probability is at most 2^-128 for up to 2^64 signatures per participant.
func (n *nonceGenerator) Generate(secret group.Scalar) (group.Scalar, error) {
	if secret == nil {
		return nil, frost.NewParameterError("secret", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Step 1: Sample 32 random bytes using crypto/rand
	randomBytes := make([]byte, 32)
	if _, err := cryptorand.Read(randomBytes); err != nil {
		return nil, frost.NewParameterError("randomness", "failed to generate random bytes", err)
	}

	// Step 2: Serialize the secret scalar
	secretBytes := secret.Bytes()

	// Step 3: Concatenate random_bytes || secret_enc
	input := append(randomBytes, secretBytes...)

	// Step 4: Compute H3(random_bytes || secret_enc) and return
	nonce := n.suite.H3(input)

	// Verify the nonce is not zero (should never happen with proper hash function)
	if nonce.IsZero() {
		return nil, frost.NewParameterError("nonce", "generated zero nonce", frost.ErrInvalidNonce)
	}

	return nonce, nil
}
