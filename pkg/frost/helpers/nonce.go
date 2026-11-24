// Package helpers provides helper functions for FROST protocol operations.
// These include nonce generation, polynomial operations, binding factors,
// group commitments, and signature challenges.
package helpers

import (
	cryptorand "crypto/rand"
	"slices"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

const (
	// RandomBytesSize is the number of random bytes used in nonce generation.
	// Per RFC 9591 Section 4.1, 32 bytes (256 bits) provides sufficient entropy
	// to ensure nonce reuse probability is at most 2^-128 for up to 2^64 signatures.
	RandomBytesSize = 32
)

// NonceGenerator provides functionality for generating signing nonces.
type NonceGenerator interface {
	// Generate returns a hedged nonce from the secret share and RandomBytesSize fresh random bytes.
	Generate(secret group.Scalar) (group.Scalar, error)
}

// NewNonceGenerator creates a new nonce generator for the given ciphersuite.
func NewNonceGenerator(suite ciphersuite.Ciphersuite) NonceGenerator {
	return &nonceGenerator{suite: suite}
}

type nonceGenerator struct {
	suite ciphersuite.Ciphersuite
}

// Generate implements NonceGenerator.Generate: H3(random_bytes || secret_enc) per RFC 9591 Section 4.1.
func (n *nonceGenerator) Generate(secret group.Scalar) (group.Scalar, error) {
	if secret == nil {
		return nil, frost.NewParameterError("secret", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Step 1: Sample random bytes using crypto/rand
	randomBytes := make([]byte, RandomBytesSize)
	if _, err := cryptorand.Read(randomBytes); err != nil {
		return nil, frost.NewParameterError("randomness", "failed to generate random bytes", err)
	}

	// Step 2: Serialize the secret scalar
	secretBytes := secret.Bytes()

	// Step 3: Concatenate random_bytes || secret_enc
	input := slices.Concat(randomBytes, secretBytes)

	// Step 4: Compute H3(random_bytes || secret_enc) and return
	nonce := n.suite.H3(input)

	// Zero ephemeral secret data to limit exposure window
	secmem.ZeroBytes(randomBytes)
	secmem.ZeroBytes(secretBytes)
	secmem.ZeroBytes(input)

	// Verify the nonce is not zero (should never happen with proper hash function)
	if nonce.IsZero() {
		return nil, frost.NewParameterError("nonce", "generated zero nonce", frost.ErrInvalidNonce)
	}

	return nonce, nil
}
