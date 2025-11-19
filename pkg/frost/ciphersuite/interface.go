// Package ciphersuite defines the ciphersuite interface for FROST.
//
// A ciphersuite specifies the prime-order group and hash function to use
// for FROST operations. RFC 9591 defines five standard ciphersuites:
// - FROST(Ed25519, SHA-512)
// - FROST(ristretto255, SHA-512)
// - FROST(Ed448, SHAKE256)
// - FROST(P-256, SHA-256)
// - FROST(secp256k1, SHA-256)
package ciphersuite

import (
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// Ciphersuite defines the cryptographic primitives for a FROST instantiation.
// Each ciphersuite specifies a prime-order group and domain-separated hash functions.
type Ciphersuite interface {
	// ID returns the unique identifier for this ciphersuite.
	ID() string

	// Group returns the prime-order group implementation.
	Group() group.Group

	// H1 is a domain-separated hash function that maps arbitrary byte strings
	// to Scalar elements. Used for binding factor computation.
	H1(data []byte) group.Scalar

	// H2 is a domain-separated hash function that maps arbitrary byte strings
	// to Scalar elements. Used for signature challenge computation.
	H2(data []byte) group.Scalar

	// H3 is a domain-separated hash function that maps arbitrary byte strings
	// to Scalar elements. Used for nonce generation.
	H3(data []byte) group.Scalar

	// H4 is a domain-separated hash function (alias for H with distinct separator).
	// Used for message hashing in binding factor computation.
	H4(msg []byte) []byte

	// H5 is a domain-separated hash function (alias for H with distinct separator).
	// Used for commitment list hashing in binding factor computation.
	H5(data []byte) []byte

	// HashToCurve maps arbitrary byte strings to group elements (H2C).
	// This is used for deriving public keys and other operations.
	// Returns an error if hashing to curve fails.
	HashToCurve(data []byte) (group.Element, error)

	// Hash is the underlying cryptographic hash function.
	// For example, SHA-512 for Ed25519 and ristretto255 ciphersuites.
	Hash(data []byte) []byte

	// VerifySignature verifies a FROST signature against a message and public key.
	// This performs the standard Schnorr signature verification for the group.
	VerifySignature(message []byte, signature []byte, publicKey group.Element) error

	// ContextString returns the domain separation context string for this ciphersuite.
	// This is prepended to all hash function inputs to provide domain separation.
	ContextString() string

	// Name returns a human-readable name for this ciphersuite.
	Name() string
}

// CiphersuiteID represents the unique identifier for a ciphersuite.
type CiphersuiteID string

const (
	// Ed25519SHA512 represents FROST(Ed25519, SHA-512)
	Ed25519SHA512 CiphersuiteID = "FROST-ED25519-SHA512-v1"

	// Ristretto255SHA512 represents FROST(ristretto255, SHA-512)
	Ristretto255SHA512 CiphersuiteID = "FROST-RISTRETTO255-SHA512-v1"

	// Ed448SHAKE256 represents FROST(Ed448, SHAKE256)
	Ed448SHAKE256 CiphersuiteID = "FROST-ED448-SHAKE256-v1"

	// P256SHA256 represents FROST(P-256, SHA-256)
	P256SHA256 CiphersuiteID = "FROST-P256-SHA256-v1"

	// Secp256k1SHA256 represents FROST(secp256k1, SHA-256)
	Secp256k1SHA256 CiphersuiteID = "FROST-SECP256K1-SHA256-v1"
)

// Registry provides access to ciphersuite implementations.
type Registry interface {
	// Get retrieves a ciphersuite by its ID.
	// Returns an error if the ciphersuite is not found.
	Get(id CiphersuiteID) (Ciphersuite, error)

	// Register registers a new ciphersuite implementation.
	// Returns an error if a ciphersuite with the same ID is already registered.
	Register(suite Ciphersuite) error

	// List returns all registered ciphersuite IDs.
	List() []CiphersuiteID
}
