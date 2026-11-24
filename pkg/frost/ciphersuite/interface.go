// Package ciphersuite defines the FROST ciphersuite interface for the five RFC 9591 suites.
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

	// HDKG computes H(contextString || "dkg" || data) for the DKG proof of knowledge.
	HDKG(data []byte) group.Scalar

	// HID is a domain-separated hash-to-scalar function for identifier derivation.
	// Used to derive participant identifiers from arbitrary byte strings.
	// Implements: H(contextString || "id" || data) -> Scalar
	HID(data []byte) group.Scalar

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
	Secp256k1SHA256 CiphersuiteID = "FROST-secp256k1-SHA256-v1"
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

// Hooks are optional points where a ciphersuite can transform messages, shares or signatures, such as Ed448 pre-hashing.
type Hooks interface {
	// PreSign may transform the message before signing; return it unchanged by default.
	PreSign(msg []byte) ([]byte, error)

	// PreAggregate may transform the message and group commitment before aggregation; return them unchanged by default.
	PreAggregate(msg []byte, groupCommitment group.Element) ([]byte, group.Element, error)

	// PreVerify may transform the message, R, z and public key before verification; return them unchanged by default.
	PreVerify(msg []byte, r group.Element, z group.Scalar, publicKey group.Element) ([]byte, group.Element, group.Scalar, group.Element, error)

	// PostDKG may validate or convert the secret share and group key after DKG; return them unchanged by default.
	PostDKG(secretShare group.Scalar, groupPublicKey group.Element) (group.Scalar, group.Element, error)

	// PostGenerate may validate or convert the secret share and group key after dealer keygen; return them unchanged by default.
	PostGenerate(secretShare group.Scalar, groupPublicKey group.Element) (group.Scalar, group.Element, error)
}

// DefaultHooks provides pass-through implementations for all hooks.
// Ciphersuites that don't need customization can embed this.
type DefaultHooks struct{}

// PreSign returns the message unchanged.
func (DefaultHooks) PreSign(msg []byte) ([]byte, error) {
	return msg, nil
}

// PreAggregate returns the values unchanged.
func (DefaultHooks) PreAggregate(msg []byte, groupCommitment group.Element) ([]byte, group.Element, error) {
	return msg, groupCommitment, nil
}

// PreVerify returns the values unchanged.
func (DefaultHooks) PreVerify(msg []byte, r group.Element, z group.Scalar, publicKey group.Element) ([]byte, group.Element, group.Scalar, group.Element, error) {
	return msg, r, z, publicKey, nil
}

// PostDKG returns the values unchanged.
func (DefaultHooks) PostDKG(secretShare group.Scalar, groupPublicKey group.Element) (group.Scalar, group.Element, error) {
	return secretShare, groupPublicKey, nil
}

// PostGenerate returns the values unchanged.
func (DefaultHooks) PostGenerate(secretShare group.Scalar, groupPublicKey group.Element) (group.Scalar, group.Element, error) {
	return secretShare, groupPublicKey, nil
}

// GetHooks returns the hooks for a ciphersuite.
// If the ciphersuite implements Hooks, it returns those hooks.
// Otherwise, it returns DefaultHooks.
func GetHooks(suite Ciphersuite) Hooks {
	if h, ok := suite.(Hooks); ok {
		return h
	}
	return DefaultHooks{}
}
