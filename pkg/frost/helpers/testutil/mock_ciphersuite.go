package testutil

import (
	"crypto/sha512"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// MockCiphersuite is a simple mock implementation of ciphersuite.Ciphersuite for testing
type MockCiphersuite struct {
	group *MockGroup
}

// NewMockCiphersuite creates a new mock ciphersuite for testing
func NewMockCiphersuite() *MockCiphersuite {
	return &MockCiphersuite{
		group: NewMockGroup(),
	}
}

func (m *MockCiphersuite) ID() string {
	return "FROST-MOCK-SHA512-v1"
}

func (m *MockCiphersuite) Group() group.Group {
	return m.group
}

// H1 implements domain-separated hash to scalar for binding factors
func (m *MockCiphersuite) H1(data []byte) group.Scalar {
	return m.hashToScalar("FROST-MOCK-SHA512-v1-H1", data)
}

// H2 implements domain-separated hash to scalar for challenge
func (m *MockCiphersuite) H2(data []byte) group.Scalar {
	return m.hashToScalar("FROST-MOCK-SHA512-v1-H2", data)
}

// H3 implements domain-separated hash to scalar for nonce generation
func (m *MockCiphersuite) H3(data []byte) group.Scalar {
	return m.hashToScalar("FROST-MOCK-SHA512-v1-H3", data)
}

// H4 implements domain-separated hash for message
func (m *MockCiphersuite) H4(msg []byte) []byte {
	return m.domainSeparatedHash("FROST-MOCK-SHA512-v1-H4", msg)
}

// H5 implements domain-separated hash for commitment list
func (m *MockCiphersuite) H5(data []byte) []byte {
	return m.domainSeparatedHash("FROST-MOCK-SHA512-v1-H5", data)
}

// HashToCurve maps arbitrary bytes to a group element
func (m *MockCiphersuite) HashToCurve(data []byte) (group.Element, error) {
	// Simple implementation: hash to scalar then multiply by generator
	scalar := m.hashToScalar("FROST-MOCK-SHA512-v1-H2C", data)
	return m.group.ScalarBaseMult(scalar), nil
}

// Hash is the underlying hash function (SHA-512 for this mock)
func (m *MockCiphersuite) Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// VerifySignature verifies a Schnorr signature
func (m *MockCiphersuite) VerifySignature(message []byte, signature []byte, publicKey group.Element) error {
	// Simple mock verification - in production this would be full Schnorr verification
	if len(signature) < 64 {
		return &MockVerificationError{reason: "signature too short"}
	}
	return nil
}

// ContextString returns the domain separation context
func (m *MockCiphersuite) ContextString() string {
	return "FROST-MOCK-SHA512-v1"
}

// Name returns the ciphersuite name
func (m *MockCiphersuite) Name() string {
	return "FROST Mock Ciphersuite (SHA-512)"
}

// Helper function to perform domain-separated hashing to scalar
func (m *MockCiphersuite) hashToScalar(domain string, data []byte) group.Scalar {
	// Concatenate domain separator and data
	input := append([]byte(domain), 0x00)
	input = append(input, data...)

	// Hash the input
	hash := sha512.Sum512(input)

	// Convert hash to scalar (reduce modulo order)
	scalar := m.group.NewScalar().(*MockScalar)
	scalar.SetBytes(hash[:])

	return scalar
}

// Helper function for domain-separated hashing
func (m *MockCiphersuite) domainSeparatedHash(domain string, data []byte) []byte {
	input := append([]byte(domain), 0x00)
	input = append(input, data...)
	hash := sha512.Sum512(input)
	return hash[:]
}

// MockVerificationError is a simple error type for signature verification
type MockVerificationError struct {
	reason string
}

func (e *MockVerificationError) Error() string {
	return "signature verification failed: " + e.reason
}
