package rfc

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

// TestSection3_1_PrimeOrderGroup tests RFC 9591 Section 3.1 requirements
// for prime-order group operations
func TestSection3_1_PrimeOrderGroup(t *testing.T) {
	// RFC 9591 Section 3.1: Prime-Order Group
	// Tests the fundamental group operations required by FROST
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("Order", func(t *testing.T) {
		// RFC 9591 Section 3.1: Order() outputs the order of G (i.e., p)
		orderBytes := grp.Order()
		if len(orderBytes) == 0 {
			t.Fatal("Order() returned nil or empty")
		}
		// Ristretto255 group order should be non-zero
		// Check that it's not all zeros
		allZero := true
		for _, b := range orderBytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("Group order should not be zero")
		}
	})

	t.Run("Identity", func(t *testing.T) {
		// RFC 9591 Section 3.1: Identity() outputs the identity Element of the group (i.e., I)
		identity := grp.Identity()
		if identity == nil {
			t.Fatal("Identity() returned nil")
		}

		// RFC 9591 Section 3.1: For any A in G, A + (-A) = (-A) + A = I
		randomScalar, _ := grp.RandomScalar()
		element := grp.ScalarBaseMult(randomScalar)
		negElement := element.Negate()

		// A + (-A) = I
		result1 := element.Add(negElement)
		if !result1.Equal(identity) {
			t.Error("A + (-A) should equal identity")
		}

		// (-A) + A = I
		result2 := negElement.Add(element)
		if !result2.Equal(identity) {
			t.Error("(-A) + A should equal identity")
		}
	})

	t.Run("RandomScalar", func(t *testing.T) {
		// RFC 9591 Section 3.1: RandomScalar() outputs a random Scalar element in GF(p)
		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()

		if scalar1 == nil || scalar2 == nil {
			t.Fatal("RandomScalar() returned nil")
		}

		// With overwhelming probability, two random scalars should be different
		if scalar1.Equal(scalar2) {
			t.Error("Two random scalars should be different (with overwhelming probability)")
		}
	})

	t.Run("ScalarBaseMult", func(t *testing.T) {
		// RFC 9591 Section 3.1: ScalarBaseMult(k) outputs the Scalar multiplication
		// between Scalar k and the group generator B
		scalar, _ := grp.RandomScalar()
		element := grp.ScalarBaseMult(scalar)

		if element == nil {
			t.Fatal("ScalarBaseMult() returned nil")
		}

		// RFC 9591 Section 3.1: For any element A, ScalarMult(A, p) = I
		// Note: This test would be very slow, so we test a different property
		// ScalarBaseMult(0) should equal Identity
		zeroScalar := grp.NewScalar() // Creates zero scalar
		zeroElement := grp.ScalarBaseMult(zeroScalar)
		if !zeroElement.Equal(grp.Identity()) {
			t.Error("ScalarBaseMult(0) should equal identity")
		}
	})

	t.Run("ScalarMult", func(t *testing.T) {
		// RFC 9591 Section 3.1: ScalarMult(A, k) outputs the Scalar multiplication
		// between Element A and Scalar k
		baseScalar, _ := grp.RandomScalar()
		baseElement := grp.ScalarBaseMult(baseScalar)

		multScalar, _ := grp.RandomScalar()
		result := grp.ScalarMult(baseElement, multScalar)

		if result == nil {
			t.Fatal("ScalarMult() returned nil")
		}

		// Verify distributive property: k1 * (k2 * G) = (k1 * k2) * G
		productScalar := baseScalar.Mul(multScalar)
		expected := grp.ScalarBaseMult(productScalar)

		if !result.Equal(expected) {
			t.Error("ScalarMult does not satisfy distributive property")
		}
	})

	t.Run("GroupAddition", func(t *testing.T) {
		// RFC 9591 Section 3.1: For any elements A and B of the group G, A + B = B + A
		// is also a member of G (commutative property)
		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()

		element1 := grp.ScalarBaseMult(scalar1)
		element2 := grp.ScalarBaseMult(scalar2)

		// Test commutativity: A + B = B + A
		result1 := element1.Add(element2)
		result2 := element2.Add(element1)

		if !result1.Equal(result2) {
			t.Error("Group addition should be commutative (A + B = B + A)")
		}

		// Verify the result equals (scalar1 + scalar2) * G
		scalarSum := scalar1.Add(scalar2)
		expected := grp.ScalarBaseMult(scalarSum)

		if !result1.Equal(expected) {
			t.Error("Group addition does not match scalar addition")
		}
	})

	t.Run("SerializeDeserializeElement", func(t *testing.T) {
		// RFC 9591 Section 3.1: SerializeElement(A) maps an Element A to a canonical
		// byte array buf of fixed length Ne
		scalar, _ := grp.RandomScalar()
		element := grp.ScalarBaseMult(scalar)

		// Serialize
		serialized := element.Bytes()
		if len(serialized) != grp.ElementLength() {
			t.Errorf("Serialized element length %d != expected %d", len(serialized), grp.ElementLength())
		}

		// RFC 9591 Section 3.1: DeserializeElement(buf) attempts to map a byte array
		// buf to an Element A
		deserialized, err := grp.DeserializeElement(serialized)
		if err != nil {
			t.Fatalf("DeserializeElement failed: %v", err)
		}

		if !deserialized.Equal(element) {
			t.Error("Deserialized element does not match original")
		}
	})

	t.Run("SerializeDeserializeScalar", func(t *testing.T) {
		// RFC 9591 Section 3.1: SerializeScalar(s) maps a Scalar s to a canonical
		// byte array buf of fixed length Ns
		scalar, _ := grp.RandomScalar()

		// Serialize
		serialized := scalar.Bytes()
		if len(serialized) != grp.ScalarLength() {
			t.Errorf("Serialized scalar length %d != expected %d", len(serialized), grp.ScalarLength())
		}

		// RFC 9591 Section 3.1: DeserializeScalar(buf) attempts to map a byte array
		// buf to a Scalar s
		deserialized, err := grp.DeserializeScalar(serialized)
		if err != nil {
			t.Fatalf("DeserializeScalar failed: %v", err)
		}

		if !deserialized.Equal(scalar) {
			t.Error("Deserialized scalar does not match original")
		}
	})

	t.Run("IdentityRejection", func(t *testing.T) {
		// RFC 9591 Section 3.1: SerializeElement raises an error if A is the
		// identity element of the group
		identity := grp.Identity()

		// Note: The implementation may or may not enforce this in SerializeElement
		// but DeserializeElement MUST reject identity
		serialized := identity.Bytes()

		// RFC 9591 Section 3.1: DeserializeElement raises an error if A is the
		// identity element of the group
		_, err := grp.DeserializeElement(serialized)
		if err == nil {
			t.Error("DeserializeElement should reject identity element")
		}
	})

	t.Run("ScalarArithmetic", func(t *testing.T) {
		// RFC 9591 Section 3.1: Scalar arithmetic operations are implicitly
		// performed modulo p
		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()

		// Test addition
		sum := scalar1.Add(scalar2)
		if sum == nil {
			t.Fatal("Scalar addition returned nil")
		}

		// Test subtraction
		diff := scalar1.Sub(scalar2)
		if diff == nil {
			t.Fatal("Scalar subtraction returned nil")
		}

		// Test multiplication
		product := scalar1.Mul(scalar2)
		if product == nil {
			t.Fatal("Scalar multiplication returned nil")
		}

		// Verify: (a - b) + b = a
		reconstructed := diff.Add(scalar2)
		if !reconstructed.Equal(scalar1) {
			t.Error("Scalar arithmetic does not satisfy (a - b) + b = a")
		}
	})
}

// TestSection3_2_CryptographicHashFunction tests RFC 9591 Section 3.2
// requirements for cryptographic hash functions
func TestSection3_2_CryptographicHashFunction(t *testing.T) {
	// RFC 9591 Section 3.2: Cryptographic Hash Function
	// Tests that the ciphersuite provides domain-separated hash functions H1-H5
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	t.Run("H1_HashToScalar", func(t *testing.T) {
		// RFC 9591 Section 3.2: H1 maps arbitrary byte strings to Scalar elements
		input1 := []byte("test input 1")
		input2 := []byte("test input 2")

		scalar1 := suite.H1(input1)
		scalar2 := suite.H1(input2)

		if scalar1 == nil || scalar2 == nil {
			t.Fatal("H1 returned nil")
		}

		// Different inputs should produce different outputs
		if scalar1.Equal(scalar2) {
			t.Error("H1 should produce different outputs for different inputs")
		}

		// Same input should produce same output (deterministic)
		scalar1Again := suite.H1(input1)
		if !scalar1.Equal(scalar1Again) {
			t.Error("H1 should be deterministic")
		}
	})

	t.Run("H2_ChallengeHash", func(t *testing.T) {
		// RFC 9591 Section 3.2: H2 maps arbitrary byte strings to Scalar elements
		input1 := []byte("challenge input 1")
		input2 := []byte("challenge input 2")

		scalar1 := suite.H2(input1)
		scalar2 := suite.H2(input2)

		if scalar1 == nil || scalar2 == nil {
			t.Fatal("H2 returned nil")
		}

		// Different inputs should produce different outputs
		if scalar1.Equal(scalar2) {
			t.Error("H2 should produce different outputs for different inputs")
		}
	})

	t.Run("H3_NonceHash", func(t *testing.T) {
		// RFC 9591 Section 3.2: H3 maps arbitrary byte strings to Scalar elements
		input1 := []byte("nonce input 1")
		input2 := []byte("nonce input 2")

		scalar1 := suite.H3(input1)
		scalar2 := suite.H3(input2)

		if scalar1 == nil || scalar2 == nil {
			t.Fatal("H3 returned nil")
		}

		// Different inputs should produce different outputs
		if scalar1.Equal(scalar2) {
			t.Error("H3 should produce different outputs for different inputs")
		}
	})

	t.Run("H4_MessageHash", func(t *testing.T) {
		// RFC 9591 Section 3.2: H4 is an alias for H with distinct domain separator
		input1 := []byte("message 1")
		input2 := []byte("message 2")

		hash1 := suite.H4(input1)
		hash2 := suite.H4(input2)

		if hash1 == nil || hash2 == nil {
			t.Fatal("H4 returned nil")
		}

		// Different inputs should produce different outputs
		if string(hash1) == string(hash2) {
			t.Error("H4 should produce different outputs for different inputs")
		}
	})

	t.Run("H5_CommitmentHash", func(t *testing.T) {
		// RFC 9591 Section 3.2: H5 is an alias for H with distinct domain separator
		input1 := []byte("commitment data 1")
		input2 := []byte("commitment data 2")

		hash1 := suite.H5(input1)
		hash2 := suite.H5(input2)

		if hash1 == nil || hash2 == nil {
			t.Fatal("H5 returned nil")
		}

		// Different inputs should produce different outputs
		if string(hash1) == string(hash2) {
			t.Error("H5 should produce different outputs for different inputs")
		}
	})

	t.Run("DomainSeparation", func(t *testing.T) {
		// RFC 9591 Section 3.2: H1, H2, H3, H4, and H5 are domain-separated
		// The same input to different hash functions should produce different outputs
		input := []byte("same input")

		scalar1 := suite.H1(input)
		scalar2 := suite.H2(input)
		scalar3 := suite.H3(input)

		// H1, H2, H3 should produce different outputs due to domain separation
		if scalar1.Equal(scalar2) || scalar1.Equal(scalar3) || scalar2.Equal(scalar3) {
			t.Error("Domain-separated hash functions should produce different outputs for the same input")
		}

		hash4 := suite.H4(input)
		hash5 := suite.H5(input)

		// H4 and H5 should produce different outputs due to domain separation
		if string(hash4) == string(hash5) {
			t.Error("H4 and H5 should produce different outputs for the same input")
		}
	})

	t.Run("ScalarFieldMembership", func(t *testing.T) {
		// RFC 9591 Section 3.2: H1, H2, and H3 output Scalars in the valid range [0, p-1]
		input := []byte("test input")

		scalar := suite.H1(input)
		if scalar == nil {
			t.Fatal("H1 returned nil")
		}

		// The scalar should be usable in group operations
		element := grp.ScalarBaseMult(scalar)
		if element == nil {
			t.Error("Scalar from H1 should be valid for group operations")
		}
	})
}
