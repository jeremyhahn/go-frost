package rfc

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

// TestSection6_Ciphersuites tests RFC 9591 Section 6
// ciphersuite requirements and specifications
func TestSection6_Ciphersuites(t *testing.T) {
	// RFC 9591 Section 6: Ciphersuites

	t.Run("Ristretto255SHA512", func(t *testing.T) {
		// RFC 9591 Section 6.2: FROST(ristretto255, SHA-512)
		suite := ristretto255_sha512.New()
		grp := suite.Group()

		// RFC 9591 Section 6.2: Group order for ristretto255
		order := grp.Order()
		if len(order) == 0 {
			t.Fatal("Group order should be non-zero")
		}

		// RFC 9591 Section 6.2: Element and Scalar lengths
		// ristretto255: Ne = 32, Ns = 32
		if grp.ElementLength() != 32 {
			t.Errorf("Expected element length 32, got %d", grp.ElementLength())
		}
		if grp.ScalarLength() != 32 {
			t.Errorf("Expected scalar length 32, got %d", grp.ScalarLength())
		}

		// Verify hash functions are available
		testInput := []byte("test")

		h1 := suite.H1(testInput)
		if h1 == nil {
			t.Error("H1 should not return nil")
		}

		h2 := suite.H2(testInput)
		if h2 == nil {
			t.Error("H2 should not return nil")
		}

		h3 := suite.H3(testInput)
		if h3 == nil {
			t.Error("H3 should not return nil")
		}

		h4 := suite.H4(testInput)
		if h4 == nil {
			t.Error("H4 should not return nil")
		}

		h5 := suite.H5(testInput)
		if h5 == nil {
			t.Error("H5 should not return nil")
		}
	})

	t.Run("CiphersuiteID", func(t *testing.T) {
		// RFC 9591 Section 6: Each ciphersuite has a unique identifier
		suite := ristretto255_sha512.New()

		id := suite.ID()
		if id == "" {
			t.Error("Ciphersuite ID should not be empty")
		}

		// RFC 9591 Section 6.2: Ciphersuite ID for ristretto255-SHA512
		// Should be "FROST-RISTRETTO255-SHA512-v1"
		expectedID := "FROST-RISTRETTO255-SHA512-v1"
		if id != expectedID {
			t.Errorf("Expected ciphersuite ID %s, got %s", expectedID, id)
		}
	})

	t.Run("GroupValidation", func(t *testing.T) {
		// RFC 9591 Section 6.6: Each ciphersuite MUST adhere to requirements
		suite := ristretto255_sha512.New()
		grp := suite.Group()

		// Test basic group operations
		scalar1, _ := grp.RandomScalar()
		scalar2, _ := grp.RandomScalar()

		element1 := grp.ScalarBaseMult(scalar1)
		element2 := grp.ScalarBaseMult(scalar2)

		// Group operation should be well-defined
		sum := element1.Add(element2)
		if sum == nil {
			t.Error("Group addition should produce valid result")
		}

		// Serialization should be canonical
		serialized := element1.Bytes()
		if len(serialized) != grp.ElementLength() {
			t.Error("Serialization should produce fixed-length output")
		}

		// Deserialization should be inverse of serialization
		deserialized, err := grp.DeserializeElement(serialized)
		if err != nil {
			t.Errorf("Deserialization failed: %v", err)
		}
		if !deserialized.Equal(element1) {
			t.Error("Deserialized element should equal original")
		}
	})

	t.Run("HashFunctionRequirements", func(t *testing.T) {
		// RFC 9591 Section 6.6: Hash function requirements
		suite := ristretto255_sha512.New()

		testInput := []byte("hash function test")

		// H1, H2, H3 should map to Scalars
		h1Result := suite.H1(testInput)
		if h1Result == nil {
			t.Error("H1 should produce Scalar")
		}

		h2Result := suite.H2(testInput)
		if h2Result == nil {
			t.Error("H2 should produce Scalar")
		}

		h3Result := suite.H3(testInput)
		if h3Result == nil {
			t.Error("H3 should produce Scalar")
		}

		// H4, H5 should produce byte strings
		h4Result := suite.H4(testInput)
		if len(h4Result) == 0 {
			t.Error("H4 should produce non-empty byte string")
		}

		h5Result := suite.H5(testInput)
		if len(h5Result) == 0 {
			t.Error("H5 should produce non-empty byte string")
		}
	})

	t.Run("SignatureVerification", func(t *testing.T) {
		// RFC 9591 Section 6: Signature verification as specified in ciphersuite
		suite := ristretto255_sha512.New()
		grp := suite.Group()

		// Create a simple signature (for structure testing only)
		rScalar, _ := grp.RandomScalar()
		r := grp.ScalarBaseMult(rScalar)
		z, _ := grp.RandomScalar()

		signature := append(r.Bytes(), z.Bytes()...)

		// Verify signature has correct length
		expectedLen := grp.ElementLength() + grp.ScalarLength()
		if len(signature) != expectedLen {
			t.Errorf("Signature length should be %d, got %d", expectedLen, len(signature))
		}
	})
}
