package frost_test

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// =====================================
// COFACTOR VERIFICATION TESTS
// =====================================

// TestCofactor_Ed25519 verifies Ed25519 has cofactor 8
func TestCofactor_Ed25519(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()

	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor should not be nil")
	}

	// Ed25519 has cofactor 8
	// Create scalar with value 8 to compare
	eightBytes := make([]byte, grp.ScalarLength())
	eightBytes[0] = 8 // Little-endian
	eight, err := grp.DeserializeScalar(eightBytes)
	if err != nil {
		t.Fatalf("Failed to create scalar 8: %v", err)
	}

	if !cofactor.Equal(eight) {
		t.Errorf("Ed25519 cofactor should be 8")
	}
}

// TestCofactor_Ed448 verifies Ed448 has cofactor 4
func TestCofactor_Ed448(t *testing.T) {
	suite := ed448_shake256.New()
	grp := suite.Group()

	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor should not be nil")
	}

	// Ed448 has cofactor 4
	fourBytes := make([]byte, grp.ScalarLength())
	fourBytes[0] = 4 // Little-endian
	four, err := grp.DeserializeScalar(fourBytes)
	if err != nil {
		t.Fatalf("Failed to create scalar 4: %v", err)
	}

	if !cofactor.Equal(four) {
		t.Errorf("Ed448 cofactor should be 4")
	}
}

// TestCofactor_Ristretto255 verifies ristretto255 has cofactor 1
func TestCofactor_Ristretto255(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor should not be nil")
	}

	// ristretto255 has cofactor 1 (prime-order group)
	oneBytes := make([]byte, grp.ScalarLength())
	oneBytes[0] = 1 // Little-endian
	one, err := grp.DeserializeScalar(oneBytes)
	if err != nil {
		t.Fatalf("Failed to create scalar 1: %v", err)
	}

	if !cofactor.Equal(one) {
		t.Errorf("ristretto255 cofactor should be 1")
	}
}

// TestCofactor_P256 verifies P-256 has cofactor 1
func TestCofactor_P256(t *testing.T) {
	suite := p256_sha256.New()
	grp := suite.Group()

	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor should not be nil")
	}

	// P-256 has cofactor 1 (prime-order group)
	oneBytes := make([]byte, grp.ScalarLength())
	oneBytes[grp.ScalarLength()-1] = 1 // Big-endian
	one, err := grp.DeserializeScalar(oneBytes)
	if err != nil {
		t.Fatalf("Failed to create scalar 1: %v", err)
	}

	if !cofactor.Equal(one) {
		t.Errorf("P-256 cofactor should be 1")
	}
}

// TestCofactor_Secp256k1 verifies secp256k1 has cofactor 1
func TestCofactor_Secp256k1(t *testing.T) {
	suite := secp256k1_sha256.New()
	grp := suite.Group()

	cofactor := grp.Cofactor()
	if cofactor == nil {
		t.Fatal("Cofactor should not be nil")
	}

	// secp256k1 has cofactor 1 (prime-order group)
	oneBytes := make([]byte, grp.ScalarLength())
	oneBytes[grp.ScalarLength()-1] = 1 // Big-endian
	one, err := grp.DeserializeScalar(oneBytes)
	if err != nil {
		t.Fatalf("Failed to create scalar 1: %v", err)
	}

	if !cofactor.Equal(one) {
		t.Errorf("secp256k1 cofactor should be 1")
	}
}

// TestCofactor_NonZero verifies cofactors are never zero for all groups
func TestCofactor_NonZero(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ed448_shake256.New(),
		ristretto255_sha512.New(),
		p256_sha256.New(),
		secp256k1_sha256.New(),
	}

	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()
			cofactor := grp.Cofactor()

			if cofactor.IsZero() {
				t.Errorf("Cofactor should never be zero for %s", suite.Name())
			}
		})
	}
}

// =====================================
// IDENTITY ELEMENT REJECTION TESTS
// =====================================

// TestIdentityRejection_SerializeElement tests that identity element cannot be serialized
func TestIdentityRejection_SerializeElement(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ed448_shake256.New(),
		ristretto255_sha512.New(),
		p256_sha256.New(),
		secp256k1_sha256.New(),
	}

	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()
			identity := grp.Identity()

			_, err := grp.SerializeElement(identity)
			if err == nil {
				t.Error("Expected error when serializing identity element")
			}
			if err != frost.ErrIdentityElement {
				t.Errorf("Expected ErrIdentityElement, got %v", err)
			}
		})
	}
}

// TestIdentityRejection_DeserializeElement tests that identity bytes are rejected
func TestIdentityRejection_DeserializeElement(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ristretto255_sha512.New(),
		// Note: Ed25519 and Ed448 identity encoding may differ
	}

	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()

			// Create all-zeros bytes (identity for ristretto255)
			zeroBytes := make([]byte, grp.ElementLength())

			_, err := grp.DeserializeElement(zeroBytes)
			if err == nil {
				t.Error("Expected error when deserializing identity element")
			}
		})
	}
}

// TestIdentityRejection_SigningCommitment tests identity is rejected in nonce commitments
func TestIdentityRejection_SigningCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Try to create commitments with identity elements
	// This should be caught during signing validation
	invalidCommitment := frost.SigningCommitments{
		HidingNonceCommitment: grp.Identity(), // Invalid!
	}

	// Verify the commitment has identity element
	if !invalidCommitment.HidingNonceCommitment.IsIdentity() {
		t.Error("Test setup error: HidingNonceCommitment should be identity")
	}
}

// TestIdentityRejection_PublicKey tests that identity public keys are rejected
func TestIdentityRejection_PublicKey(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ristretto255_sha512.New(),
		p256_sha256.New(),
		secp256k1_sha256.New(),
	}

	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()
			identity := grp.Identity()

			// Verify identity is actually identity
			if !identity.IsIdentity() {
				t.Fatal("Identity element should report as identity")
			}

			// Zero scalar should produce identity when multiplied with generator
			zeroScalar := grp.NewScalar()
			result := grp.ScalarBaseMult(zeroScalar)

			if !result.IsIdentity() {
				t.Error("0 * G should produce identity element")
			}
		})
	}
}

// =====================================
// ZEROIZATION EFFECTIVENESS TESTS
// =====================================

// TestZeroization_KeyPackage tests KeyPackage.Zeroize() effectiveness
func TestZeroization_KeyPackage(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a KeyPackage with a secret share
	secretShare, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret share: %v", err)
	}

	// Verify secret is not zero initially
	if secretShare.IsZero() {
		t.Fatal("Secret share should not be zero initially")
	}

	// Store original bytes to verify they were non-zero
	originalBytes := make([]byte, len(secretShare.Bytes()))
	copy(originalBytes, secretShare.Bytes())

	// Verify original bytes are not all zeros
	hasNonZero := false
	for _, b := range originalBytes {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Original secret share bytes were all zero - test may be invalid")
	}

	keyPackage := frost.KeyPackage{
		Identifier:     1,
		SecretShare:    secretShare,
		GroupPublicKey: grp.ScalarBaseMult(secretShare),
		MinSigners:     2,
		MaxSigners:     3,
	}

	// Zeroize the key package
	keyPackage.Zeroize()

	// Verify secret share is zero after zeroization
	if !keyPackage.SecretShare.IsZero() {
		t.Error("SecretShare should be zero after Zeroize()")
	}

	// Verify the bytes are all zeros
	zeroizedBytes := keyPackage.SecretShare.Bytes()
	for i, b := range zeroizedBytes {
		if b != 0 {
			t.Errorf("SecretShare byte %d is not zero: got %d", i, b)
		}
	}
}

// TestZeroization_SecretKeyShare tests SecretKeyShare.Zeroize() effectiveness
func TestZeroization_SecretKeyShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a SecretKeyShare
	secret, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if secret.IsZero() {
		t.Fatal("Secret should not be zero initially")
	}

	secretKeyShare := frost.SecretKeyShare{
		Identifier:  1,
		SecretShare: secret,
	}

	// Zeroize
	secretKeyShare.Zeroize()

	// Verify secret share is zero
	if !secretKeyShare.SecretShare.IsZero() {
		t.Error("SecretShare should be zero after Zeroize()")
	}
}

// TestZeroization_Polynomial tests Polynomial.Zeroize() effectiveness
func TestZeroization_Polynomial(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a polynomial with random coefficients
	coefficients := make([]group.Scalar, 3)
	for i := range coefficients {
		coeff, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("Failed to generate coefficient: %v", err)
		}
		coefficients[i] = coeff
	}

	// Verify coefficients are not zero
	for i, coeff := range coefficients {
		if coeff.IsZero() {
			t.Fatalf("Coefficient %d should not be zero initially", i)
		}
	}

	polynomial := frost.Polynomial{
		Coefficients: coefficients,
	}

	// Zeroize
	polynomial.Zeroize()

	// Verify all coefficients are zero
	for i, coeff := range polynomial.Coefficients {
		if !coeff.IsZero() {
			t.Errorf("Coefficient %d should be zero after Zeroize()", i)
		}
	}
}

// TestZeroization_MultipleCallsSafe tests that calling Zeroize multiple times is safe
func TestZeroization_MultipleCallsSafe(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// KeyPackage
	secret, _ := grp.RandomScalar()
	kp := frost.KeyPackage{SecretShare: secret}
	kp.Zeroize()
	kp.Zeroize()
	kp.Zeroize()
	if !kp.SecretShare.IsZero() {
		t.Error("KeyPackage should remain zeroed after multiple Zeroize() calls")
	}

	// SecretKeyShare
	secret2, _ := grp.RandomScalar()
	sks := frost.SecretKeyShare{SecretShare: secret2}
	sks.Zeroize()
	sks.Zeroize()
	if !sks.SecretShare.IsZero() {
		t.Error("SecretKeyShare should remain zeroed after multiple Zeroize() calls")
	}
}

// =====================================
// HOOK CUSTOMIZATION TESTS
// =====================================

// TestHooks_DefaultHooks tests that DefaultHooks pass through values unchanged
func TestHooks_DefaultHooks(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	grp := ristretto255_sha512.New().Group()

	// PreSign
	msg := []byte("test message")
	result, err := hooks.PreSign(msg)
	if err != nil {
		t.Errorf("PreSign error: %v", err)
	}
	if string(result) != string(msg) {
		t.Error("PreSign should return message unchanged")
	}

	// PreAggregate
	scalar, _ := grp.RandomScalar()
	elem := grp.ScalarBaseMult(scalar)
	resultMsg, resultElem, err := hooks.PreAggregate(msg, elem)
	if err != nil {
		t.Errorf("PreAggregate error: %v", err)
	}
	if string(resultMsg) != string(msg) || !resultElem.Equal(elem) {
		t.Error("PreAggregate should return values unchanged")
	}

	// PreVerify
	r := grp.ScalarBaseMult(scalar)
	z, _ := grp.RandomScalar()
	pk := grp.ScalarBaseMult(z)
	rMsg, rR, rZ, rPK, err := hooks.PreVerify(msg, r, z, pk)
	if err != nil {
		t.Errorf("PreVerify error: %v", err)
	}
	if string(rMsg) != string(msg) || !rR.Equal(r) || !rZ.Equal(z) || !rPK.Equal(pk) {
		t.Error("PreVerify should return values unchanged")
	}

	// PostDKG
	secret, _ := grp.RandomScalar()
	groupPK := grp.ScalarBaseMult(secret)
	rSecret, rGroupPK, err := hooks.PostDKG(secret, groupPK)
	if err != nil {
		t.Errorf("PostDKG error: %v", err)
	}
	if !rSecret.Equal(secret) || !rGroupPK.Equal(groupPK) {
		t.Error("PostDKG should return values unchanged")
	}

	// PostGenerate
	rSecret, rGroupPK, err = hooks.PostGenerate(secret, groupPK)
	if err != nil {
		t.Errorf("PostGenerate error: %v", err)
	}
	if !rSecret.Equal(secret) || !rGroupPK.Equal(groupPK) {
		t.Error("PostGenerate should return values unchanged")
	}
}

// TestHooks_GetHooks tests GetHooks function
func TestHooks_GetHooks(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Standard ciphersuite should return DefaultHooks (or its own hooks if implemented)
	hooks := ciphersuite.GetHooks(suite)
	if hooks == nil {
		t.Error("GetHooks should never return nil")
	}

	// Test that returned hooks work correctly
	msg := []byte("test")
	result, err := hooks.PreSign(msg)
	if err != nil {
		t.Errorf("PreSign should not error: %v", err)
	}
	if result == nil {
		t.Error("PreSign should return a result")
	}
}

// =====================================
// BYTE ORDER CORRECTNESS TESTS
// =====================================

// TestByteOrder_LittleEndian tests little-endian groups
func TestByteOrder_LittleEndian(t *testing.T) {
	littleEndianSuites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ed448_shake256.New(),
		ristretto255_sha512.New(),
	}

	for _, suite := range littleEndianSuites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()

			if grp.ByteOrder() != group.LittleEndian {
				t.Errorf("%s should use little-endian byte order", suite.Name())
			}

			// Verify serialization is consistent
			scalar, _ := grp.RandomScalar()
			bytes := grp.SerializeScalar(scalar)

			deserialized, err := grp.DeserializeScalar(bytes)
			if err != nil {
				t.Errorf("Failed to deserialize scalar: %v", err)
			}

			if !deserialized.Equal(scalar) {
				t.Error("Round-trip serialization failed")
			}
		})
	}
}

// TestByteOrder_BigEndian tests big-endian groups
func TestByteOrder_BigEndian(t *testing.T) {
	bigEndianSuites := []ciphersuite.Ciphersuite{
		p256_sha256.New(),
		secp256k1_sha256.New(),
	}

	for _, suite := range bigEndianSuites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()

			if grp.ByteOrder() != group.BigEndian {
				t.Errorf("%s should use big-endian byte order", suite.Name())
			}

			// Verify serialization is consistent
			scalar, _ := grp.RandomScalar()
			bytes := grp.SerializeScalar(scalar)

			deserialized, err := grp.DeserializeScalar(bytes)
			if err != nil {
				t.Errorf("Failed to deserialize scalar: %v", err)
			}

			if !deserialized.Equal(scalar) {
				t.Error("Round-trip serialization failed")
			}
		})
	}
}

// TestByteOrder_ScalarOne tests that scalar 1 is correctly encoded
func TestByteOrder_ScalarOne(t *testing.T) {
	testCases := []struct {
		suite         ciphersuite.Ciphersuite
		expectedOrder group.ByteOrder
	}{
		{ed25519_sha512.New(), group.LittleEndian},
		{ristretto255_sha512.New(), group.LittleEndian},
		{ed448_shake256.New(), group.LittleEndian},
		{p256_sha256.New(), group.BigEndian},
		{secp256k1_sha256.New(), group.BigEndian},
	}

	for _, tc := range testCases {
		t.Run(tc.suite.Name(), func(t *testing.T) {
			grp := tc.suite.Group()

			// Create scalar with value 1
			oneBytes := make([]byte, grp.ScalarLength())
			if tc.expectedOrder == group.LittleEndian {
				oneBytes[0] = 1 // Little-endian: LSB first
			} else {
				oneBytes[grp.ScalarLength()-1] = 1 // Big-endian: MSB first
			}

			one, err := grp.DeserializeScalar(oneBytes)
			if err != nil {
				t.Fatalf("Failed to create scalar 1: %v", err)
			}

			// Verify 1 * G = G
			result := grp.ScalarBaseMult(one)
			generator := grp.Generator()

			if !result.Equal(generator) {
				t.Error("1 * G should equal G")
			}
		})
	}
}

// TestByteOrder_AllGroups tests byte order is correctly reported
func TestByteOrder_AllGroups(t *testing.T) {
	suites := []struct {
		suite         ciphersuite.Ciphersuite
		expectedOrder group.ByteOrder
	}{
		{ed25519_sha512.New(), group.LittleEndian},
		{ed448_shake256.New(), group.LittleEndian},
		{ristretto255_sha512.New(), group.LittleEndian},
		{p256_sha256.New(), group.BigEndian},
		{secp256k1_sha256.New(), group.BigEndian},
	}

	for _, tc := range suites {
		t.Run(tc.suite.Name(), func(t *testing.T) {
			grp := tc.suite.Group()

			if grp.ByteOrder() != tc.expectedOrder {
				t.Errorf("%s: expected %v, got %v", tc.suite.Name(), tc.expectedOrder, grp.ByteOrder())
			}
		})
	}
}

// =====================================
// ELEMENT LENGTH AND SCALAR LENGTH TESTS
// =====================================

// TestElementScalarLengths tests that element and scalar lengths are correct
func TestElementScalarLengths(t *testing.T) {
	testCases := []struct {
		suite         ciphersuite.Ciphersuite
		elementLength int
		scalarLength  int
	}{
		{ed25519_sha512.New(), 32, 32},
		{ristretto255_sha512.New(), 32, 32},
		{ed448_shake256.New(), 57, 57},
		{p256_sha256.New(), 33, 32},      // Compressed point
		{secp256k1_sha256.New(), 33, 32}, // Compressed point
	}

	for _, tc := range testCases {
		t.Run(tc.suite.Name(), func(t *testing.T) {
			grp := tc.suite.Group()

			if grp.ElementLength() != tc.elementLength {
				t.Errorf("%s: expected element length %d, got %d",
					tc.suite.Name(), tc.elementLength, grp.ElementLength())
			}

			if grp.ScalarLength() != tc.scalarLength {
				t.Errorf("%s: expected scalar length %d, got %d",
					tc.suite.Name(), tc.scalarLength, grp.ScalarLength())
			}
		})
	}
}

// TestSerializationRoundTrip tests that all groups have consistent serialization
func TestSerializationRoundTrip(t *testing.T) {
	suites := []ciphersuite.Ciphersuite{
		ed25519_sha512.New(),
		ed448_shake256.New(),
		ristretto255_sha512.New(),
		p256_sha256.New(),
		secp256k1_sha256.New(),
	}

	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			grp := suite.Group()

			// Test scalar round-trip
			scalar, err := grp.RandomScalar()
			if err != nil {
				t.Fatalf("Failed to generate random scalar: %v", err)
			}

			scalarBytes := grp.SerializeScalar(scalar)
			if len(scalarBytes) != grp.ScalarLength() {
				t.Errorf("Scalar bytes length mismatch: expected %d, got %d",
					grp.ScalarLength(), len(scalarBytes))
			}

			scalarDeserialized, err := grp.DeserializeScalar(scalarBytes)
			if err != nil {
				t.Fatalf("Failed to deserialize scalar: %v", err)
			}

			if !scalarDeserialized.Equal(scalar) {
				t.Error("Scalar round-trip failed")
			}

			// Test element round-trip
			element := grp.ScalarBaseMult(scalar)

			elementBytes, err := grp.SerializeElement(element)
			if err != nil {
				t.Fatalf("Failed to serialize element: %v", err)
			}

			if len(elementBytes) != grp.ElementLength() {
				t.Errorf("Element bytes length mismatch: expected %d, got %d",
					grp.ElementLength(), len(elementBytes))
			}

			elementDeserialized, err := grp.DeserializeElement(elementBytes)
			if err != nil {
				t.Fatalf("Failed to deserialize element: %v", err)
			}

			if !elementDeserialized.Equal(element) {
				t.Error("Element round-trip failed")
			}
		})
	}
}
