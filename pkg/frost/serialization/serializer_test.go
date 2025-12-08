package serialization

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

func TestSerializer_SerializeDeserializeSignature(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create a test signature
	scalar, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	r := grp.ScalarBaseMult(scalar)
	z, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}

	sig := frost.Signature{
		R: r,
		Z: z,
	}

	// Serialize
	data, err := serializer.SerializeSignature(sig)
	if err != nil {
		t.Fatalf("SerializeSignature failed: %v", err)
	}

	// Verify header
	header, err := DeserializeHeader(data)
	if err != nil {
		t.Fatalf("DeserializeHeader failed: %v", err)
	}

	if header.Version != CurrentVersion {
		t.Errorf("Expected version %d, got %d", CurrentVersion, header.Version)
	}

	if header.DataType != DataTypeSignature {
		t.Errorf("Expected data type %d, got %d", DataTypeSignature, header.DataType)
	}

	// Deserialize
	deserializedSig, err := serializer.DeserializeSignature(data)
	if err != nil {
		t.Fatalf("DeserializeSignature failed: %v", err)
	}

	// Verify equality
	if !deserializedSig.R.Equal(sig.R) {
		t.Error("Deserialized R does not match original")
	}

	if !deserializedSig.Z.Equal(sig.Z) {
		t.Error("Deserialized Z does not match original")
	}
}

func TestSerializer_SerializeDeserializeSigningCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create test commitments
	hidingScalar, _ := grp.RandomScalar()
	bindingScalar, _ := grp.RandomScalar()
	hiding := grp.ScalarBaseMult(hidingScalar)
	binding := grp.ScalarBaseMult(bindingScalar)

	commitments := frost.SigningCommitments{
		Identifier:             frost.Identifier(42),
		HidingNonceCommitment:  hiding,
		BindingNonceCommitment: binding,
	}

	// Serialize
	data, err := serializer.SerializeSigningCommitments(commitments)
	if err != nil {
		t.Fatalf("SerializeSigningCommitments failed: %v", err)
	}

	// Deserialize
	deserializedCommitments, err := serializer.DeserializeSigningCommitments(data)
	if err != nil {
		t.Fatalf("DeserializeSigningCommitments failed: %v", err)
	}

	// Verify equality
	if deserializedCommitments.Identifier != commitments.Identifier {
		t.Errorf("Expected identifier %d, got %d", commitments.Identifier, deserializedCommitments.Identifier)
	}

	if !deserializedCommitments.HidingNonceCommitment.Equal(commitments.HidingNonceCommitment) {
		t.Error("Deserialized hiding commitment does not match original")
	}

	if !deserializedCommitments.BindingNonceCommitment.Equal(commitments.BindingNonceCommitment) {
		t.Error("Deserialized binding commitment does not match original")
	}
}

func TestSerializer_SerializeDeserializeSignatureShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create test signature share
	share, _ := grp.RandomScalar()
	sigShare := frost.SignatureShare{
		Identifier:     frost.Identifier(7),
		SignatureShare: share,
	}

	// Serialize
	data, err := serializer.SerializeSignatureShare(sigShare)
	if err != nil {
		t.Fatalf("SerializeSignatureShare failed: %v", err)
	}

	// Deserialize
	deserializedShare, err := serializer.DeserializeSignatureShare(data)
	if err != nil {
		t.Fatalf("DeserializeSignatureShare failed: %v", err)
	}

	// Verify equality
	if deserializedShare.Identifier != sigShare.Identifier {
		t.Errorf("Expected identifier %d, got %d", sigShare.Identifier, deserializedShare.Identifier)
	}

	if !deserializedShare.SignatureShare.Equal(sigShare.SignatureShare) {
		t.Error("Deserialized signature share does not match original")
	}
}

func TestSerializer_SerializeDeserializePublicKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create test public key
	scalar, _ := grp.RandomScalar()
	pk := grp.ScalarBaseMult(scalar)

	// Serialize
	data, err := serializer.SerializePublicKey(pk)
	if err != nil {
		t.Fatalf("SerializePublicKey failed: %v", err)
	}

	// Deserialize
	deserializedPK, err := serializer.DeserializePublicKey(data)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	// Verify equality
	if !deserializedPK.Equal(pk) {
		t.Error("Deserialized public key does not match original")
	}
}

func TestSerializer_SerializeDeserializeSecretShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create test secret share
	secret, _ := grp.RandomScalar()

	// Serialize
	data, err := serializer.SerializeSecretShare(secret)
	if err != nil {
		t.Fatalf("SerializeSecretShare failed: %v", err)
	}

	// Deserialize
	deserializedSecret, err := serializer.DeserializeSecretShare(data)
	if err != nil {
		t.Fatalf("DeserializeSecretShare failed: %v", err)
	}

	// Verify equality
	if !deserializedSecret.Equal(secret) {
		t.Error("Deserialized secret share does not match original")
	}
}

func TestSerializer_InvalidData(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Test invalid header (too short)
	_, err := serializer.DeserializeSignature([]byte{0x01, 0x02})
	if err != ErrInvalidHeader {
		t.Errorf("Expected ErrInvalidHeader, got %v", err)
	}

	// Test version mismatch
	badVersionData := make([]byte, HeaderSize+100)
	badVersionData[0] = 99 // Invalid version
	_, err = serializer.DeserializeSignature(badVersionData)
	if err != ErrVersionMismatch {
		t.Errorf("Expected ErrVersionMismatch, got %v", err)
	}
}

func TestSerializer_DataTypeMismatch(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create and serialize a public key
	scalar, _ := grp.RandomScalar()
	pk := grp.ScalarBaseMult(scalar)
	data, err := serializer.SerializePublicKey(pk)
	if err != nil {
		t.Fatalf("SerializePublicKey failed: %v", err)
	}

	// Try to deserialize as signature (wrong type)
	_, err = serializer.DeserializeSignature(data)
	if err != ErrDataTypeMismatch {
		t.Errorf("Expected ErrDataTypeMismatch, got %v", err)
	}
}

func TestSerializer_NilInputs(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Test nil signature components
	_, err := serializer.SerializeSignature(frost.Signature{R: nil, Z: nil})
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for nil signature, got %v", err)
	}

	// Test nil public key
	_, err = serializer.SerializePublicKey(nil)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for nil public key, got %v", err)
	}

	// Test nil secret share
	_, err = serializer.SerializeSecretShare(nil)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for nil secret share, got %v", err)
	}
}

func TestSerializer_NilCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Test nil hiding commitment
	_, err := serializer.SerializeSigningCommitments(frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  nil,
		BindingNonceCommitment: nil,
	})
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for nil commitments, got %v", err)
	}
}

func TestSerializer_NilSignatureShare(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Test nil signature share
	_, err := serializer.SerializeSignatureShare(frost.SignatureShare{
		Identifier:     1,
		SignatureShare: nil,
	})
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for nil signature share, got %v", err)
	}
}

func TestHeader_Serialize_Deserialize(t *testing.T) {
	header := NewHeader(0x12345678, DataTypeSignature)

	data := header.Serialize()
	if len(data) != HeaderSize {
		t.Errorf("Expected header size %d, got %d", HeaderSize, len(data))
	}

	deserialized, err := DeserializeHeader(data)
	if err != nil {
		t.Fatalf("DeserializeHeader failed: %v", err)
	}

	if deserialized.Version != header.Version {
		t.Errorf("Version mismatch: expected %d, got %d", header.Version, deserialized.Version)
	}

	if deserialized.CiphersuiteID != header.CiphersuiteID {
		t.Errorf("CiphersuiteID mismatch: expected %d, got %d", header.CiphersuiteID, deserialized.CiphersuiteID)
	}

	if deserialized.DataType != header.DataType {
		t.Errorf("DataType mismatch: expected %d, got %d", header.DataType, deserialized.DataType)
	}
}

func TestHeader_Validate(t *testing.T) {
	header := NewHeader(0x12345678, DataTypeSignature)

	// Valid validation
	if err := header.Validate(0x12345678, DataTypeSignature); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}

	// Wrong ciphersuite
	if err := header.Validate(0x87654321, DataTypeSignature); err != ErrCiphersuiteMismatch {
		t.Errorf("Expected ErrCiphersuiteMismatch, got %v", err)
	}

	// Wrong data type
	if err := header.Validate(0x12345678, DataTypePublicKey); err != ErrDataTypeMismatch {
		t.Errorf("Expected ErrDataTypeMismatch, got %v", err)
	}
}

func TestDataType_String(t *testing.T) {
	tests := []struct {
		dt       DataType
		expected string
	}{
		{DataTypeUnknown, "Unknown"},
		{DataTypeSigningNonces, "SigningNonces"},
		{DataTypeSigningCommitments, "SigningCommitments"},
		{DataTypeKeyPackage, "KeyPackage"},
		{DataTypeSignature, "Signature"},
		{DataTypePublicKey, "PublicKey"},
		{DataTypeSecretShare, "SecretShare"},
		{DataTypeSignatureShare, "SignatureShare"},
		{DataType(255), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.dt.String(); got != tt.expected {
			t.Errorf("DataType(%d).String() = %q, want %q", tt.dt, got, tt.expected)
		}
	}
}

func TestCiphersuiteIDFromString(t *testing.T) {
	// Same string should always produce same ID
	id1 := CiphersuiteIDFromString("FROST-RISTRETTO255-SHA512-v1")
	id2 := CiphersuiteIDFromString("FROST-RISTRETTO255-SHA512-v1")
	if id1 != id2 {
		t.Error("Same string should produce same ID")
	}

	// Different strings should produce different IDs (with high probability)
	id3 := CiphersuiteIDFromString("FROST-P256-SHA256-v1")
	if id1 == id3 {
		t.Error("Different strings should produce different IDs")
	}
}

func TestSerializer_AllCiphersuites(t *testing.T) {
	// Test with ristretto255 (main test suite)
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create and serialize a signature
	scalar, _ := grp.RandomScalar()
	r := grp.ScalarBaseMult(scalar)
	z, _ := grp.RandomScalar()

	sig := frost.Signature{R: r, Z: z}
	data, err := serializer.SerializeSignature(sig)
	if err != nil {
		t.Fatalf("SerializeSignature failed: %v", err)
	}

	// Verify we can deserialize with the same serializer
	_, err = serializer.DeserializeSignature(data)
	if err != nil {
		t.Fatalf("DeserializeSignature failed: %v", err)
	}

	// Verify we get an error with a different ciphersuite ID
	badHeader := NewHeader(0x11111111, DataTypeSignature)
	badData := make([]byte, len(data))
	copy(badData, badHeader.Serialize())
	copy(badData[HeaderSize:], data[HeaderSize:])

	_, err = serializer.DeserializeSignature(badData)
	if err != ErrCiphersuiteMismatch {
		t.Errorf("Expected ErrCiphersuiteMismatch with different ciphersuite, got %v", err)
	}
}

// Ensure the group interface import is used
var _ group.Group = nil

func TestSerializer_DeserializeSignature_InvalidLength(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Create valid header but wrong data length
	header := NewHeader(serializer.ciphersuiteID, DataTypeSignature)
	data := make([]byte, HeaderSize+10) // Wrong length
	copy(data[:HeaderSize], header.Serialize())

	_, err := serializer.DeserializeSignature(data)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for wrong data length, got %v", err)
	}
}

func TestSerializer_DeserializeSigningCommitments_InvalidLength(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Create valid header but wrong data length
	header := NewHeader(serializer.ciphersuiteID, DataTypeSigningCommitments)
	data := make([]byte, HeaderSize+10) // Wrong length
	copy(data[:HeaderSize], header.Serialize())

	_, err := serializer.DeserializeSigningCommitments(data)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for wrong data length, got %v", err)
	}
}

func TestSerializer_DeserializeSignatureShare_InvalidLength(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Create valid header but wrong data length
	header := NewHeader(serializer.ciphersuiteID, DataTypeSignatureShare)
	data := make([]byte, HeaderSize+10) // Wrong length
	copy(data[:HeaderSize], header.Serialize())

	_, err := serializer.DeserializeSignatureShare(data)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for wrong data length, got %v", err)
	}
}

func TestSerializer_DeserializePublicKey_InvalidLength(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Create valid header but wrong data length
	header := NewHeader(serializer.ciphersuiteID, DataTypePublicKey)
	data := make([]byte, HeaderSize+10) // Wrong length
	copy(data[:HeaderSize], header.Serialize())

	_, err := serializer.DeserializePublicKey(data)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for wrong data length, got %v", err)
	}
}

func TestSerializer_DeserializeSecretShare_InvalidLength(t *testing.T) {
	suite := ristretto255_sha512.New()
	serializer := NewSerializer(suite)

	// Create valid header but wrong data length
	header := NewHeader(serializer.ciphersuiteID, DataTypeSecretShare)
	data := make([]byte, HeaderSize+10) // Wrong length
	copy(data[:HeaderSize], header.Serialize())

	_, err := serializer.DeserializeSecretShare(data)
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData for wrong data length, got %v", err)
	}
}

func TestSerializer_DeserializeSigningCommitments_InvalidElementData(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create valid header with correct length but invalid element data
	header := NewHeader(serializer.ciphersuiteID, DataTypeSigningCommitments)
	elemLen := grp.ElementLength()
	dataLen := HeaderSize + 4 + elemLen*2
	data := make([]byte, dataLen)
	copy(data[:HeaderSize], header.Serialize())
	// Leave rest as zeros - invalid element representation

	_, err := serializer.DeserializeSigningCommitments(data)
	if err == nil {
		t.Error("Expected error for invalid element data")
	}
}

func TestSerializer_DeserializeSignatureShare_InvalidScalarData(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create valid header with correct length but test scalar deserialization
	header := NewHeader(serializer.ciphersuiteID, DataTypeSignatureShare)
	scalarLen := grp.ScalarLength()
	dataLen := HeaderSize + 4 + scalarLen
	data := make([]byte, dataLen)
	copy(data[:HeaderSize], header.Serialize())
	// Fill with non-zero values that form a valid scalar
	for i := HeaderSize + 4; i < len(data); i++ {
		data[i] = 0x01
	}

	// This should succeed with valid scalar bytes
	_, err := serializer.DeserializeSignatureShare(data)
	// The deserialize may or may not error depending on if scalar is valid
	// The test is to exercise the code path
	_ = err
}

func TestSerializer_DeserializePublicKey_InvalidElementData(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create valid header with correct length but invalid element data
	header := NewHeader(serializer.ciphersuiteID, DataTypePublicKey)
	elemLen := grp.ElementLength()
	dataLen := HeaderSize + elemLen
	data := make([]byte, dataLen)
	copy(data[:HeaderSize], header.Serialize())
	// Leave rest as zeros - this may be invalid for some groups

	_, err := serializer.DeserializePublicKey(data)
	if err == nil {
		t.Error("Expected error for invalid element data (all zeros)")
	}
}

func TestSerializer_DeserializeSecretShare_InvalidScalarData(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create valid header with correct length
	header := NewHeader(serializer.ciphersuiteID, DataTypeSecretShare)
	scalarLen := grp.ScalarLength()
	dataLen := HeaderSize + scalarLen
	data := make([]byte, dataLen)
	copy(data[:HeaderSize], header.Serialize())
	// Fill with ones
	for i := HeaderSize; i < len(data); i++ {
		data[i] = 0x01
	}

	// This exercises the code path
	_, _ = serializer.DeserializeSecretShare(data)
}

func TestSerializer_DeserializeSignature_InvalidScalarZ(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()
	serializer := NewSerializer(suite)

	// Create a valid signature first
	scalar, _ := grp.RandomScalar()
	r := grp.ScalarBaseMult(scalar)
	z, _ := grp.RandomScalar()
	sig := frost.Signature{R: r, Z: z}

	data, err := serializer.SerializeSignature(sig)
	if err != nil {
		t.Fatalf("SerializeSignature failed: %v", err)
	}

	// Corrupt the Z scalar portion (last scalarLen bytes)
	scalarLen := grp.ScalarLength()
	// Set to all 0xFF which is likely invalid for most scalar representations
	for i := len(data) - scalarLen; i < len(data); i++ {
		data[i] = 0xFF
	}

	// Deserialization may fail if scalar is out of range
	_, _ = serializer.DeserializeSignature(data)
}
