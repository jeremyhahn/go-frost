package ciphersuite_test

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestDefaultHooks_PreSign tests that DefaultHooks.PreSign passes through the message unchanged.
func TestDefaultHooks_PreSign(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	msg := []byte("test message")

	result, err := hooks.PreSign(msg)
	if err != nil {
		t.Fatalf("PreSign returned error: %v", err)
	}

	if string(result) != string(msg) {
		t.Errorf("PreSign should return message unchanged, got %q, want %q", result, msg)
	}
}

// TestDefaultHooks_PreAggregate tests that DefaultHooks.PreAggregate passes through values unchanged.
func TestDefaultHooks_PreAggregate(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	msg := []byte("test message")
	commitment := grp.Generator()

	resultMsg, resultCommitment, err := hooks.PreAggregate(msg, commitment)
	if err != nil {
		t.Fatalf("PreAggregate returned error: %v", err)
	}

	if string(resultMsg) != string(msg) {
		t.Errorf("PreAggregate should return message unchanged")
	}

	if !resultCommitment.Equal(commitment) {
		t.Errorf("PreAggregate should return commitment unchanged")
	}
}

// TestDefaultHooks_PreVerify tests that DefaultHooks.PreVerify passes through values unchanged.
func TestDefaultHooks_PreVerify(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	msg := []byte("test message")
	r := grp.Generator()
	z, _ := grp.RandomScalar()
	publicKey := grp.Generator()

	resultMsg, resultR, resultZ, resultPK, err := hooks.PreVerify(msg, r, z, publicKey)
	if err != nil {
		t.Fatalf("PreVerify returned error: %v", err)
	}

	if string(resultMsg) != string(msg) {
		t.Errorf("PreVerify should return message unchanged")
	}

	if !resultR.Equal(r) {
		t.Errorf("PreVerify should return R unchanged")
	}

	if !resultZ.Equal(z) {
		t.Errorf("PreVerify should return z unchanged")
	}

	if !resultPK.Equal(publicKey) {
		t.Errorf("PreVerify should return publicKey unchanged")
	}
}

// TestDefaultHooks_PostDKG tests that DefaultHooks.PostDKG passes through values unchanged.
func TestDefaultHooks_PostDKG(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secretShare)

	resultShare, resultPK, err := hooks.PostDKG(secretShare, groupPublicKey)
	if err != nil {
		t.Fatalf("PostDKG returned error: %v", err)
	}

	if !resultShare.Equal(secretShare) {
		t.Errorf("PostDKG should return secretShare unchanged")
	}

	if !resultPK.Equal(groupPublicKey) {
		t.Errorf("PostDKG should return groupPublicKey unchanged")
	}
}

// TestDefaultHooks_PostGenerate tests that DefaultHooks.PostGenerate passes through values unchanged.
func TestDefaultHooks_PostGenerate(t *testing.T) {
	hooks := ciphersuite.DefaultHooks{}
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secretShare)

	resultShare, resultPK, err := hooks.PostGenerate(secretShare, groupPublicKey)
	if err != nil {
		t.Fatalf("PostGenerate returned error: %v", err)
	}

	if !resultShare.Equal(secretShare) {
		t.Errorf("PostGenerate should return secretShare unchanged")
	}

	if !resultPK.Equal(groupPublicKey) {
		t.Errorf("PostGenerate should return groupPublicKey unchanged")
	}
}

// TestGetHooks_WithHooksImplementor tests GetHooks with a ciphersuite that implements Hooks.
func TestGetHooks_WithHooksImplementor(t *testing.T) {
	suite := ristretto255_sha512.New()

	hooks := ciphersuite.GetHooks(suite)
	if hooks == nil {
		t.Fatal("GetHooks returned nil")
	}

	// Test that it returns the actual hooks implementation
	msg := []byte("test")
	result, err := hooks.PreSign(msg)
	if err != nil {
		t.Fatalf("PreSign returned error: %v", err)
	}
	if string(result) != string(msg) {
		t.Error("PreSign should pass through message")
	}
}

// mockCiphersuiteWithoutHooks is a mock that doesn't implement Hooks
type mockCiphersuiteWithoutHooks struct{}

func (m mockCiphersuiteWithoutHooks) ID() string                                          { return "test" }
func (m mockCiphersuiteWithoutHooks) Name() string                                        { return "test" }
func (m mockCiphersuiteWithoutHooks) ContextString() string                               { return "test" }
func (m mockCiphersuiteWithoutHooks) Group() group.Group                                  { return nil }
func (m mockCiphersuiteWithoutHooks) Hash([]byte) []byte                                  { return nil }
func (m mockCiphersuiteWithoutHooks) H1([]byte) group.Scalar                              { return nil }
func (m mockCiphersuiteWithoutHooks) H2([]byte) group.Scalar                              { return nil }
func (m mockCiphersuiteWithoutHooks) H2NoContextString([]byte) group.Scalar               { return nil }
func (m mockCiphersuiteWithoutHooks) H3([]byte) group.Scalar                              { return nil }
func (m mockCiphersuiteWithoutHooks) H4([]byte) []byte                                    { return nil }
func (m mockCiphersuiteWithoutHooks) H5([]byte) []byte                                    { return nil }
func (m mockCiphersuiteWithoutHooks) HDKG([]byte) group.Scalar                            { return nil }
func (m mockCiphersuiteWithoutHooks) HID([]byte) group.Scalar                             { return nil }
func (m mockCiphersuiteWithoutHooks) HashToCurve([]byte) (group.Element, error)           { return nil, nil }
func (m mockCiphersuiteWithoutHooks) VerifySignature([]byte, []byte, group.Element) error { return nil }

// TestGetHooks_WithoutHooksImplementor tests GetHooks with a ciphersuite that doesn't implement Hooks.
func TestGetHooks_WithoutHooksImplementor(t *testing.T) {
	suite := mockCiphersuiteWithoutHooks{}

	hooks := ciphersuite.GetHooks(suite)
	if hooks == nil {
		t.Fatal("GetHooks returned nil")
	}

	// Should return DefaultHooks
	_, ok := hooks.(ciphersuite.DefaultHooks)
	if !ok {
		t.Error("GetHooks should return DefaultHooks for ciphersuites that don't implement Hooks")
	}
}
