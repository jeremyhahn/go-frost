package keystore

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
)

// TestStoredKeyPackage_NoPlaintextShareField is the structural half of the
// protected-memory guarantee: the share is held in an enclave and nowhere
// else, so no exported byte field may carry a plaintext duplicate of it.
func TestStoredKeyPackage_NoPlaintextShareField(t *testing.T) {
	typ := reflect.TypeOf(StoredKeyPackage{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Name == "SecretShare" {
			t.Fatalf("StoredKeyPackage carries a plaintext %s field of type %s; "+
				"the share must live only in SecretShareProtected", field.Name, field.Type)
		}
	}

	protected, ok := typ.FieldByName("SecretShareProtected")
	if !ok {
		t.Fatal("StoredKeyPackage has no SecretShareProtected field")
	}
	if got := protected.Tag.Get("json"); got != "-" {
		t.Errorf("SecretShareProtected json tag = %q, want %q", got, "-")
	}
}

// TestStoredKeyPackage_ToKeyPackage_MissingShare verifies the plaintext
// fallback is gone: without a protected share there is nothing to convert.
func TestStoredKeyPackage_ToKeyPackage_MissingShare(t *testing.T) {
	g := ristretto255.NewGroup()
	storedKP := &StoredKeyPackage{Identifier: 1}

	_, err := storedKP.ToKeyPackage(g)
	if !errors.Is(err, ErrMissingSecretShare) {
		t.Errorf("expected ErrMissingSecretShare, got %v", err)
	}
}

// TestStoredKeyPackage_Zeroize verifies Zeroize destroys the share and is safe
// to call repeatedly and on a nil receiver.
func TestStoredKeyPackage_Zeroize(t *testing.T) {
	g := ristretto255.NewGroup()
	keyPackages := generateTestKeyPackages(t, g, 2, 3)

	storedKP, err := FromKeyPackage("key-1", "group-1", &keyPackages[0], 2, 3, 1000)
	if err != nil {
		t.Fatalf("FromKeyPackage failed: %v", err)
	}

	storedKP.Zeroize()
	if storedKP.SecretShareProtected != nil {
		t.Error("Zeroize left the protected share in place")
	}
	storedKP.Zeroize()

	var nilKP *StoredKeyPackage
	nilKP.Zeroize()
}

// TestFromKeyPackage_InvalidKeyPackage verifies a key package with no share
// is rejected with a typed error instead of producing an empty enclave.
func TestFromKeyPackage_InvalidKeyPackage(t *testing.T) {
	tests := []struct {
		name string
		kp   *frost.KeyPackage
	}{
		{name: "nil key package", kp: nil},
		{name: "nil secret share", kp: &frost.KeyPackage{Identifier: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromKeyPackage("key-1", "group-1", tt.kp, 2, 3, 1000)
			if !errors.Is(err, ErrInvalidKeyPackage) {
				t.Errorf("expected ErrInvalidKeyPackage, got %v", err)
			}
		})
	}
}
