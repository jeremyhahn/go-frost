package security

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
)

// TestSerializeCommitment tests the SerializeCommitment helper function.
func TestSerializeCommitment(t *testing.T) {
	g := ristretto255.NewGroup()

	// Create test commitments
	hiding, _ := g.RandomScalar()
	binding, _ := g.RandomScalar()

	commitment := frost.SigningCommitments{
		HidingNonceCommitment:  g.ScalarBaseMult(hiding),
		BindingNonceCommitment: g.ScalarBaseMult(binding),
	}

	// Serialize
	data, err := SerializeCommitment(commitment)
	if err != nil {
		t.Fatalf("SerializeCommitment() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("SerializeCommitment() returned empty data")
	}

	// Expected length is hiding bytes + binding bytes
	hidingBytes := commitment.HidingNonceCommitment.Bytes()
	bindingBytes := commitment.BindingNonceCommitment.Bytes()
	expectedLen := len(hidingBytes) + len(bindingBytes)

	if len(data) != expectedLen {
		t.Errorf("SerializeCommitment() length = %d, want %d", len(data), expectedLen)
	}
}

// TestSerializeSignatureShare tests the SerializeSignatureShare helper function.
func TestSerializeSignatureShare(t *testing.T) {
	g := ristretto255.NewGroup()

	// Create test signature share
	shareScalar, _ := g.RandomScalar()

	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: shareScalar,
	}

	// Serialize
	data, err := SerializeSignatureShare(share)
	if err != nil {
		t.Fatalf("SerializeSignatureShare() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("SerializeSignatureShare() returned empty data")
	}

	// Expected length is share scalar bytes
	expectedLen := len(shareScalar.Bytes())

	if len(data) != expectedLen {
		t.Errorf("SerializeSignatureShare() length = %d, want %d", len(data), expectedLen)
	}
}
