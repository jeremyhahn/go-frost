package signing

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

func TestNewSigningPackage_Empty(t *testing.T) {
	_, err := NewSigningPackage([]byte("msg"), frost.CommitmentList{}, nil)
	if err == nil {
		t.Error("Expected error for empty commitment list")
	}
}

func TestNewSigningPackage_Unsorted(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	_, err := NewSigningPackage([]byte("msg"), commitments, nil)
	if err == nil {
		t.Error("Expected error for unsorted commitment list")
	}
}

func TestNewSigningPackage_DuplicateIdentifiers(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	_, err := NewSigningPackage([]byte("msg"), commitments, nil)
	if err == nil {
		t.Error("Expected error for duplicate identifiers")
	}
}

func TestNewSigningPackage_Success(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	msg := []byte("test message")
	pkg, err := NewSigningPackage(msg, commitments, grp.Generator())
	if err != nil {
		t.Fatalf("NewSigningPackage failed: %v", err)
	}

	if string(pkg.Message) != string(msg) {
		t.Error("Message mismatch")
	}
}

func TestSigningPackage_GetCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	pkg, _ := NewSigningPackage([]byte("msg"), commitments, nil)

	// Get existing commitment
	c := pkg.GetCommitment(1)
	if c == nil {
		t.Fatal("GetCommitment returned nil for existing participant")
	}
	if c.Identifier != 1 {
		t.Errorf("Expected identifier 1, got %d", c.Identifier)
	}

	// Get non-existing commitment
	c = pkg.GetCommitment(99)
	if c != nil {
		t.Error("GetCommitment should return nil for non-existing participant")
	}
}

func TestSigningPackage_GetParticipants(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 3, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	pkg, _ := NewSigningPackage([]byte("msg"), commitments, nil)

	participants := pkg.GetParticipants()
	if len(participants) != 3 {
		t.Errorf("Expected 3 participants, got %d", len(participants))
	}

	for i, p := range participants {
		expected := frost.Identifier(i + 1)
		if p != expected {
			t.Errorf("Expected participant %d at index %d, got %d", expected, i, p)
		}
	}
}

func TestSigningPackage_ContainsParticipant(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	pkg, _ := NewSigningPackage([]byte("msg"), commitments, nil)

	if !pkg.ContainsParticipant(1) {
		t.Error("ContainsParticipant should return true for participant 1")
	}

	if !pkg.ContainsParticipant(2) {
		t.Error("ContainsParticipant should return true for participant 2")
	}

	if pkg.ContainsParticipant(99) {
		t.Error("ContainsParticipant should return false for non-existing participant")
	}
}

func TestSigningPackage_Len(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	commitments := frost.CommitmentList{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	pkg, _ := NewSigningPackage([]byte("msg"), commitments, nil)

	if pkg.Len() != 2 {
		t.Errorf("Expected Len() = 2, got %d", pkg.Len())
	}
}

func TestSigningPackageBuilder_Basic(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	builder := NewSigningPackageBuilder()

	msg := []byte("test message")
	pubKey := grp.Generator()

	pkg, err := builder.
		WithMessage(msg).
		WithGroupPublicKey(pubKey).
		AddCommitment(frost.SigningCommitments{
			Identifier:             1,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		AddCommitment(frost.SigningCommitments{
			Identifier:             2,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if string(pkg.Message) != string(msg) {
		t.Error("Message mismatch")
	}

	if pkg.Len() != 2 {
		t.Errorf("Expected 2 commitments, got %d", pkg.Len())
	}
}

func TestSigningPackageBuilder_EmptyCommitments(t *testing.T) {
	builder := NewSigningPackageBuilder()

	_, err := builder.WithMessage([]byte("msg")).Build()
	if err == nil {
		t.Error("Expected error for empty commitments")
	}
}

func TestSigningPackageBuilder_DuplicateIdentifiers(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	builder := NewSigningPackageBuilder()

	_, err := builder.
		WithMessage([]byte("msg")).
		AddCommitment(frost.SigningCommitments{
			Identifier:             1,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		AddCommitment(frost.SigningCommitments{
			Identifier:             1,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		Build()

	if err == nil {
		t.Error("Expected error for duplicate identifiers")
	}
}

func TestSigningPackageBuilder_AddCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	builder := NewSigningPackageBuilder()

	commitments := []frost.SigningCommitments{
		{Identifier: 1, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 2, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
		{Identifier: 3, HidingNonceCommitment: grp.Generator(), BindingNonceCommitment: grp.Generator()},
	}

	pkg, err := builder.
		WithMessage([]byte("msg")).
		AddCommitments(commitments).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if pkg.Len() != 3 {
		t.Errorf("Expected 3 commitments, got %d", pkg.Len())
	}
}

func TestSigningPackageBuilder_Sorts(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	builder := NewSigningPackageBuilder()

	// Add out of order
	pkg, err := builder.
		WithMessage([]byte("msg")).
		AddCommitment(frost.SigningCommitments{
			Identifier:             3,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		AddCommitment(frost.SigningCommitments{
			Identifier:             1,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		AddCommitment(frost.SigningCommitments{
			Identifier:             2,
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify sorted
	participants := pkg.GetParticipants()
	for i := 0; i < len(participants)-1; i++ {
		if participants[i] >= participants[i+1] {
			t.Error("Commitments should be sorted by identifier")
		}
	}
}
