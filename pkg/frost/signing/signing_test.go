package signing

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

func TestGenerateNonces_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	// Generate nonces
	noncePkg, err := GenerateNonces(keyPackages[0].Identifier, keyPackages[0].SecretShare, suite)
	if err != nil {
		t.Fatalf("GenerateNonces failed: %v", err)
	}

	if noncePkg == nil {
		t.Fatal("GenerateNonces returned nil")
	}

	if noncePkg.Nonces.HidingNonce == nil {
		t.Error("Hiding nonce should not be nil")
	}

	if noncePkg.Nonces.BindingNonce == nil {
		t.Error("Binding nonce should not be nil")
	}

	if noncePkg.Commitments == nil {
		t.Error("Commitments should not be nil")
	}
}

func TestSign_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	// Generate nonces for two participants
	noncePkgs := make([]*NoncePackage, 2)
	for i := 0; i < 2; i++ {
		noncePkg, err := GenerateNonces(keyPackages[i].Identifier, keyPackages[i].SecretShare, suite)
		if err != nil {
			t.Fatalf("GenerateNonces failed: %v", err)
		}
		noncePkgs[i] = noncePkg
	}

	// Build commitment map
	allCommitments := make(map[frost.Identifier]*frost.SigningCommitments)
	for i := 0; i < 2; i++ {
		allCommitments[keyPackages[i].Identifier] = noncePkgs[i].Commitments
	}

	msg := []byte("test message")

	// Sign with first participant
	share, err := Sign(msg, keyPackages[0], noncePkgs[0], allCommitments, suite)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if share == nil {
		t.Fatal("Sign returned nil")
	}

	if share.SignatureShare == nil {
		t.Error("Signature share should not be nil")
	}
}

func TestAggregate_Success(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Generate nonces for two participants
	noncePkgs := make([]*NoncePackage, 2)
	for i := 0; i < 2; i++ {
		noncePkg, err := GenerateNonces(keyPackages[i].Identifier, keyPackages[i].SecretShare, suite)
		if err != nil {
			t.Fatalf("GenerateNonces failed: %v", err)
		}
		noncePkgs[i] = noncePkg
	}

	// Build commitment map
	allCommitments := make(map[frost.Identifier]*frost.SigningCommitments)
	for i := 0; i < 2; i++ {
		allCommitments[keyPackages[i].Identifier] = noncePkgs[i].Commitments
	}

	msg := []byte("test message for aggregation")

	// Generate signature shares
	signatureShares := make(map[frost.Identifier]*SignatureShare)
	for i := 0; i < 2; i++ {
		share, err := Sign(msg, keyPackages[i], noncePkgs[i], allCommitments, suite)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		signatureShares[keyPackages[i].Identifier] = share
	}

	// Build verification shares map
	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for _, vs := range keyPackages[0].VerificationShares {
		verificationShares[vs.Identifier] = vs
	}

	// Aggregate
	signature, err := Aggregate(msg, allCommitments, signatureShares, verificationShares, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	if signature.R == nil {
		t.Error("Signature R should not be nil")
	}
	if signature.Z == nil {
		t.Error("Signature Z should not be nil")
	}

	// Verify signature
	err = VerifySignature(msg, signature, groupPublicKey, suite)
	if err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignature_Invalid(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a random public key
	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")

	// Create an invalid signature
	r := grp.Generator()
	z, _ := grp.RandomScalar()
	invalidSig := frost.Signature{R: r, Z: z}

	// Verify should fail
	err := VerifySignature(msg, invalidSig, groupPublicKey, suite)
	if err == nil {
		t.Error("VerifySignature should fail for invalid signature")
	}
}

func TestSortCommitmentList(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create unsorted commitment list
	list := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(3),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
	}

	// Sort
	sortCommitmentList(list)

	// Verify sorted
	if list[0].Identifier != 1 {
		t.Errorf("Expected first element identifier 1, got %d", list[0].Identifier)
	}
	if list[1].Identifier != 2 {
		t.Errorf("Expected second element identifier 2, got %d", list[1].Identifier)
	}
	if list[2].Identifier != 3 {
		t.Errorf("Expected third element identifier 3, got %d", list[2].Identifier)
	}
}

func TestSortCommitmentList_AlreadySorted(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create already sorted commitment list
	list := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
		{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
	}

	// Sort (should be no-op)
	sortCommitmentList(list)

	// Verify still sorted
	if list[0].Identifier != 1 {
		t.Errorf("Expected first element identifier 1, got %d", list[0].Identifier)
	}
	if list[1].Identifier != 2 {
		t.Errorf("Expected second element identifier 2, got %d", list[1].Identifier)
	}
}

func TestSortCommitmentList_Empty(t *testing.T) {
	list := frost.CommitmentList{}

	// Should not panic on empty list
	sortCommitmentList(list)

	if len(list) != 0 {
		t.Error("Empty list should remain empty")
	}
}

func TestSortCommitmentList_Single(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	list := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.Generator(),
			BindingNonceCommitment: grp.Generator(),
		},
	}

	// Should not panic on single element
	sortCommitmentList(list)

	if list[0].Identifier != 1 {
		t.Errorf("Expected identifier 1, got %d", list[0].Identifier)
	}
}
