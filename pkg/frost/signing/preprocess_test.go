package signing

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

func TestPreprocess_GeneratesCorrectCount(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate a secret share
	secretShare, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate secret share: %v", err)
	}

	identifier := frost.Identifier(1)
	count := 10

	// Preprocess nonces
	preprocessed, err := Preprocess(count, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	// Verify count
	if len(preprocessed.Nonces) != count {
		t.Errorf("Expected %d nonces, got %d", count, len(preprocessed.Nonces))
	}

	if len(preprocessed.Commitments) != count {
		t.Errorf("Expected %d commitments, got %d", count, len(preprocessed.Commitments))
	}
}

func TestPreprocess_NoncesAreUnique(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(1)

	preprocessed, err := Preprocess(5, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	// Check that all hiding nonces are unique
	seenHiding := make(map[string]bool)
	seenBinding := make(map[string]bool)

	for i, nonce := range preprocessed.Nonces {
		hidingBytes := string(nonce.HidingNonce.Bytes())
		bindingBytes := string(nonce.BindingNonce.Bytes())

		if seenHiding[hidingBytes] {
			t.Errorf("Duplicate hiding nonce at index %d", i)
		}
		if seenBinding[bindingBytes] {
			t.Errorf("Duplicate binding nonce at index %d", i)
		}

		seenHiding[hidingBytes] = true
		seenBinding[bindingBytes] = true
	}
}

func TestPreprocess_CommitmentsMatchNonces(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(42)

	preprocessed, err := Preprocess(3, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	for i, nonce := range preprocessed.Nonces {
		commitment := preprocessed.Commitments[i]

		// Verify hiding commitment
		expectedHiding := grp.ScalarBaseMult(nonce.HidingNonce)
		if !commitment.HidingNonceCommitment.Equal(expectedHiding) {
			t.Errorf("Hiding commitment mismatch at index %d", i)
		}

		// Verify binding commitment
		expectedBinding := grp.ScalarBaseMult(nonce.BindingNonce)
		if !commitment.BindingNonceCommitment.Equal(expectedBinding) {
			t.Errorf("Binding commitment mismatch at index %d", i)
		}

		// Verify identifier
		if commitment.Identifier != identifier {
			t.Errorf("Identifier mismatch at index %d: expected %d, got %d",
				i, identifier, commitment.Identifier)
		}
	}
}

func TestPreprocess_InvalidCount(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(1)

	// Zero count
	_, err := Preprocess(0, identifier, secretShare, suite)
	if err == nil {
		t.Error("Expected error for zero count")
	}

	// Negative count
	_, err = Preprocess(-1, identifier, secretShare, suite)
	if err == nil {
		t.Error("Expected error for negative count")
	}
}

func TestPreprocess_InvalidIdentifier(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()

	// Zero identifier
	_, err := Preprocess(5, frost.Identifier(0), secretShare, suite)
	if err == nil {
		t.Error("Expected error for zero identifier")
	}
}

func TestPreprocess_NilSecretShare(t *testing.T) {
	suite := ristretto255_sha512.New()

	_, err := Preprocess(5, frost.Identifier(1), nil, suite)
	if err == nil {
		t.Error("Expected error for nil secret share")
	}
}

func TestPreprocessDeterministic_SameSeedSameOutput(t *testing.T) {
	suite := ristretto255_sha512.New()

	identifier := frost.Identifier(1)
	seed := []byte("deterministic seed for testing")
	count := 5

	// Generate twice with same seed
	preprocessed1, err := PreprocessDeterministic(count, identifier, seed, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	preprocessed2, err := PreprocessDeterministic(count, identifier, seed, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	// Verify outputs are identical
	for i := 0; i < count; i++ {
		if !preprocessed1.Nonces[i].HidingNonce.Equal(preprocessed2.Nonces[i].HidingNonce) {
			t.Errorf("Hiding nonces differ at index %d", i)
		}
		if !preprocessed1.Nonces[i].BindingNonce.Equal(preprocessed2.Nonces[i].BindingNonce) {
			t.Errorf("Binding nonces differ at index %d", i)
		}
	}
}

func TestPreprocessDeterministic_DifferentSeedDifferentOutput(t *testing.T) {
	suite := ristretto255_sha512.New()

	identifier := frost.Identifier(1)
	seed1 := []byte("seed one")
	seed2 := []byte("seed two")

	preprocessed1, err := PreprocessDeterministic(3, identifier, seed1, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	preprocessed2, err := PreprocessDeterministic(3, identifier, seed2, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	// Verify outputs are different
	allSame := true
	for i := 0; i < 3; i++ {
		if !preprocessed1.Nonces[i].HidingNonce.Equal(preprocessed2.Nonces[i].HidingNonce) {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Different seeds should produce different nonces")
	}
}

func TestPreprocessDeterministic_DifferentIdentifierSameNonces(t *testing.T) {
	suite := ristretto255_sha512.New()

	seed := []byte("same seed")

	preprocessed1, err := PreprocessDeterministic(3, frost.Identifier(1), seed, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	preprocessed2, err := PreprocessDeterministic(3, frost.Identifier(2), seed, suite)
	if err != nil {
		t.Fatalf("PreprocessDeterministic failed: %v", err)
	}

	// The nonces should be the same since only seed is used for derivation
	// The identifier is only used in the commitment struct, not nonce derivation
	for i := 0; i < 3; i++ {
		if !preprocessed1.Nonces[i].HidingNonce.Equal(preprocessed2.Nonces[i].HidingNonce) {
			t.Errorf("Nonces should be same for same seed regardless of identifier at index %d", i)
		}
	}

	// But the commitments should have different identifiers
	if preprocessed1.Commitments[0].Identifier == preprocessed2.Commitments[0].Identifier {
		t.Error("Commitments should have different identifiers")
	}
}

func TestPreprocessDeterministic_InvalidInputs(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Zero count
	_, err := PreprocessDeterministic(0, frost.Identifier(1), []byte("seed"), suite)
	if err == nil {
		t.Error("Expected error for zero count")
	}

	// Zero identifier
	_, err = PreprocessDeterministic(5, frost.Identifier(0), []byte("seed"), suite)
	if err == nil {
		t.Error("Expected error for zero identifier")
	}

	// Empty seed
	_, err = PreprocessDeterministic(5, frost.Identifier(1), []byte{}, suite)
	if err == nil {
		t.Error("Expected error for empty seed")
	}

	// Nil seed
	_, err = PreprocessDeterministic(5, frost.Identifier(1), nil, suite)
	if err == nil {
		t.Error("Expected error for nil seed")
	}
}

func TestPreprocessedNonces_Next(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(1)

	preprocessed, err := Preprocess(5, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	initialLen := preprocessed.Len()

	// Next should return and remove the first nonce/commitment pair
	nonce, commitment, ok := preprocessed.Next()
	if !ok {
		t.Fatal("Next failed")
	}

	// Verify length decreased
	if preprocessed.Len() != initialLen-1 {
		t.Errorf("Expected %d nonces after Next, got %d", initialLen-1, preprocessed.Len())
	}

	// Verify returned values are valid
	if nonce.HidingNonce == nil || nonce.BindingNonce == nil {
		t.Error("Next nonce has nil values")
	}

	if commitment.HidingNonceCommitment == nil || commitment.BindingNonceCommitment == nil {
		t.Error("Next commitment has nil values")
	}
}

func TestPreprocessedNonces_Next_Empty(t *testing.T) {
	preprocessed := &PreprocessedNonces{
		Nonces:      []frost.SigningNonces{},
		Commitments: []frost.SigningCommitments{},
	}

	_, _, ok := preprocessed.Next()
	if ok {
		t.Error("Expected ok=false when calling Next on empty preprocessed nonces")
	}
}

func TestPreprocessedNonces_Len(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(1)

	preprocessed, err := Preprocess(10, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	if preprocessed.Len() != 10 {
		t.Errorf("Expected 10 remaining, got %d", preprocessed.Len())
	}

	preprocessed.Next()
	preprocessed.Next()

	if preprocessed.Len() != 8 {
		t.Errorf("Expected 8 remaining, got %d", preprocessed.Len())
	}
}

func TestPreprocessedNonces_Zeroize(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secretShare, _ := grp.RandomScalar()
	identifier := frost.Identifier(1)

	preprocessed, err := Preprocess(3, identifier, secretShare, suite)
	if err != nil {
		t.Fatalf("Preprocess failed: %v", err)
	}

	// Store original byte values
	originalNonces := make([][]byte, len(preprocessed.Nonces))
	for i, nonce := range preprocessed.Nonces {
		originalNonces[i] = make([]byte, len(nonce.HidingNonce.Bytes()))
		copy(originalNonces[i], nonce.HidingNonce.Bytes())
	}

	// Zeroize
	preprocessed.Zeroize()

	// Verify all nonces are zeroed
	for i, nonce := range preprocessed.Nonces {
		if !nonce.HidingNonce.IsZero() {
			t.Errorf("Hiding nonce %d should be zero after Zeroize()", i)
		}
		if !nonce.BindingNonce.IsZero() {
			t.Errorf("Binding nonce %d should be zero after Zeroize()", i)
		}
	}
}
