package signing

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

func TestCheaterDetectionStrategy_Constants(t *testing.T) {
	// Verify the strategy constants exist
	if CheaterDetectionDisabled != 0 {
		t.Error("CheaterDetectionDisabled should be 0")
	}
	if CheaterDetectionFirstCheater != 1 {
		t.Error("CheaterDetectionFirstCheater should be 1")
	}
	if CheaterDetectionAllCheaters != 2 {
		t.Error("CheaterDetectionAllCheaters should be 2")
	}
}

func TestCheaterDetectionStrategy_String(t *testing.T) {
	tests := []struct {
		strategy CheaterDetectionStrategy
		expected string
	}{
		{CheaterDetectionDisabled, "Disabled"},
		{CheaterDetectionFirstCheater, "FirstCheater"},
		{CheaterDetectionAllCheaters, "AllCheaters"},
		{CheaterDetectionStrategy(99), "Unknown"},
	}

	for _, tt := range tests {
		result := tt.strategy.String()
		if result != tt.expected {
			t.Errorf("String() for %d: expected %q, got %q", tt.strategy, tt.expected, result)
		}
	}
}

func TestAggregateWithStrategy_DisabledStrategy(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message")

	// Round 2
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Aggregate with disabled strategy (no verification of shares)
	signature, err := AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionDisabled,
		suite,
		2,
	)
	if err != nil {
		t.Fatalf("AggregateWithStrategy failed: %v", err)
	}

	// Verify the signature
	agg := NewAggregator(suite, 2)
	err = agg.Verify(msg, signature, groupPublicKey)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestAggregateWithStrategy_InvalidShare_FirstCheater(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message")

	// Round 2 - but corrupt the first participant's share
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Corrupt first share
	badScalar, _ := grp.RandomScalar()
	signatureShares[0].SignatureShare = badScalar

	// Aggregate with FirstCheater strategy
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionFirstCheater,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for invalid share")
	}

	// Check that culprits can be extracted
	culprits := frost.GetCulprits(err)
	if len(culprits) != 1 {
		t.Errorf("Expected 1 culprit, got %d", len(culprits))
	}

	if culprits[0] != keyPackages[0].Identifier {
		t.Errorf("Expected culprit %d, got %d", keyPackages[0].Identifier, culprits[0])
	}
}

func TestAggregateWithStrategy_InvalidShare_AllCheaters(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message")

	// Round 2 - corrupt both participants' shares
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Corrupt both shares
	badScalar1, _ := grp.RandomScalar()
	badScalar2, _ := grp.RandomScalar()
	signatureShares[0].SignatureShare = badScalar1
	signatureShares[1].SignatureShare = badScalar2

	// Aggregate with AllCheaters strategy
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for invalid shares")
	}

	// Check that both culprits are identified
	culprits := frost.GetCulprits(err)
	if len(culprits) != 2 {
		t.Errorf("Expected 2 culprits, got %d", len(culprits))
	}
}

func TestSignatureShareError_Culprits(t *testing.T) {
	culprits := []frost.Identifier{1, 2, 3}

	err := frost.NewSignatureShareError(culprits, "test reason", frost.ErrInvalidSignatureShare)

	extractedCulprits := err.Culprits()
	if len(extractedCulprits) != 3 {
		t.Errorf("Expected 3 culprits, got %d", len(extractedCulprits))
	}

	for i, c := range extractedCulprits {
		if c != culprits[i] {
			t.Errorf("Culprit %d mismatch: expected %d, got %d", i, culprits[i], c)
		}
	}
}

func TestGetCulprits_NonCulpritError(t *testing.T) {
	// Test with a regular error that doesn't implement CulpritError
	regularErr := errors.New("regular error")
	culprits := frost.GetCulprits(regularErr)

	if culprits != nil {
		t.Error("GetCulprits should return nil for non-CulpritError")
	}
}

func TestGetCulprits_NilError(t *testing.T) {
	culprits := frost.GetCulprits(nil)
	if culprits != nil {
		t.Error("GetCulprits should return nil for nil error")
	}
}

func TestProofOfKnowledgeError_Culprits(t *testing.T) {
	identifier := frost.Identifier(42)
	err := frost.NewProofOfKnowledgeError(identifier, "invalid proof", frost.ErrInvalidParameters)

	culprits := err.Culprits()
	if len(culprits) != 1 {
		t.Errorf("Expected 1 culprit, got %d", len(culprits))
	}

	if culprits[0] != identifier {
		t.Errorf("Expected culprit %d, got %d", identifier, culprits[0])
	}
}

func TestSecretShareError_Culprits(t *testing.T) {
	identifier := frost.Identifier(99)
	err := frost.NewSecretShareError(identifier, "invalid share", frost.ErrInvalidKeyShare)

	culprits := err.Culprits()
	if len(culprits) != 1 {
		t.Errorf("Expected 1 culprit, got %d", len(culprits))
	}

	if culprits[0] != identifier {
		t.Errorf("Expected culprit %d, got %d", identifier, culprits[0])
	}
}

func TestErrorMessages(t *testing.T) {
	// Test SignatureShareError message
	ssErr := frost.NewSignatureShareError([]frost.Identifier{1, 2}, "test reason", nil)
	if ssErr.Error() == "" {
		t.Error("SignatureShareError should have an error message")
	}

	// Test ProofOfKnowledgeError message
	pokErr := frost.NewProofOfKnowledgeError(1, "invalid proof", nil)
	if pokErr.Error() == "" {
		t.Error("ProofOfKnowledgeError should have an error message")
	}

	// Test SecretShareError message
	secErr := frost.NewSecretShareError(1, "invalid share", nil)
	if secErr.Error() == "" {
		t.Error("SecretShareError should have an error message")
	}
}

func TestErrorUnwrap(t *testing.T) {
	wrappedErr := frost.ErrInvalidSignatureShare

	ssErr := frost.NewSignatureShareError([]frost.Identifier{1}, "test", wrappedErr)

	// Check that Unwrap returns the wrapped error
	if !errors.Is(ssErr, wrappedErr) {
		t.Error("SignatureShareError should wrap the underlying error")
	}
}

func TestSignatureShareError_AddCulprit(t *testing.T) {
	err := frost.NewSignatureShareError([]frost.Identifier{1}, "test", nil)

	// Add another culprit
	err = err.AddCulprit(2)

	culprits := err.Culprits()
	if len(culprits) != 2 {
		t.Errorf("Expected 2 culprits after AddCulprit, got %d", len(culprits))
	}
}

func TestParticipantError_Culprits(t *testing.T) {
	err := frost.NewParticipantError(42, "test error", nil)

	culprits := err.Culprits()
	if len(culprits) != 1 {
		t.Errorf("Expected 1 culprit, got %d", len(culprits))
	}

	if culprits[0] != 42 {
		t.Errorf("Expected culprit 42, got %d", culprits[0])
	}
}

func TestAggregateWithStrategy_UnknownStrategy(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate minimal test data
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	commitmentList := make(frost.CommitmentList, 2)
	signatureShares := make([]frost.SignatureShare, 2)

	// Create minimal commitments
	for i := 0; i < 2; i++ {
		hidingNonce, _ := grp.RandomScalar()
		bindingNonce, _ := grp.RandomScalar()
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		}
		share, _ := grp.RandomScalar()
		signatureShares[i] = frost.SignatureShare{
			Identifier:     frost.Identifier(i + 1),
			SignatureShare: share,
		}
	}

	// Test with unknown strategy value
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		[]byte("test"),
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionStrategy(99), // Unknown strategy
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for unknown strategy")
	}
}

func TestAggregateWithStrategy_AllCheaters_NilGroupPublicKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate minimal test data
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	commitmentList := make(frost.CommitmentList, 2)
	signatureShares := make([]frost.SignatureShare, 2)

	for i := 0; i < 2; i++ {
		hidingNonce, _ := grp.RandomScalar()
		bindingNonce, _ := grp.RandomScalar()
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		}
		share, _ := grp.RandomScalar()
		signatureShares[i] = frost.SignatureShare{
			Identifier:     frost.Identifier(i + 1),
			SignatureShare: share,
		}
	}

	// Test with nil group public key
	_, err = AggregateWithStrategy(
		nil, // nil group public key
		commitmentList,
		[]byte("test"),
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for nil group public key")
	}
}

func TestAggregateWithStrategy_AllCheaters_EmptyVerificationShares(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate minimal test data
	identifiers := []frost.Identifier{1, 2, 3}
	_, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	commitmentList := make(frost.CommitmentList, 2)
	signatureShares := make([]frost.SignatureShare, 2)

	for i := 0; i < 2; i++ {
		hidingNonce, _ := grp.RandomScalar()
		bindingNonce, _ := grp.RandomScalar()
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		}
		share, _ := grp.RandomScalar()
		signatureShares[i] = frost.SignatureShare{
			Identifier:     frost.Identifier(i + 1),
			SignatureShare: share,
		}
	}

	// Test with empty verification shares
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		[]byte("test"),
		signatureShares,
		[]frost.VerificationShare{}, // empty
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for empty verification shares")
	}
}

func TestAggregateWithStrategy_AllCheaters_InsufficientSignatureShares(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate minimal test data
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	commitmentList := make(frost.CommitmentList, 1)    // Only 1 commitment
	signatureShares := make([]frost.SignatureShare, 1) // Only 1 share

	hidingNonce, _ := grp.RandomScalar()
	bindingNonce, _ := grp.RandomScalar()
	commitmentList[0] = frost.SigningCommitments{
		Identifier:             frost.Identifier(1),
		HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
	}
	share, _ := grp.RandomScalar()
	signatureShares[0] = frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: share,
	}

	// Test with insufficient signature shares (need 2, have 1)
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		[]byte("test"),
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2, // minSigners = 2
	)

	if err == nil {
		t.Fatal("Expected error for insufficient signature shares")
	}
}

func TestAggregateWithStrategy_AllCheaters_MissingVerificationKey(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message")

	// Round 2
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Create verification shares with missing key for participant 1
	incompleteVerificationShares := []frost.VerificationShare{
		keyPackages[0].VerificationShares[1], // Only participant 2's verification share
		keyPackages[0].VerificationShares[2], // participant 3
	}

	// Test with missing verification key - should identify culprit
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		incompleteVerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for missing verification key")
	}

	// Should identify the participant with missing verification key as culprit
	culprits := frost.GetCulprits(err)
	if len(culprits) == 0 {
		t.Error("Expected at least one culprit for missing verification key")
	}
}

func TestAggregateWithStrategy_AllCheaters_ValidSignatures(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message for all cheaters strategy")

	// Round 2
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Test with all valid signatures using AllCheaters strategy
	signature, err := AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err != nil {
		t.Fatalf("AggregateWithStrategy with AllCheaters failed: %v", err)
	}

	// Verify the signature
	agg := NewAggregator(suite, 2)
	err = agg.Verify(msg, signature, groupPublicKey)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestAggregateWithStrategy_AllCheaters_MissingBindingFactor(t *testing.T) {
	suite := ristretto255_sha512.New()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create participants
	participants := make([]Participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite)
	}

	// Round 1
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed: %v", err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	msg := []byte("test message")

	// Round 2
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed: %v", err)
		}
		signatureShares[i] = share
	}

	// Create a signature share with an identifier that is NOT in the commitment list
	// This will cause a missing binding factor lookup failure
	signatureShares[0].Identifier = frost.Identifier(999) // Not in commitment list

	// Test should identify culprit for missing binding factor
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		msg,
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for missing binding factor")
	}

	// Should identify the participant with missing binding factor as culprit
	culprits := frost.GetCulprits(err)
	if len(culprits) == 0 {
		t.Error("Expected at least one culprit for missing binding factor")
	}
}

func TestAggregateWithStrategy_AllCheaters_MissingCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create commitment list for identifiers 1 and 2
	commitmentList := make(frost.CommitmentList, 2)
	for i := 0; i < 2; i++ {
		hidingNonce, _ := grp.RandomScalar()
		bindingNonce, _ := grp.RandomScalar()
		commitmentList[i] = frost.SigningCommitments{
			Identifier:             frost.Identifier(i + 1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		}
	}

	// Create signature shares but one has identifier that IS in verification shares
	// but NOT in commitment list
	signatureShares := make([]frost.SignatureShare, 2)
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()
	signatureShares[0] = frost.SignatureShare{
		Identifier:     frost.Identifier(1), // In commitment list
		SignatureShare: share1,
	}
	signatureShares[1] = frost.SignatureShare{
		Identifier:     frost.Identifier(3), // NOT in commitment list (only 1,2)
		SignatureShare: share2,
	}

	// Test should identify culprit for missing commitment
	_, err = AggregateWithStrategy(
		groupPublicKey,
		commitmentList,
		[]byte("test"),
		signatureShares,
		keyPackages[0].VerificationShares,
		CheaterDetectionAllCheaters,
		suite,
		2,
	)

	if err == nil {
		t.Fatal("Expected error for missing commitment")
	}

	// Should identify the participant with missing commitment as culprit
	culprits := frost.GetCulprits(err)
	if len(culprits) == 0 {
		t.Error("Expected at least one culprit for missing commitment")
	}
}
