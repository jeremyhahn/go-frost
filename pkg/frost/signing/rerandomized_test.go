package signing

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
)

func TestNewRandomizedParams_Success(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a group public key
	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	// Create a randomizer
	randomizer, _ := grp.RandomScalar()

	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Verify params are set
	if params.Randomizer == nil {
		t.Error("Randomizer should not be nil")
	}

	if params.RandomizedVerifyingKey == nil {
		t.Error("RandomizedVerifyingKey should not be nil")
	}

	// Verify randomized public key is different from original
	if params.RandomizedVerifyingKey.Equal(groupPublicKey) {
		t.Error("RandomizedVerifyingKey should be different from original")
	}

	// Verify randomized public key is not identity
	if params.RandomizedVerifyingKey.IsIdentity() {
		t.Error("RandomizedVerifyingKey should not be identity")
	}
}

func TestNewRandomizedParams_NilPublicKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	randomizer, _ := grp.RandomScalar()

	_, err := NewRandomizedParams(randomizer, nil, suite)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

func TestNewRandomizedParams_NilRandomizer(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	_, err := NewRandomizedParams(nil, groupPublicKey, suite)
	if err == nil {
		t.Error("Expected error for nil randomizer")
	}
}

func TestComputeRandomizer_Deterministic(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")
	randomness, _ := grp.RandomScalar()

	// Create commitment list
	hidingNonce, _ := grp.RandomScalar()
	bindingNonce, _ := grp.RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		},
	}

	// Compute twice with same inputs
	params1, err := ComputeRandomizer(msg, commitmentList, randomness, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("ComputeRandomizer failed: %v", err)
	}

	params2, err := ComputeRandomizer(msg, commitmentList, randomness, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("ComputeRandomizer failed: %v", err)
	}

	// Verify outputs are identical
	if !params1.Randomizer.Equal(params2.Randomizer) {
		t.Error("Randomizers should be identical for same inputs")
	}

	if !params1.RandomizedVerifyingKey.Equal(params2.RandomizedVerifyingKey) {
		t.Error("RandomizedVerifyingKeys should be identical for same inputs")
	}
}

func TestComputeRandomizer_DifferentInputs(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg1 := []byte("message one")
	msg2 := []byte("message two")
	randomness, _ := grp.RandomScalar()

	// Create commitment list
	hidingNonce, _ := grp.RandomScalar()
	bindingNonce, _ := grp.RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		},
	}

	params1, _ := ComputeRandomizer(msg1, commitmentList, randomness, groupPublicKey, suite)
	params2, _ := ComputeRandomizer(msg2, commitmentList, randomness, groupPublicKey, suite)

	// Different messages should produce different randomizers
	if params1.Randomizer.Equal(params2.Randomizer) {
		t.Error("Different messages should produce different randomizers")
	}
}

func TestComputeRandomizer_NilPublicKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	randomness, _ := grp.RandomScalar()
	commitmentList := frost.CommitmentList{}

	_, err := ComputeRandomizer([]byte("msg"), commitmentList, randomness, nil, suite)
	if err == nil {
		t.Error("Expected error for nil public key")
	}
}

func TestRerandomizedParticipant_RoundOne(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate key packages
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Compute randomizer
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Create rerandomized participant
	rerandParticipant := NewRerandomizedParticipant(*keyPackages[0], params, suite)

	// Round one
	nonces, commitments, err := rerandParticipant.RoundOne()
	if err != nil {
		t.Fatalf("RoundOne failed: %v", err)
	}

	// Verify nonces and commitments are valid
	if nonces.HidingNonce == nil || nonces.BindingNonce == nil {
		t.Error("Nonces should not be nil")
	}

	if commitments.HidingNonceCommitment == nil || commitments.BindingNonceCommitment == nil {
		t.Error("Commitments should not be nil")
	}

	// Verify commitments match nonces
	expectedHiding := grp.ScalarBaseMult(nonces.HidingNonce)
	if !expectedHiding.Equal(commitments.HidingNonceCommitment) {
		t.Error("Hiding commitment doesn't match nonce")
	}
}

func TestRerandomizedSigningWorkflow(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	msg := []byte("test message for rerandomized signing")

	// Compute randomizer (same for all participants)
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Create rerandomized participants (use first 2 of 3)
	participants := make([]*RerandomizedParticipant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewRerandomizedParticipant(*keyPackages[i], params, suite)
	}

	// Round 1: Generate nonces and commitments
	noncesList := make([]frost.SigningNonces, 2)
	commitmentList := make(frost.CommitmentList, 2)

	for i, p := range participants {
		nonces, commitments, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed for participant %d: %v", i, err)
		}
		noncesList[i] = nonces
		commitmentList[i] = commitments
	}

	// Round 2: Generate signature shares
	signatureShares := make([]frost.SignatureShare, 2)
	for i, p := range participants {
		share, err := p.RoundTwo(noncesList[i], msg, commitmentList)
		if err != nil {
			t.Fatalf("RoundTwo failed for participant %d: %v", i, err)
		}
		signatureShares[i] = share
	}

	// Build verification shares for aggregation
	verificationShares := make([]frost.VerificationShare, 2)
	for i := 0; i < 2; i++ {
		for _, vs := range keyPackages[i].VerificationShares {
			if vs.Identifier == keyPackages[i].Identifier {
				verificationShares[i] = vs
				break
			}
		}
	}

	// Aggregate
	aggregator := NewRerandomizedAggregator(suite, 2, params)
	signature, err := aggregator.Aggregate(commitmentList, msg, signatureShares, verificationShares)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// Verify signature structure is valid
	if signature.R == nil {
		t.Error("Signature R should not be nil")
	}
	if signature.Z == nil {
		t.Error("Signature Z should not be nil")
	}

	// Verify the randomized public key is different from original
	randomizedPK := aggregator.GetRandomizedPublicKey()
	if randomizedPK.Equal(groupPublicKey) {
		t.Error("Randomized public key should be different from original")
	}

	if !randomizedPK.Equal(params.RandomizedVerifyingKey) {
		t.Error("GetRandomizedPublicKey should return the params' randomized public key")
	}

	// Verify the signature against the randomized public key
	err = aggregator.Verify(msg, signature)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestRerandomizedSignature_UnlinkableToOriginalKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	_, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Create two different randomizers
	randomizer1, _ := grp.RandomScalar()
	randomizer2, _ := grp.RandomScalar()

	// Compute two different randomized params
	params1, _ := NewRandomizedParams(randomizer1, groupPublicKey, suite)
	params2, _ := NewRandomizedParams(randomizer2, groupPublicKey, suite)

	// Verify the two randomized public keys are different
	if params1.RandomizedVerifyingKey.Equal(params2.RandomizedVerifyingKey) {
		t.Error("Different randomizers should produce different randomized public keys")
	}

	// This demonstrates unlinkability: signatures made with different randomizers
	// will verify against different public keys, making it impossible to link
	// them back to the same original group public key without knowing the randomizer
}

func TestRerandomizedAggregator_GetRandomizedPublicKey(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	randomizer, _ := grp.RandomScalar()
	params, _ := NewRandomizedParams(randomizer, groupPublicKey, suite)

	aggregator := NewRerandomizedAggregator(suite, 2, params)

	rpk := aggregator.GetRandomizedPublicKey()
	if !rpk.Equal(params.RandomizedVerifyingKey) {
		t.Error("GetRandomizedPublicKey should return the correct randomized public key")
	}
}

func TestRerandomizedAggregator_Verify(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate a valid rerandomized signature
	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")
	randomizer, _ := grp.RandomScalar()

	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	aggregator := NewRerandomizedAggregator(suite, 2, params)

	// Create a simple valid Schnorr signature against the randomized public key
	k, _ := grp.RandomScalar()
	r := grp.ScalarBaseMult(k)

	// Derive a secret key for the randomized public key
	// This is just for testing - in practice the signature comes from FROST
	randomizedSecret := secret.Add(params.Randomizer)

	// Compute challenge
	rBytes, _ := grp.SerializeElement(r)
	pkBytes, _ := grp.SerializeElement(params.RandomizedVerifyingKey)
	challengeInput := append(rBytes, pkBytes...)
	challengeInput = append(challengeInput, msg...)
	challenge := suite.H2(challengeInput)

	// Compute response: z = k + challenge * randomizedSecret
	z := k.Add(challenge.Mul(randomizedSecret))

	sig := frost.Signature{
		R: r,
		Z: z,
	}

	// Verify using the aggregator's Verify method
	err = aggregator.Verify(msg, sig)
	if err != nil {
		t.Errorf("Verify failed for valid signature: %v", err)
	}

	// Test with invalid signature
	badZ, _ := grp.RandomScalar()
	badSig := frost.Signature{
		R: r,
		Z: badZ,
	}

	err = aggregator.Verify(msg, badSig)
	if err == nil {
		t.Error("Verify should fail for invalid signature")
	}
}

func TestRerandomizedParticipant_RoundTwo_Error(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate key packages
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Compute randomizer
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Create rerandomized participant
	rerandParticipant := NewRerandomizedParticipant(*keyPackages[0], params, suite)

	// Round one to get valid nonces
	nonces, _, err := rerandParticipant.RoundOne()
	if err != nil {
		t.Fatalf("RoundOne failed: %v", err)
	}

	// Round two with invalid/empty commitment list should fail
	_, err = rerandParticipant.RoundTwo(nonces, []byte("msg"), frost.CommitmentList{})
	if err == nil {
		t.Error("RoundTwo should fail with empty commitment list")
	}
}

func TestRerandomizedAggregator_Aggregate_InsufficientShares(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")
	randomizer, _ := grp.RandomScalar()

	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	aggregator := NewRerandomizedAggregator(suite, 2, params)

	// Try to aggregate with insufficient shares (need 2, provide 1)
	hidingNonce, _ := grp.RandomScalar()
	bindingNonce, _ := grp.RandomScalar()
	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
		},
	}

	share, _ := grp.RandomScalar()
	signatureShares := []frost.SignatureShare{
		{Identifier: frost.Identifier(1), SignatureShare: share},
	}

	verificationShares := []frost.VerificationShare{
		{Identifier: frost.Identifier(1), VerificationKey: grp.Generator()},
	}

	_, err = aggregator.Aggregate(commitmentList, msg, signatureShares, verificationShares)
	if err == nil {
		t.Error("Aggregate should fail with insufficient shares")
	}
}

func TestRandomizeKeyPackage(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate key packages
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey

	// Compute randomizer
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Randomize a key package
	originalKP := *keyPackages[0]
	randomizedKP := RandomizeKeyPackage(originalKP, params, suite)

	// Verify secret share is randomized
	expectedSecret := originalKP.SecretShare.Add(params.Randomizer)
	if !randomizedKP.SecretShare.Equal(expectedSecret) {
		t.Error("Secret share should be randomized by adding randomizer")
	}

	// Verify group public key is randomized
	if !randomizedKP.GroupPublicKey.Equal(params.RandomizedVerifyingKey) {
		t.Error("Group public key should be randomized")
	}

	// Verify verification shares are randomized
	for i, vs := range randomizedKP.VerificationShares {
		expectedVK := originalKP.VerificationShares[i].VerificationKey.Add(params.RandomizerElement)
		if !vs.VerificationKey.Equal(expectedVK) {
			t.Errorf("Verification share %d should be randomized", i)
		}
	}
}

func TestRerandomizedVerify(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Create a simple Schnorr signature for testing
	secret, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(secret)

	msg := []byte("test message")
	randomizer, _ := grp.RandomScalar()

	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Create signature against randomized public key
	randomizedSecret := secret.Add(params.Randomizer)
	k, _ := grp.RandomScalar()
	r := grp.ScalarBaseMult(k)

	rBytes, _ := grp.SerializeElement(r)
	pkBytes, _ := grp.SerializeElement(params.RandomizedVerifyingKey)
	challengeInput := append(rBytes, pkBytes...)
	challengeInput = append(challengeInput, msg...)
	challenge := suite.H2(challengeInput)

	z := k.Add(challenge.Mul(randomizedSecret))

	sig := frost.Signature{R: r, Z: z}

	// Verify using RerandomizedVerify
	err = RerandomizedVerify(msg, sig, params, suite)
	if err != nil {
		t.Errorf("RerandomizedVerify failed for valid signature: %v", err)
	}
}

func TestRerandomizedSign_Success(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	msg := []byte("test message for RerandomizedSign")

	// Compute randomizer (same for all participants)
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Round 1: Generate nonces using regular participant
	participants := make([]*participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite).(*participant)
	}

	noncePackages := make([]*NoncePackage, 2)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments, 2)

	for i, p := range participants {
		nonces, commitment, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed for participant %d: %v", i, err)
		}
		noncePackages[i] = &NoncePackage{
			Nonces: nonces,
		}
		commitments[commitment.Identifier] = &commitment
	}

	// Round 2: Use RerandomizedSign for each participant
	signatureShares := make(map[frost.Identifier]*SignatureShare, 2)
	for i := 0; i < 2; i++ {
		share, err := RerandomizedSign(msg, keyPackages[i], noncePackages[i], commitments, params, suite)
		if err != nil {
			t.Fatalf("RerandomizedSign failed for participant %d: %v", i, err)
		}
		signatureShares[keyPackages[i].Identifier] = share
	}

	// Verify we got signature shares
	if len(signatureShares) != 2 {
		t.Errorf("Expected 2 signature shares, got %d", len(signatureShares))
	}

	for id, share := range signatureShares {
		if share.SignatureShare == nil {
			t.Errorf("Signature share for participant %d is nil", id)
		}
	}
}

func TestRerandomizedAggregate_Success(t *testing.T) {
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate keys
	identifiers := []frost.Identifier{1, 2, 3}
	keyPackages, pubKeyPkg, err := keygen.TrustedDealerKeygen(3, 2, identifiers, suite)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen failed: %v", err)
	}

	groupPublicKey := pubKeyPkg.GroupPublicKey
	msg := []byte("test message for RerandomizedAggregate")

	// Compute randomizer (same for all participants)
	randomizer, _ := grp.RandomScalar()
	params, err := NewRandomizedParams(randomizer, groupPublicKey, suite)
	if err != nil {
		t.Fatalf("NewRandomizedParams failed: %v", err)
	}

	// Round 1: Generate nonces using regular participant
	participants := make([]*participant, 2)
	for i := 0; i < 2; i++ {
		participants[i] = NewParticipant(*keyPackages[i], suite).(*participant)
	}

	noncePackages := make([]*NoncePackage, 2)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments, 2)

	for i, p := range participants {
		nonces, commitment, err := p.RoundOne()
		if err != nil {
			t.Fatalf("RoundOne failed for participant %d: %v", i, err)
		}
		noncePackages[i] = &NoncePackage{
			Nonces: nonces,
		}
		commitments[commitment.Identifier] = &commitment
	}

	// Round 2: Use RerandomizedSign for each participant
	signatureShares := make(map[frost.Identifier]*SignatureShare, 2)
	for i := 0; i < 2; i++ {
		share, err := RerandomizedSign(msg, keyPackages[i], noncePackages[i], commitments, params, suite)
		if err != nil {
			t.Fatalf("RerandomizedSign failed for participant %d: %v", i, err)
		}
		signatureShares[keyPackages[i].Identifier] = share
	}

	// Build verification shares
	verificationShares := make(map[frost.Identifier]frost.VerificationShare, 2)
	for i := 0; i < 2; i++ {
		for _, vs := range keyPackages[i].VerificationShares {
			if vs.Identifier == keyPackages[i].Identifier {
				verificationShares[keyPackages[i].Identifier] = vs
				break
			}
		}
	}

	// Aggregate using RerandomizedAggregate
	sig, err := RerandomizedAggregate(msg, commitments, signatureShares, verificationShares, params, suite)
	if err != nil {
		t.Fatalf("RerandomizedAggregate failed: %v", err)
	}

	// Verify signature is valid
	if sig.R == nil || sig.Z == nil {
		t.Error("Signature components should not be nil")
	}

	// Verify the signature against the randomized public key
	err = RerandomizedVerify(msg, sig, params, suite)
	if err != nil {
		t.Errorf("RerandomizedVerify failed: %v", err)
	}
}
