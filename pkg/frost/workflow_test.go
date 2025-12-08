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
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/dkg"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/refresh"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen/repairable"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestWorkflow_DKGToSigning_AllCiphersuites tests the complete
// DKG -> Signing workflow across all supported ciphersuites
func TestWorkflow_DKGToSigning_AllCiphersuites(t *testing.T) {
	suites := []struct {
		name  string
		suite ciphersuite.Ciphersuite
	}{
		{"Ed25519-SHA512", ed25519_sha512.New()},
		{"Ristretto255-SHA512", ristretto255_sha512.New()},
		{"Ed448-SHAKE256", ed448_shake256.New()},
		{"P256-SHA256", p256_sha256.New()},
		{"secp256k1-SHA256", secp256k1_sha256.New()},
	}

	for _, s := range suites {
		t.Run(s.name, func(t *testing.T) {
			testDKGToSigningWorkflow(t, s.suite)
		})
	}
}

func testDKGToSigningWorkflow(t *testing.T, suite ciphersuite.Ciphersuite) {
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// === PHASE 1: Distributed Key Generation ===

	// Round 1: All participants generate commitments and proofs
	secretPackages := make(map[frost.Identifier]*dkg.Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*dkg.Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := dkg.Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("DKG Part1 failed for participant %d: %v", i, err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	// Round 2: All participants verify proofs and distribute shares
	round2SecretPackages := make(map[frost.Identifier]*dkg.Round2SecretPackage)
	round2Packages := make(map[frost.Identifier]map[frost.Identifier]*dkg.Round2Package)

	for id, secretPkg := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*dkg.Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		r2SecretPkg, r2Pkgs, err := dkg.Part2(secretPkg, round1ForParticipant, suite)
		if err != nil {
			t.Fatalf("DKG Part2 failed for participant %v: %v", id, err)
		}
		round2SecretPackages[id] = r2SecretPkg
		round2Packages[id] = r2Pkgs
	}

	// Round 3: All participants finalize
	keyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	var publicKeyPackage *dkg.PublicKeyPackage

	for id := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*dkg.Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		round2ForParticipant := make(map[frost.Identifier]*dkg.Round2Package)
		for senderId, packages := range round2Packages {
			if senderId != id {
				round2ForParticipant[senderId] = packages[id]
			}
		}

		keyPkg, pubKeyPkg, err := dkg.Part3(round2SecretPackages[id], round1ForParticipant, round2ForParticipant, suite)
		if err != nil {
			t.Fatalf("DKG Part3 failed for participant %v: %v", id, err)
		}
		keyPackages[id] = keyPkg
		publicKeyPackage = pubKeyPkg
	}

	// Verify all participants have the same group public key
	for id, kp := range keyPackages {
		if !kp.GroupPublicKey.Equal(publicKeyPackage.VerifyingKey) {
			t.Errorf("Participant %v has different group public key", id)
		}
	}

	// === PHASE 2: Threshold Signing ===

	message := []byte("Integration test message for DKG-generated keys")

	// Select first minSigners participants
	signingParticipants := make([]*frost.KeyPackage, 0, minSigners)
	for _, kp := range keyPackages {
		signingParticipants = append(signingParticipants, kp)
		if uint32(len(signingParticipants)) >= minSigners {
			break
		}
	}

	// Round 1: Generate nonces
	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range signingParticipants {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("Failed to generate nonces for %v: %v", kp.Identifier, err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	// Round 2: Generate signature shares
	signatureShares := make(map[frost.Identifier]*signing.SignatureShare)
	for _, kp := range signingParticipants {
		share, err := signing.Sign(
			message,
			kp,
			noncePackages[kp.Identifier],
			commitments,
			suite,
		)
		if err != nil {
			t.Fatalf("Failed to sign for %v: %v", kp.Identifier, err)
		}
		signatureShares[kp.Identifier] = share
	}

	// Aggregate signature
	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for id, vs := range publicKeyPackage.VerifyingShares {
		verificationShares[id] = frost.VerificationShare{
			Identifier:      id,
			VerificationKey: vs,
		}
	}

	signature, err := signing.Aggregate(
		message,
		commitments,
		signatureShares,
		verificationShares,
		publicKeyPackage.VerifyingKey,
		suite,
	)
	if err != nil {
		t.Fatalf("Failed to aggregate signature: %v", err)
	}

	// Verify signature
	err = signing.VerifySignature(message, signature, publicKeyPackage.VerifyingKey, suite)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

// TestWorkflow_TrustedDealerRefreshSign tests trusted dealer
// keygen, refresh, and signing workflow
func TestWorkflow_TrustedDealerRefreshSign(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("Failed to generate initial keys: %v", err)
	}

	originalGroupPublicKey := publicKeyPackage.GroupPublicKey

	// Sign a message before refresh
	message1 := []byte("Message before key refresh")
	sig1 := signWithKeyPackages(t, message1, keyPackages[:minSigners], publicKeyPackage, suite)

	err = signing.VerifySignature(message1, sig1, publicKeyPackage.GroupPublicKey, suite)
	if err != nil {
		t.Errorf("Pre-refresh signature verification failed: %v", err)
	}

	// === KEY REFRESH ===

	dkgPublicKeyPackage := &dkg.PublicKeyPackage{
		VerifyingKey:    publicKeyPackage.GroupPublicKey,
		VerifyingShares: make(map[frost.Identifier]group.Element),
	}
	for _, vs := range publicKeyPackage.VerificationShares {
		dkgPublicKeyPackage.VerifyingShares[vs.Identifier] = vs.VerificationKey
	}

	refreshShares, newPublicKeyPackage, err := refresh.ComputeRefreshingShares(
		dkgPublicKeyPackage,
		maxSigners,
		minSigners,
		identifiers,
		suite,
	)
	if err != nil {
		t.Fatalf("Failed to compute refresh shares: %v", err)
	}

	// Verify group public key unchanged
	if !newPublicKeyPackage.VerifyingKey.Equal(originalGroupPublicKey) {
		t.Error("Group public key changed after refresh")
	}

	// Apply refresh shares
	refreshedKeyPackages := make([]*frost.KeyPackage, len(keyPackages))
	for i, kp := range keyPackages {
		var rs refresh.RefreshShare
		for _, r := range refreshShares {
			if r.Identifier == kp.Identifier {
				rs = r
				break
			}
		}
		refreshedKP, err := refresh.ApplyRefreshShare(rs, kp, suite)
		if err != nil {
			t.Fatalf("Failed to apply refresh share: %v", err)
		}
		refreshedKeyPackages[i] = refreshedKP
	}

	// Sign with refreshed keys
	refreshedPublicKeyPackage := &keygen.PublicKeyPackage{
		GroupPublicKey: newPublicKeyPackage.VerifyingKey,
	}
	for id, vs := range newPublicKeyPackage.VerifyingShares {
		refreshedPublicKeyPackage.VerificationShares = append(
			refreshedPublicKeyPackage.VerificationShares,
			frost.VerificationShare{Identifier: id, VerificationKey: vs},
		)
	}

	message2 := []byte("Message after key refresh")
	sig2 := signWithKeyPackages(t, message2, refreshedKeyPackages[:minSigners], refreshedPublicKeyPackage, suite)

	err = signing.VerifySignature(message2, sig2, newPublicKeyPackage.VerifyingKey, suite)
	if err != nil {
		t.Errorf("Post-refresh signature verification failed: %v", err)
	}
}

// TestWorkflow_ShareRepairAndSign tests share repair followed by signing
func TestWorkflow_ShareRepairAndSign(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// Generate initial keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("Failed to generate initial keys: %v", err)
	}

	// Participant 1 "loses" their share
	lostParticipant := frost.Identifier(1)
	originalShare := keyPackages[0].SecretShare

	// Helpers: participants 2, 3, 4
	helperIdentifiers := []frost.Identifier{2, 3, 4}
	helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	for _, kp := range keyPackages {
		for _, hid := range helperIdentifiers {
			if kp.Identifier == hid {
				helperKeyPackages[hid] = kp
			}
		}
	}

	// Execute repair protocol
	step1Results := make(map[frost.Identifier]*repairable.Step1Result)
	for _, hid := range helperIdentifiers {
		result, err := repairable.RepairShareStep1(
			helperIdentifiers,
			helperKeyPackages[hid],
			lostParticipant,
			suite,
		)
		if err != nil {
			t.Fatalf("Repair Step1 failed: %v", err)
		}
		step1Results[hid] = result
	}

	sigmas := make([]group.Scalar, len(helperIdentifiers))
	for i, hid := range helperIdentifiers {
		deltas := make([]group.Scalar, 0)
		for _, senderId := range helperIdentifiers {
			deltas = append(deltas, step1Results[senderId].Deltas[hid])
		}
		sigmas[i] = repairable.RepairShareStep2(deltas)
	}

	recoveredKeyPackage, err := repairable.RepairShareStep3(
		sigmas,
		lostParticipant,
		publicKeyPackage.GroupPublicKey,
		nil,
		suite,
	)
	if err != nil {
		t.Fatalf("Repair Step3 failed: %v", err)
	}

	// Verify recovered share matches original
	if !recoveredKeyPackage.SecretShare.Equal(originalShare) {
		t.Error("Recovered share doesn't match original")
	}

	// Add verification shares to recovered key package
	recoveredKeyPackage.VerificationShares = keyPackages[0].VerificationShares

	// Sign with recovered participant and 2 helpers
	signingKeyPackages := []*frost.KeyPackage{
		recoveredKeyPackage,
		keyPackages[1], // participant 2
		keyPackages[2], // participant 3
	}

	message := []byte("Message signed with recovered share")
	sig := signWithKeyPackages(t, message, signingKeyPackages, publicKeyPackage, suite)

	err = signing.VerifySignature(message, sig, publicKeyPackage.GroupPublicKey, suite)
	if err != nil {
		t.Errorf("Signature verification with recovered share failed: %v", err)
	}
}

// TestWorkflow_BatchVerifyMultipleSignatures tests batch verification of
// multiple signatures from different signing sessions
func TestWorkflow_BatchVerifyMultipleSignatures(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// Generate keys
	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Create multiple signatures
	numSignatures := 10
	signatures := make([]frost.Signature, numSignatures)
	messages := make([][]byte, numSignatures)

	for i := 0; i < numSignatures; i++ {
		messages[i] = []byte("Batch verification message " + string(rune('A'+i)))
		signatures[i] = signWithKeyPackages(t, messages[i], keyPackages[:minSigners], publicKeyPackage, suite)
	}

	// Batch verify all signatures
	bv := signing.NewBatchVerifier(suite)
	for i := 0; i < numSignatures; i++ {
		err := bv.Add(publicKeyPackage.GroupPublicKey, signatures[i], messages[i])
		if err != nil {
			t.Fatalf("Failed to add signature %d to batch: %v", i, err)
		}
	}

	err = bv.Verify()
	if err != nil {
		t.Errorf("Batch verification failed: %v", err)
	}
}

// TestWorkflow_SecretReconstruction tests secret reconstruction from shares
func TestWorkflow_SecretReconstruction(t *testing.T) {
	suite := ed25519_sha512.New()
	grp := suite.Group()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	identifiers := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < maxSigners; i++ {
		identifiers[i] = frost.Identifier(i + 1)
	}

	keyPackages, publicKeyPackage, err := keygen.TrustedDealerKeygen(maxSigners, minSigners, identifiers, suite)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Reconstruct secret using exactly threshold shares
	shareInputs := make([]keygen.ShareInput, minSigners)
	for i := uint32(0); i < minSigners; i++ {
		shareInputs[i] = keygen.ShareInput{
			Identifier: keyPackages[i].Identifier,
			Share:      keyPackages[i].SecretShare,
		}
	}

	reconstructedSecret, err := keygen.Reconstruct(shareInputs, suite)
	if err != nil {
		t.Fatalf("Failed to reconstruct secret: %v", err)
	}

	// Verify reconstructed secret produces the correct public key
	computedPublicKey := grp.ScalarBaseMult(reconstructedSecret)
	if !computedPublicKey.Equal(publicKeyPackage.GroupPublicKey) {
		t.Error("Reconstructed secret doesn't produce correct public key")
	}

	// Test with different subset of shares
	shareInputs2 := make([]keygen.ShareInput, minSigners)
	for i := uint32(0); i < minSigners; i++ {
		// Use participants 2, 4, 5 (indices 1, 3, 4)
		idx := (i*2 + 1) % maxSigners
		shareInputs2[i] = keygen.ShareInput{
			Identifier: keyPackages[idx].Identifier,
			Share:      keyPackages[idx].SecretShare,
		}
	}

	reconstructedSecret2, err := keygen.Reconstruct(shareInputs2, suite)
	if err != nil {
		t.Fatalf("Failed to reconstruct with different subset: %v", err)
	}

	// Both reconstructions should give the same secret
	if !reconstructedSecret.Equal(reconstructedSecret2) {
		t.Error("Different share subsets reconstructed different secrets")
	}
}

// TestWorkflow_DKGRefreshRepairSign tests a complete lifecycle:
// DKG -> Sign -> Refresh -> Sign -> Repair -> Sign
func TestWorkflow_DKGRefreshRepairSign(t *testing.T) {
	suite := ed25519_sha512.New()
	maxSigners := uint32(5)
	minSigners := uint32(3)

	// === PHASE 1: DKG ===

	secretPackages := make(map[frost.Identifier]*dkg.Round1SecretPackage)
	publicPackages := make(map[frost.Identifier]*dkg.Round1Package)

	for i := uint32(1); i <= maxSigners; i++ {
		id := frost.Identifier(i)
		secretPkg, publicPkg, err := dkg.Part1(id, maxSigners, minSigners, suite)
		if err != nil {
			t.Fatalf("DKG Part1 failed: %v", err)
		}
		secretPackages[id] = secretPkg
		publicPackages[id] = publicPkg
	}

	round2SecretPackages := make(map[frost.Identifier]*dkg.Round2SecretPackage)
	round2Packages := make(map[frost.Identifier]map[frost.Identifier]*dkg.Round2Package)

	for id, secretPkg := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*dkg.Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		r2SecretPkg, r2Pkgs, err := dkg.Part2(secretPkg, round1ForParticipant, suite)
		if err != nil {
			t.Fatalf("DKG Part2 failed: %v", err)
		}
		round2SecretPackages[id] = r2SecretPkg
		round2Packages[id] = r2Pkgs
	}

	keyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	var dkgPublicKeyPackage *dkg.PublicKeyPackage

	for id := range secretPackages {
		round1ForParticipant := make(map[frost.Identifier]*dkg.Round1Package)
		for otherId, pkg := range publicPackages {
			if otherId != id {
				round1ForParticipant[otherId] = pkg
			}
		}

		round2ForParticipant := make(map[frost.Identifier]*dkg.Round2Package)
		for senderId, packages := range round2Packages {
			if senderId != id {
				round2ForParticipant[senderId] = packages[id]
			}
		}

		keyPkg, pubKeyPkg, err := dkg.Part3(round2SecretPackages[id], round1ForParticipant, round2ForParticipant, suite)
		if err != nil {
			t.Fatalf("DKG Part3 failed: %v", err)
		}
		keyPackages[id] = keyPkg
		dkgPublicKeyPackage = pubKeyPkg
	}

	// Convert to keygen.PublicKeyPackage format
	publicKeyPackage := &keygen.PublicKeyPackage{
		GroupPublicKey: dkgPublicKeyPackage.VerifyingKey,
	}
	for id, vs := range dkgPublicKeyPackage.VerifyingShares {
		publicKeyPackage.VerificationShares = append(publicKeyPackage.VerificationShares,
			frost.VerificationShare{Identifier: id, VerificationKey: vs})
	}

	// Convert map to slice for signing helper
	keyPackageSlice := make([]*frost.KeyPackage, 0, len(keyPackages))
	for _, kp := range keyPackages {
		keyPackageSlice = append(keyPackageSlice, kp)
	}

	// === PHASE 2: Initial Sign ===

	message1 := []byte("Message after DKG")
	sig1 := signWithKeyPackages(t, message1, keyPackageSlice[:minSigners], publicKeyPackage, suite)
	if err := signing.VerifySignature(message1, sig1, publicKeyPackage.GroupPublicKey, suite); err != nil {
		t.Errorf("Initial signing failed: %v", err)
	}

	// === PHASE 3: Refresh ===

	identifiers := make([]frost.Identifier, 0, len(keyPackages))
	for id := range keyPackages {
		identifiers = append(identifiers, id)
	}

	refreshShares, newDkgPublicKeyPackage, err := refresh.ComputeRefreshingShares(
		dkgPublicKeyPackage,
		maxSigners,
		minSigners,
		identifiers,
		suite,
	)
	if err != nil {
		t.Fatalf("Failed to compute refresh shares: %v", err)
	}

	// Apply refresh shares
	for id, kp := range keyPackages {
		var rs refresh.RefreshShare
		for _, r := range refreshShares {
			if r.Identifier == id {
				rs = r
				break
			}
		}
		refreshedKP, err := refresh.ApplyRefreshShare(rs, kp, suite)
		if err != nil {
			t.Fatalf("Failed to apply refresh share: %v", err)
		}
		keyPackages[id] = refreshedKP
	}

	// Update public key package
	publicKeyPackage.GroupPublicKey = newDkgPublicKeyPackage.VerifyingKey
	publicKeyPackage.VerificationShares = nil
	for id, vs := range newDkgPublicKeyPackage.VerifyingShares {
		publicKeyPackage.VerificationShares = append(publicKeyPackage.VerificationShares,
			frost.VerificationShare{Identifier: id, VerificationKey: vs})
	}

	// Update slice
	keyPackageSlice = keyPackageSlice[:0]
	for _, kp := range keyPackages {
		keyPackageSlice = append(keyPackageSlice, kp)
	}

	// === PHASE 4: Sign after refresh ===

	message2 := []byte("Message after refresh")
	sig2 := signWithKeyPackages(t, message2, keyPackageSlice[:minSigners], publicKeyPackage, suite)
	if err := signing.VerifySignature(message2, sig2, publicKeyPackage.GroupPublicKey, suite); err != nil {
		t.Errorf("Post-refresh signing failed: %v", err)
	}

	// === PHASE 5: Repair (simulate participant 1 losing their share) ===

	lostParticipant := frost.Identifier(1)
	originalLostShare := keyPackages[lostParticipant].SecretShare

	helperIdentifiers := []frost.Identifier{2, 3, 4}
	helperKeyPackages := make(map[frost.Identifier]*frost.KeyPackage)
	for _, hid := range helperIdentifiers {
		helperKeyPackages[hid] = keyPackages[hid]
	}

	step1Results := make(map[frost.Identifier]*repairable.Step1Result)
	for _, hid := range helperIdentifiers {
		result, err := repairable.RepairShareStep1(helperIdentifiers, helperKeyPackages[hid], lostParticipant, suite)
		if err != nil {
			t.Fatalf("Repair Step1 failed: %v", err)
		}
		step1Results[hid] = result
	}

	sigmas := make([]group.Scalar, len(helperIdentifiers))
	for i, hid := range helperIdentifiers {
		deltas := make([]group.Scalar, 0)
		for _, sid := range helperIdentifiers {
			deltas = append(deltas, step1Results[sid].Deltas[hid])
		}
		sigmas[i] = repairable.RepairShareStep2(deltas)
	}

	recoveredKeyPackage, err := repairable.RepairShareStep3(sigmas, lostParticipant, publicKeyPackage.GroupPublicKey, nil, suite)
	if err != nil {
		t.Fatalf("Repair Step3 failed: %v", err)
	}

	if !recoveredKeyPackage.SecretShare.Equal(originalLostShare) {
		t.Error("Recovered share doesn't match lost share")
	}

	recoveredKeyPackage.VerificationShares = keyPackages[lostParticipant].VerificationShares
	keyPackages[lostParticipant] = recoveredKeyPackage

	// === PHASE 6: Sign after repair ===

	message3 := []byte("Message after repair")
	signingParticipants := []*frost.KeyPackage{
		keyPackages[frost.Identifier(1)], // Recovered
		keyPackages[frost.Identifier(2)],
		keyPackages[frost.Identifier(3)],
	}
	sig3 := signWithKeyPackages(t, message3, signingParticipants, publicKeyPackage, suite)
	if err := signing.VerifySignature(message3, sig3, publicKeyPackage.GroupPublicKey, suite); err != nil {
		t.Errorf("Post-repair signing failed: %v", err)
	}
}

// signWithKeyPackages is a helper that creates a threshold signature
func signWithKeyPackages(
	t *testing.T,
	message []byte,
	keyPackages []*frost.KeyPackage,
	publicKeyPackage *keygen.PublicKeyPackage,
	suite ciphersuite.Ciphersuite,
) frost.Signature {
	t.Helper()

	noncePackages := make(map[frost.Identifier]*signing.NoncePackage)
	commitments := make(map[frost.Identifier]*frost.SigningCommitments)

	for _, kp := range keyPackages {
		noncePkg, err := signing.GenerateNonces(kp.Identifier, kp.SecretShare, suite)
		if err != nil {
			t.Fatalf("Failed to generate nonces: %v", err)
		}
		noncePackages[kp.Identifier] = noncePkg
		commitments[kp.Identifier] = noncePkg.Commitments
	}

	signatureShares := make(map[frost.Identifier]*signing.SignatureShare)
	for _, kp := range keyPackages {
		share, err := signing.Sign(message, kp, noncePackages[kp.Identifier], commitments, suite)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		signatureShares[kp.Identifier] = share
	}

	verificationShares := make(map[frost.Identifier]frost.VerificationShare)
	for _, vs := range publicKeyPackage.VerificationShares {
		verificationShares[vs.Identifier] = vs
	}

	signature, err := signing.Aggregate(message, commitments, signatureShares, verificationShares, publicKeyPackage.GroupPublicKey, suite)
	if err != nil {
		t.Fatalf("Failed to aggregate: %v", err)
	}

	return signature
}
