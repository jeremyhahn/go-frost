package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Mock participant for testing
type mockParticipant struct {
	id          frost.Identifier
	commitments frost.SigningCommitments
	nonces      frost.SigningNonces
	share       frost.SignatureShare
	shouldFail  bool
}

func (m *mockParticipant) Identifier() frost.Identifier {
	return m.id
}

func (m *mockParticipant) MinSigners() uint32 {
	return 2 // Default for tests
}

func (m *mockParticipant) RoundOne() (frost.SigningNonces, frost.SigningCommitments, error) {
	if m.shouldFail {
		return frost.SigningNonces{}, frost.SigningCommitments{}, frost.ErrInvalidNonce
	}
	return m.nonces, m.commitments, nil
}

func (m *mockParticipant) RoundTwo(nonces frost.SigningNonces, msg []byte, commitmentList frost.CommitmentList) (frost.SignatureShare, error) {
	if m.shouldFail {
		return frost.SignatureShare{}, frost.ErrInvalidSignatureShare
	}
	return m.share, nil
}

func (m *mockParticipant) VerifySignatureShare(share frost.SignatureShare, msg []byte, commitmentList frost.CommitmentList) error {
	if m.shouldFail {
		return frost.ErrInvalidSignatureShare
	}
	return nil
}

func TestCoordinator_RequestCommitments_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create mock participants
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participant2 := &mockParticipant{
		id: frost.Identifier(2),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce2,
			BindingNonce: bindingNonce2,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
		frost.Identifier(2): participant2,
	}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{frost.Identifier(1), frost.Identifier(2)}
	msg := []byte("test message")

	// Request commitments
	commitmentList, err := coordinator.RequestCommitments(participantIDs, msg)
	if err != nil {
		t.Fatalf("RequestCommitments failed: %v", err)
	}

	// Verify commitment list
	if len(commitmentList) != 2 {
		t.Errorf("Expected 2 commitments, got %d", len(commitmentList))
	}

	// Verify sorted by identifier
	if commitmentList[0].Identifier != frost.Identifier(1) {
		t.Errorf("Expected first commitment identifier 1, got %d", commitmentList[0].Identifier)
	}
	if commitmentList[1].Identifier != frost.Identifier(2) {
		t.Errorf("Expected second commitment identifier 2, got %d", commitmentList[1].Identifier)
	}
}

func TestCoordinator_RequestCommitments_EmptyParticipantList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	participants := map[frost.Identifier]Participant{}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{}
	msg := []byte("test message")

	// Request commitments should fail
	_, err := coordinator.RequestCommitments(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error for empty participant list")
	}
}

func TestCoordinator_RequestCommitments_InvalidParticipant(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	// Request commitment from non-existent participant
	participantIDs := []frost.Identifier{frost.Identifier(1), frost.Identifier(999)}
	msg := []byte("test message")

	_, err := coordinator.RequestCommitments(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error for invalid participant")
	}
	if err != frost.ErrInvalidParticipant {
		t.Errorf("Expected ErrInvalidParticipant, got: %v", err)
	}
}

func TestCoordinator_RequestCommitments_ParticipantFails(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	participant1 := &mockParticipant{
		id:         frost.Identifier(1),
		shouldFail: true,
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	_, err := coordinator.RequestCommitments(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error when participant fails")
	}
}

func TestCoordinator_RequestSignatureShares_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create mock participants
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		share: frost.SignatureShare{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	participant2 := &mockParticipant{
		id: frost.Identifier(2),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce2,
			BindingNonce: bindingNonce2,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
		share: frost.SignatureShare{
			Identifier:     frost.Identifier(2),
			SignatureShare: share2,
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
		frost.Identifier(2): participant2,
	}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)
	msg := []byte("test message")

	// First, request commitments (required for stateful coordinator)
	participantIDs := []frost.Identifier{frost.Identifier(1), frost.Identifier(2)}
	commitmentList, err := coordinator.RequestCommitments(participantIDs, msg)
	if err != nil {
		t.Fatalf("RequestCommitments failed: %v", err)
	}

	// Request signature shares
	signatureShares, err := coordinator.RequestSignatureShares(commitmentList, msg)
	if err != nil {
		t.Fatalf("RequestSignatureShares failed: %v", err)
	}

	// Verify signature shares
	if len(signatureShares) != 2 {
		t.Errorf("Expected 2 signature shares, got %d", len(signatureShares))
	}
}

func TestCoordinator_RequestSignatureShares_EmptyCommitmentList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	participants := map[frost.Identifier]Participant{}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	commitmentList := frost.CommitmentList{}
	msg := []byte("test message")

	_, err := coordinator.RequestSignatureShares(commitmentList, msg)
	if err == nil {
		t.Fatal("Expected error for empty commitment list")
	}
	if err != frost.ErrEmptyCommitmentList {
		t.Errorf("Expected ErrEmptyCommitmentList, got: %v", err)
	}
}

func TestCoordinator_RequestSignatureShares_ParticipantFails(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		shouldFail: true,
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinator(suite, participants, aggregator)

	commitmentList := frost.CommitmentList{participant1.commitments}
	msg := []byte("test message")

	_, err := coordinator.RequestSignatureShares(commitmentList, msg)
	if err == nil {
		t.Fatal("Expected error when participant fails")
	}
}

func TestCoordinator_Sign_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create mock participants
	nonce1, _ := grp.RandomScalar()
	nonce2, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce2, _ := grp.RandomScalar()
	share1, _ := grp.RandomScalar()
	share2, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		share: frost.SignatureShare{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	participant2 := &mockParticipant{
		id: frost.Identifier(2),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce2,
			BindingNonce: bindingNonce2,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(2),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce2),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce2),
		},
		share: frost.SignatureShare{
			Identifier:     frost.Identifier(2),
			SignatureShare: share2,
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
		frost.Identifier(2): participant2,
	}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinatorWithPublicKey(suite, participants, aggregator, groupPublicKey)

	participantIDs := []frost.Identifier{frost.Identifier(1), frost.Identifier(2)}
	msg := []byte("test message")

	// Execute complete signing protocol
	signature, err := coordinator.Sign(participantIDs, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature structure
	if signature.R == nil {
		t.Error("Expected signature.R to be set")
	}
	if signature.Z == nil {
		t.Error("Expected signature.Z to be set")
	}

	// Verify z = sum(z_i)
	expectedZ := share1.Add(share2)
	if !signature.Z.Equal(expectedZ) {
		t.Error("Signature.Z does not equal sum of signature shares")
	}
}

func TestCoordinator_Sign_EmptyParticipantList(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	participants := map[frost.Identifier]Participant{}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{}
	msg := []byte("test message")

	_, err := coordinator.Sign(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error for empty participant list")
	}
}

func TestCoordinator_Sign_CommitmentPhaseFails(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	participant1 := &mockParticipant{
		id:         frost.Identifier(1),
		shouldFail: true,
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	_, err := coordinator.Sign(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error when commitment phase fails")
	}
}

func TestCoordinator_Sign_NilGroupPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 1)
	// Create coordinator without group public key
	coordinator := NewCoordinator(suite, participants, aggregator)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	_, err := coordinator.Sign(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error for nil group public key")
	}
}

func TestCoordinator_RequestCommitments_UnsortedParticipants(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create participants with IDs in unsorted order
	nonce1, _ := grp.RandomScalar()
	nonce3, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	bindingNonce3, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participant3 := &mockParticipant{
		id: frost.Identifier(3),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce3,
			BindingNonce: bindingNonce3,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(3),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce3),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce3),
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
		frost.Identifier(3): participant3,
	}

	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinator(suite, participants, aggregator)

	// Request commitments in unsorted order (3, 1)
	participantIDs := []frost.Identifier{frost.Identifier(3), frost.Identifier(1)}
	msg := []byte("test message")

	commitmentList, err := coordinator.RequestCommitments(participantIDs, msg)
	if err != nil {
		t.Fatalf("RequestCommitments failed: %v", err)
	}

	// Verify list is sorted (1, 3)
	if len(commitmentList) != 2 {
		t.Fatalf("Expected 2 commitments, got %d", len(commitmentList))
	}
	if commitmentList[0].Identifier != frost.Identifier(1) {
		t.Errorf("Expected first commitment identifier 1, got %d", commitmentList[0].Identifier)
	}
	if commitmentList[1].Identifier != frost.Identifier(3) {
		t.Errorf("Expected second commitment identifier 3, got %d", commitmentList[1].Identifier)
	}
}

func TestCoordinator_Sign_SignatureSharePhaseFails(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create participant that succeeds in round 1 but fails in round 2
	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		shouldFail: false, // Succeeds in round 1
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinatorWithPublicKey(suite, participants, aggregator, groupPublicKey)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	// Make participant fail in round 2
	participant1.shouldFail = true

	_, err := coordinator.Sign(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error when signature share phase fails")
	}
}

func TestCoordinator_RequestSignatureShares_ParticipantNotFound(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create commitment for participant that doesn't exist in map
	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(999), // Non-existent
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participants := map[frost.Identifier]Participant{}
	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinator(suite, participants, aggregator)

	msg := []byte("test message")

	_, err := coordinator.RequestSignatureShares(commitmentList, msg)
	if err == nil {
		t.Fatal("Expected error for participant not found")
	}
}

func TestCoordinator_Sign_AggregationFails(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create group public key
	groupSecretKey, _ := grp.RandomScalar()
	groupPublicKey := grp.ScalarBaseMult(groupSecretKey)

	// Create only 1 participant but require 2 signatures (insufficient)
	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()
	share1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		share: frost.SignatureShare{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	// Require 2 signers but only have 1
	aggregator := NewAggregator(suite, 2)
	coordinator := NewCoordinatorWithPublicKey(suite, participants, aggregator, groupPublicKey)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	_, err := coordinator.Sign(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error when aggregation fails")
	}
	if err != frost.ErrInsufficientParticipants {
		t.Errorf("Expected ErrInsufficientParticipants, got: %v", err)
	}
}

func TestAggregator_Aggregate_NilGroupPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	minSigners := uint32(2)

	agg := NewAggregator(suite, minSigners)

	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	commitmentList := frost.CommitmentList{
		{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	msg := []byte("test message")
	share1, _ := grp.RandomScalar()

	signatureShares := []frost.SignatureShare{
		{
			Identifier:     frost.Identifier(1),
			SignatureShare: share1,
		},
	}

	// Aggregate with nil group public key should fail
	_, err := agg.Aggregate(nil, commitmentList, msg, signatureShares)
	if err == nil {
		t.Fatal("Expected error for nil group public key")
	}
}

// TestCoordinator_AuthenticateCommitment_Success tests successful commitment authentication.
func TestCoordinator_AuthenticateCommitment_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create coordinator with authenticator
	coord := NewCoordinatorWithAuthenticator(suite, nil, nil, nil, auth)

	// Create commitment
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Sign commitment
	proof, err := security.SignCommitment(participantID, commitment, privKey)
	if err != nil {
		t.Fatal(err)
	}

	// Authenticate commitment - should succeed
	c := coord.(*coordinator)
	err = c.AuthenticateCommitment(participantID, commitment, proof)
	if err != nil {
		t.Fatalf("Expected authentication to succeed, got error: %v", err)
	}
}

// TestCoordinator_AuthenticateCommitment_InvalidProof tests authentication fails with invalid proof.
func TestCoordinator_AuthenticateCommitment_InvalidProof(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create coordinator with authenticator
	coord := NewCoordinatorWithAuthenticator(suite, nil, nil, nil, auth)

	// Create commitment
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Use invalid proof (random bytes)
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	// Authenticate commitment - should fail
	c := coord.(*coordinator)
	err = c.AuthenticateCommitment(participantID, commitment, invalidProof)
	if err == nil {
		t.Fatal("Expected authentication to fail with invalid proof")
	}
}

// TestCoordinator_AuthenticateCommitment_NoAuthenticator tests authentication fails without authenticator.
func TestCoordinator_AuthenticateCommitment_NoAuthenticator(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create coordinator without authenticator
	coord := NewCoordinator(suite, nil, nil)

	// Create commitment
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Authenticate commitment - should fail (no authenticator configured)
	c := coord.(*coordinator)
	err := c.AuthenticateCommitment(frost.Identifier(1), commitment, nil)
	if err == nil {
		t.Fatal("Expected error when no authenticator is configured")
	}
}

// TestCoordinator_AuthenticateSignatureShare_Success tests successful signature share authentication.
func TestCoordinator_AuthenticateSignatureShare_Success(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create coordinator with authenticator
	coord := NewCoordinatorWithAuthenticator(suite, nil, nil, nil, auth)

	// Create signature share
	shareScalar, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     participantID,
		SignatureShare: shareScalar,
	}

	// Sign signature share
	proof, err := security.SignSignatureShare(participantID, share, privKey)
	if err != nil {
		t.Fatal(err)
	}

	// Authenticate signature share - should succeed
	c := coord.(*coordinator)
	err = c.AuthenticateSignatureShare(participantID, share, proof)
	if err != nil {
		t.Fatalf("Expected authentication to succeed, got error: %v", err)
	}
}

// TestCoordinator_AuthenticateSignatureShare_InvalidProof tests authentication fails with invalid proof.
func TestCoordinator_AuthenticateSignatureShare_InvalidProof(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create coordinator with authenticator
	coord := NewCoordinatorWithAuthenticator(suite, nil, nil, nil, auth)

	// Create signature share
	shareScalar, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     participantID,
		SignatureShare: shareScalar,
	}

	// Use invalid proof (random bytes)
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	// Authenticate signature share - should fail
	c := coord.(*coordinator)
	err = c.AuthenticateSignatureShare(participantID, share, invalidProof)
	if err == nil {
		t.Fatal("Expected authentication to fail with invalid proof")
	}
}

// TestCoordinator_AuthenticateSignatureShare_NoAuthenticator tests authentication fails without authenticator.
func TestCoordinator_AuthenticateSignatureShare_NoAuthenticator(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create coordinator without authenticator
	coord := NewCoordinator(suite, nil, nil)

	// Create signature share
	shareScalar, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     frost.Identifier(1),
		SignatureShare: shareScalar,
	}

	// Authenticate signature share - should fail (no authenticator configured)
	c := coord.(*coordinator)
	err := c.AuthenticateSignatureShare(frost.Identifier(1), share, nil)
	if err == nil {
		t.Fatal("Expected error when no authenticator is configured")
	}
}

// TestNewCoordinatorWithSecurity tests the security-enhanced coordinator constructor.
func TestNewCoordinatorWithSecurity(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create participants
	participants := make(map[frost.Identifier]Participant)
	for i := 1; i <= 3; i++ {
		participants[frost.Identifier(i)] = NewParticipant(
			frost.KeyPackage{
				Identifier:  frost.Identifier(i),
				SecretShare: grp.NewScalar(),
			},
			suite,
		)
	}

	// Create aggregator
	aggregator := NewAggregator(suite, 3)

	// Create group public key
	groupPubKey := grp.Generator()

	// Create Ed25519 authenticator
	pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey3, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	authenticator := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		frost.Identifier(1): pubKey1,
		frost.Identifier(2): pubKey2,
		frost.Identifier(3): pubKey3,
	})

	// Create reputation tracker
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	// Create coordinator with security
	coord := NewCoordinatorWithSecurity(
		suite,
		participants,
		aggregator,
		groupPubKey,
		authenticator,
		reputationTracker,
	)

	if coord == nil {
		t.Fatal("NewCoordinatorWithSecurity returned nil")
	}

	// Verify coordinator has security features
	c := coord.(*coordinator)
	if c.authenticator == nil {
		t.Error("Coordinator should have authenticator")
	}
	if c.reputationTracker == nil {
		t.Error("Coordinator should have reputation tracker")
	}
	if c.suite != suite {
		t.Error("Coordinator should have correct ciphersuite")
	}
	if len(c.participants) != 3 {
		t.Errorf("Coordinator should have 3 participants, got %d", len(c.participants))
	}
	if c.aggregator == nil {
		t.Error("Coordinator should have aggregator")
	}
	if !c.groupPublicKey.Equal(groupPubKey) {
		t.Error("Coordinator should have correct group public key")
	}
}

// TestCoordinator_RequestCommitments_ExcludedParticipant tests that excluded participants are rejected.
func TestCoordinator_RequestCommitments_ExcludedParticipant(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create mock participant
	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	// Create reputation tracker and exclude participant
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	// Record enough misbehaviors to exclude participant
	for i := 0; i < reputationConfig.MaxInvalidShares+1; i++ {
		reputationTracker.RecordMisbehavior(frost.Identifier(1), security.MisbehaviorInvalidCommitment, "test")
	}

	aggregator := NewAggregator(suite, 1)
	groupPubKey := grp.Generator()

	// Create coordinator with reputation tracker
	coordinator := NewCoordinatorWithSecurity(suite, participants, aggregator, groupPubKey, nil, reputationTracker)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	// Request commitments should fail - participant is excluded
	_, err := coordinator.RequestCommitments(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error for excluded participant")
	}
}

// TestCoordinator_RequestCommitments_TracksMisbehavior tests that misbehavior is tracked.
func TestCoordinator_RequestCommitments_TracksMisbehavior(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	// Create failing participant
	participant1 := &mockParticipant{
		id:         frost.Identifier(1),
		shouldFail: true, // Will fail RoundOne
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	// Create reputation tracker
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinatorWithSecurity(suite, participants, aggregator, nil, nil, reputationTracker)

	participantIDs := []frost.Identifier{frost.Identifier(1)}
	msg := []byte("test message")

	// Request commitments - participant will fail
	_, err := coordinator.RequestCommitments(participantIDs, msg)
	if err == nil {
		t.Fatal("Expected error when participant fails")
	}

	// Verify misbehavior was recorded
	excluded, err := reputationTracker.IsExcluded(frost.Identifier(1))
	if err != nil {
		t.Fatalf("Failed to check exclusion: %v", err)
	}

	// After first failure, should not be excluded yet
	if excluded {
		t.Error("Participant should not be excluded after single failure")
	}
}

// TestCoordinator_RequestSignatureShares_TracksMisbehavior tests that signature share misbehavior is tracked.
func TestCoordinator_RequestSignatureShares_TracksMisbehavior(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Create participant that will fail in RoundTwo
	nonce1, _ := grp.RandomScalar()
	bindingNonce1, _ := grp.RandomScalar()

	participant1 := &mockParticipant{
		id: frost.Identifier(1),
		nonces: frost.SigningNonces{
			HidingNonce:  nonce1,
			BindingNonce: bindingNonce1,
		},
		commitments: frost.SigningCommitments{
			Identifier:             frost.Identifier(1),
			HidingNonceCommitment:  grp.ScalarBaseMult(nonce1),
			BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce1),
		},
		shouldFail: true, // Will fail RoundTwo
	}

	participants := map[frost.Identifier]Participant{
		frost.Identifier(1): participant1,
	}

	// Create reputation tracker
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	aggregator := NewAggregator(suite, 1)
	coordinator := NewCoordinatorWithSecurity(suite, participants, aggregator, nil, nil, reputationTracker)

	commitmentList := frost.CommitmentList{participant1.commitments}
	msg := []byte("test message")

	// Request signature shares - participant will fail
	_, err := coordinator.RequestSignatureShares(commitmentList, msg)
	if err == nil {
		t.Fatal("Expected error when participant fails")
	}

	// Verify misbehavior was recorded
	excluded, err := reputationTracker.IsExcluded(frost.Identifier(1))
	if err != nil {
		t.Fatalf("Failed to check exclusion: %v", err)
	}

	// After first failure, should not be excluded yet
	if excluded {
		t.Error("Participant should not be excluded after single failure")
	}
}

// TestCoordinator_AuthenticateCommitment_TracksMisbehavior tests that authentication failures are tracked.
func TestCoordinator_AuthenticateCommitment_TracksMisbehavior(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create reputation tracker
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	// Create coordinator with authenticator and reputation tracker
	coord := NewCoordinatorWithSecurity(suite, nil, nil, nil, auth, reputationTracker)

	// Create commitment
	hiding, _ := grp.RandomScalar()
	binding, _ := grp.RandomScalar()
	commitment := frost.SigningCommitments{
		HidingNonceCommitment:  grp.ScalarBaseMult(hiding),
		BindingNonceCommitment: grp.ScalarBaseMult(binding),
	}

	// Use invalid proof (random bytes)
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	// Authenticate commitment with invalid proof - should fail and track misbehavior
	c := coord.(*coordinator)
	err = c.AuthenticateCommitment(participantID, commitment, invalidProof)
	if err == nil {
		t.Fatal("Expected authentication to fail with invalid proof")
	}

	// Verify misbehavior was tracked (but not excluded yet)
	excluded, err := reputationTracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("Failed to check exclusion: %v", err)
	}
	if excluded {
		t.Error("Participant should not be excluded after single auth failure")
	}
}

// TestCoordinator_AuthenticateSignatureShare_TracksMisbehavior tests that share authentication failures are tracked.
func TestCoordinator_AuthenticateSignatureShare_TracksMisbehavior(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()

	// Generate Ed25519 keypair for participant
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create authenticator with participant's public key
	participantID := frost.Identifier(1)
	auth := security.NewEd25519Authenticator(map[frost.Identifier]ed25519.PublicKey{
		participantID: pubKey,
	})

	// Create reputation tracker
	reputationConfig := security.DefaultReputationConfig()
	reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

	// Create coordinator with authenticator and reputation tracker
	coord := NewCoordinatorWithSecurity(suite, nil, nil, nil, auth, reputationTracker)

	// Create signature share
	shareScalar, _ := grp.RandomScalar()
	share := frost.SignatureShare{
		Identifier:     participantID,
		SignatureShare: shareScalar,
	}

	// Use invalid proof (random bytes)
	invalidProof := make([]byte, ed25519.SignatureSize)
	rand.Read(invalidProof)

	// Authenticate signature share with invalid proof - should fail and track misbehavior
	c := coord.(*coordinator)
	err = c.AuthenticateSignatureShare(participantID, share, invalidProof)
	if err == nil {
		t.Fatal("Expected authentication to fail with invalid proof")
	}

	// Verify misbehavior was tracked (but not excluded yet)
	excluded, err := reputationTracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("Failed to check exclusion: %v", err)
	}
	if excluded {
		t.Error("Participant should not be excluded after single auth failure")
	}
}

// TestCoordinator_NewCoordinatorWithPublicKey tests the public key constructor
func TestCoordinator_NewCoordinatorWithPublicKey(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	groupPublicKey := grp.Generator()

	participants := make(map[frost.Identifier]Participant)
	aggregator := NewAggregator(suite, 2)

	coord := NewCoordinatorWithPublicKey(suite, participants, aggregator, groupPublicKey)
	if coord == nil {
		t.Fatal("NewCoordinatorWithPublicKey returned nil")
	}

	c := coord.(*coordinator)
	if !c.groupPublicKey.Equal(groupPublicKey) {
		t.Error("Coordinator should have correct group public key")
	}
}

// TestCoordinator_NewCoordinatorWithAuthenticator tests the authenticator constructor
func TestCoordinator_NewCoordinatorWithAuthenticator(t *testing.T) {
	suite := testutil.NewMockCiphersuite()
	grp := suite.Group()
	groupPublicKey := grp.Generator()

	participants := make(map[frost.Identifier]Participant)
	aggregator := NewAggregator(suite, 2)
	auth := security.NewNoOpAuthenticator()

	coord := NewCoordinatorWithAuthenticator(suite, participants, aggregator, groupPublicKey, auth)
	if coord == nil {
		t.Fatal("NewCoordinatorWithAuthenticator returned nil")
	}

	c := coord.(*coordinator)
	if c.authenticator == nil {
		t.Error("Coordinator should have authenticator")
	}
}

// TestNewCoordinator tests the basic NewCoordinator constructor
func TestNewCoordinator(t *testing.T) {
	suite := testutil.NewMockCiphersuite()

	participants := make(map[frost.Identifier]Participant)
	aggregator := NewAggregator(suite, 2)

	coord := NewCoordinator(suite, participants, aggregator)
	if coord == nil {
		t.Fatal("NewCoordinator returned nil")
	}

	c := coord.(*coordinator)
	if c.suite != suite {
		t.Error("Coordinator should have correct ciphersuite")
	}
	if c.aggregator == nil {
		t.Error("Coordinator should have aggregator")
	}
}
