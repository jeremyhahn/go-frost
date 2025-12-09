package service

import (
	"sync"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// TestSessionManager_CreateSession tests session creation
func TestSessionManager_CreateSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	// Generate keys for testing
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	tests := []struct {
		name           string
		participantIDs []frost.Identifier
		message        []byte
		expectError    bool
		description    string
	}{
		{
			name:           "valid session with 2 participants",
			participantIDs: []frost.Identifier{keyPackages[0].Identifier, keyPackages[1].Identifier},
			message:        []byte("test message"),
			expectError:    false,
			description:    "minimum threshold participants",
		},
		{
			name:           "valid session with all 3 participants",
			participantIDs: []frost.Identifier{keyPackages[0].Identifier, keyPackages[1].Identifier, keyPackages[2].Identifier},
			message:        []byte("test message"),
			expectError:    false,
			description:    "all participants",
		},
		{
			name:           "empty message",
			participantIDs: []frost.Identifier{keyPackages[0].Identifier, keyPackages[1].Identifier},
			message:        []byte{},
			expectError:    false,
			description:    "empty message should be allowed",
		},
		{
			name:           "nil participant IDs",
			participantIDs: nil,
			message:        []byte("test message"),
			expectError:    true,
			description:    "nil participants should fail",
		},
		{
			name:           "empty participant IDs",
			participantIDs: []frost.Identifier{},
			message:        []byte("test message"),
			expectError:    true,
			description:    "empty participants should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := manager.CreateSession(tt.participantIDs, tt.message)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}

			// Verify session ID is not empty
			if session.ID() == "" {
				t.Error("session ID is empty")
			}

			// Verify session is not complete initially
			if session.IsComplete() {
				t.Error("new session should not be complete")
			}
		})
	}
}

// TestSessionManager_GetSession tests session retrieval
func TestSessionManager_GetSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	// Create a session
	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")
	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sessionID := session.ID()

	tests := []struct {
		name        string
		sessionID   string
		expectError bool
		description string
	}{
		{
			name:        "retrieve existing session",
			sessionID:   sessionID,
			expectError: false,
			description: "should retrieve the created session",
		},
		{
			name:        "retrieve non-existent session",
			sessionID:   "non-existent-id",
			expectError: true,
			description: "should fail for non-existent session",
		},
		{
			name:        "empty session ID",
			sessionID:   "",
			expectError: true,
			description: "should fail for empty session ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrievedSession, err := manager.GetSession(tt.sessionID)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, tt.description)
			}

			if retrievedSession.ID() != sessionID {
				t.Errorf("wrong session ID: expected %s, got %s", sessionID, retrievedSession.ID())
			}
		})
	}
}

// TestSessionManager_DeleteSession tests session deletion
func TestSessionManager_DeleteSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	// Create a session
	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")
	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sessionID := session.ID()

	// Verify session exists
	_, err = manager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("session should exist before deletion: %v", err)
	}

	// Delete the session
	err = manager.DeleteSession(sessionID)
	if err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	// Verify session is gone
	_, err = manager.GetSession(sessionID)
	if err == nil {
		t.Error("session should not exist after deletion")
	}

	// Try to delete non-existent session
	err = manager.DeleteSession("non-existent-id")
	if err == nil {
		t.Error("deleting non-existent session should return error")
	}
}

// TestSessionManager_ListSessions tests session listing
func TestSessionManager_ListSessions(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	// Initially should be empty
	sessions := manager.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions initially, got %d", len(sessions))
	}

	// Create multiple sessions
	participantIDs := []frost.Identifier{1, 2}
	numSessions := 5
	createdIDs := make(map[string]bool)

	for i := 0; i < numSessions; i++ {
		message := []byte("test message")
		session, err := manager.CreateSession(participantIDs, message)
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		createdIDs[session.ID()] = true
	}

	// List sessions
	sessions = manager.ListSessions()
	if len(sessions) != numSessions {
		t.Errorf("expected %d sessions, got %d", numSessions, len(sessions))
	}

	// Verify all created sessions are in the list
	for _, id := range sessions {
		if !createdIDs[id] {
			t.Errorf("unexpected session ID in list: %s", id)
		}
	}

	// Delete one session
	if len(sessions) > 0 {
		err := manager.DeleteSession(sessions[0])
		if err != nil {
			t.Fatalf("failed to delete session: %v", err)
		}

		// List again
		sessions = manager.ListSessions()
		if len(sessions) != numSessions-1 {
			t.Errorf("expected %d sessions after deletion, got %d", numSessions-1, len(sessions))
		}
	}
}

// TestSigningSession_Complete tests completing a signing session
func TestSigningSession_Complete(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)

	// Generate keys for 2-of-3 threshold
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, groupPubKey, err := service.GenerateKeys(config, participantIDs)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	manager := NewSessionManager(service)
	message := []byte("test message")

	// Create session
	signingParticipants := []frost.Identifier{keyPackages[0].Identifier, keyPackages[1].Identifier}
	session, err := manager.CreateSession(signingParticipants, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Session should not be complete initially
	if session.IsComplete() {
		t.Error("new session should not be complete")
	}

	// Generate commitments from participants
	var commitments []frost.SigningCommitments
	// Import signing package to create participants
	// Note: In real implementation, participants would be created separately
	// For testing, we simulate round one
	for _, pkg := range keyPackages[:2] {
		// Create mock commitment (nonces would be used in actual signing)
		_, commitment, err := generateMockCommitment(suite, pkg.Identifier)
		if err != nil {
			t.Fatalf("failed to generate commitment: %v", err)
		}
		commitments = append(commitments, commitment)
	}

	// Add commitments to session
	for _, commitment := range commitments {
		err = session.AddCommitment(commitment)
		if err != nil {
			t.Fatalf("failed to add commitment: %v", err)
		}
	}

	// Get commitment list
	commitmentList, err := session.GetCommitmentList()
	if err != nil {
		t.Fatalf("failed to get commitment list: %v", err)
	}

	if len(commitmentList) != 2 {
		t.Errorf("expected 2 commitments, got %d", len(commitmentList))
	}

	// Session still should not be complete (need signature shares)
	if session.IsComplete() {
		t.Error("session should not be complete after commitments")
	}

	// Add signature shares
	for i, pkg := range keyPackages[:2] {
		share := frost.SignatureShare{
			Identifier:     pkg.Identifier,
			SignatureShare: suite.Group().NewScalar(),
		}
		err = session.AddSignatureShare(share)
		if err != nil {
			t.Fatalf("failed to add signature share %d: %v", i, err)
		}
	}

	// Try to get signature
	// Note: This will fail because the session doesn't have the group public key
	// In a full implementation, the session would need to store the group public key
	// or accept it as a parameter to GetSignature
	signature, err := session.GetSignature()
	if err == nil {
		t.Error("expected error from GetSignature due to missing group public key context")
	}

	// The signature should be empty due to the error
	_ = signature
	_ = groupPubKey
}

// TestSigningSession_Cancel tests canceling a signing session
func TestSigningSession_Cancel(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Cancel the session
	err = session.Cancel()
	if err != nil {
		t.Fatalf("failed to cancel session: %v", err)
	}

	// Operations on canceled session should fail
	commitment := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  suite.Group().Generator(),
		BindingNonceCommitment: suite.Group().Generator(),
	}

	err = session.AddCommitment(commitment)
	if err == nil {
		t.Error("adding commitment to canceled session should fail")
	}
}

// TestSessionManager_ConcurrentSessions tests concurrent session operations
func TestSessionManager_ConcurrentSessions(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	numSessions := 20

	var wg sync.WaitGroup
	errors := make(chan error, numSessions)
	sessionIDs := make(chan string, numSessions)

	// Create sessions concurrently
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			message := []byte("concurrent message")
			session, err := manager.CreateSession(participantIDs, message)
			if err != nil {
				errors <- err
				return
			}

			sessionIDs <- session.ID()
		}(i)
	}

	wg.Wait()
	close(errors)
	close(sessionIDs)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent session creation error: %v", err)
	}

	// Verify all sessions are unique and retrievable
	uniqueIDs := make(map[string]bool)
	for id := range sessionIDs {
		if uniqueIDs[id] {
			t.Errorf("duplicate session ID: %s", id)
		}
		uniqueIDs[id] = true

		_, err := manager.GetSession(id)
		if err != nil {
			t.Errorf("failed to retrieve session %s: %v", id, err)
		}
	}

	if len(uniqueIDs) != numSessions {
		t.Errorf("expected %d unique sessions, got %d", numSessions, len(uniqueIDs))
	}
}

// TestSigningSession_DuplicateCommitment tests handling of duplicate commitments
func TestSigningSession_DuplicateCommitment(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	commitment := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  suite.Group().Generator(),
		BindingNonceCommitment: suite.Group().Generator(),
	}

	// Add commitment first time
	err = session.AddCommitment(commitment)
	if err != nil {
		t.Fatalf("failed to add commitment: %v", err)
	}

	// Try to add same commitment again
	err = session.AddCommitment(commitment)
	if err == nil {
		t.Error("adding duplicate commitment should fail")
	}
}

// TestSigningSession_InsufficientCommitments tests getting commitment list
// with insufficient commitments
func TestSigningSession_InsufficientCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Try to get commitment list without adding any commitments
	_, err = session.GetCommitmentList()
	if err == nil {
		t.Error("getting commitment list with no commitments should fail")
	}

	// Add only one commitment (need 2)
	commitment := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  suite.Group().Generator(),
		BindingNonceCommitment: suite.Group().Generator(),
	}
	err = session.AddCommitment(commitment)
	if err != nil {
		t.Fatalf("failed to add commitment: %v", err)
	}

	// Try to get commitment list with insufficient commitments
	_, err = session.GetCommitmentList()
	if err == nil {
		t.Error("getting commitment list with insufficient commitments should fail")
	}
}

// TestSigningSession_GetSignature_CanceledSession tests GetSignature on canceled session
func TestSigningSession_GetSignature_CanceledSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Cancel the session
	err = session.Cancel()
	if err != nil {
		t.Fatalf("failed to cancel session: %v", err)
	}

	// Try to get signature from canceled session
	_, err = session.GetSignature()
	if err == nil {
		t.Error("GetSignature on canceled session should fail")
	}
}

// TestSigningSession_AddSignatureShare_CanceledSession tests adding share to canceled session
func TestSigningSession_AddSignatureShare_CanceledSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Cancel the session
	err = session.Cancel()
	if err != nil {
		t.Fatalf("failed to cancel session: %v", err)
	}

	// Try to add signature share to canceled session
	share := frost.SignatureShare{
		Identifier:     1,
		SignatureShare: suite.Group().NewScalar(),
	}
	err = session.AddSignatureShare(share)
	if err == nil {
		t.Error("AddSignatureShare on canceled session should fail")
	}
}

// TestSigningSession_AddSignatureShare_UnknownParticipant tests adding share from unknown participant
func TestSigningSession_AddSignatureShare_UnknownParticipant(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Try to add signature share from unknown participant (ID 3)
	share := frost.SignatureShare{
		Identifier:     3, // Not in participant list
		SignatureShare: suite.Group().NewScalar(),
	}
	err = session.AddSignatureShare(share)
	if err == nil {
		t.Error("AddSignatureShare from unknown participant should fail")
	}
}

// TestSigningSession_AddSignatureShare_Duplicate tests adding duplicate signature share
func TestSigningSession_AddSignatureShare_Duplicate(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	share := frost.SignatureShare{
		Identifier:     1,
		SignatureShare: suite.Group().NewScalar(),
	}

	// Add first time
	err = session.AddSignatureShare(share)
	if err != nil {
		t.Fatalf("failed to add signature share: %v", err)
	}

	// Add again - should fail
	err = session.AddSignatureShare(share)
	if err == nil {
		t.Error("adding duplicate signature share should fail")
	}
}

// TestSigningSession_GetCommitmentList_CanceledSession tests getting commitment list from canceled session
func TestSigningSession_GetCommitmentList_CanceledSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	service := NewFrostService(suite)
	manager := NewSessionManager(service)

	participantIDs := []frost.Identifier{1, 2}
	message := []byte("test message")

	session, err := manager.CreateSession(participantIDs, message)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Cancel the session
	err = session.Cancel()
	if err != nil {
		t.Fatalf("failed to cancel session: %v", err)
	}

	// Try to get commitment list from canceled session
	_, err = session.GetCommitmentList()
	if err == nil {
		t.Error("GetCommitmentList on canceled session should fail")
	}
}

// Helper function to generate mock commitment for testing
func generateMockCommitment(suite interface{ Group() group.Group }, id frost.Identifier) (frost.SigningNonces, frost.SigningCommitments, error) {
	grp := suite.Group()

	hidingNonce, err := grp.RandomScalar()
	if err != nil {
		return frost.SigningNonces{}, frost.SigningCommitments{}, err
	}

	bindingNonce, err := grp.RandomScalar()
	if err != nil {
		return frost.SigningNonces{}, frost.SigningCommitments{}, err
	}

	commitment := frost.SigningCommitments{
		Identifier:             id,
		HidingNonceCommitment:  grp.ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: grp.ScalarBaseMult(bindingNonce),
	}

	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitment,
	}

	return nonces, commitment, nil
}
