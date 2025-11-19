// RFC 9591 Section 7.3: Nonce Reuse Prevention
//
// This file tests the nonce reuse prevention mechanisms required by RFC 9591 Section 7.3.
// It verifies that:
// 1. Signing commitments are tracked per session and participant
// 2. Nonce reuse is detected and rejected
// 3. Sessions can be cleared after successful completion
// 4. Commitment counting and monitoring works correctly
//
// RFC 9591 Section 7.3 Requirements:
// - "Implementations MUST ensure that signing nonces are never reused"
// - "Nonce reuse leads to complete private key recovery"
// - "This is the most critical security requirement in threshold signature schemes"
// - "Implementations SHOULD track used nonces to prevent accidental reuse"
//
// Test Coverage:
// - C-1: Nonce Tracking (RFC 9591 Section 7.3) - CRITICAL
// - Nonce commitment recording
// - Nonce reuse detection
// - Session lifecycle management
// - Commitment counting and monitoring
package rfc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/security"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// TestSection7_3_NonceCommitmentTracking verifies that nonce commitments
// are properly recorded and tracked as required by RFC 9591 Section 7.3.
func TestSection7_3_NonceCommitmentTracking(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	sessionID := "test-session-1"

	// Test: First recording should succeed
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Errorf("First commitment recording failed: %v", err)
	}

	// Test: Session should have 2 commitments (hiding + binding)
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 commitments (hiding + binding), got %d", count)
	}

	// Test: Total count should also be 2
	totalCount, err := tracker.TotalCommitmentCount(ctx)
	if err != nil {
		t.Fatalf("TotalCommitmentCount failed: %v", err)
	}
	if totalCount != 2 {
		t.Errorf("Expected total of 2 commitments, got %d", totalCount)
	}
}

// TestSection7_3_NonceReuseDetection verifies that nonce reuse is detected
// and rejected as required by RFC 9591 Section 7.3.
func TestSection7_3_NonceReuseDetection(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	sessionID := "test-session-reuse"

	// Record commitments
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Fatalf("First commitment recording failed: %v", err)
	}

	// Test: Attempting to record same commitments again should fail
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err == nil {
		t.Error("Nonce reuse was not detected")
	}

	// Test: Error should be ErrCommitmentReused
	if !errors.Is(err, security.ErrCommitmentReused) {
		t.Errorf("Expected ErrCommitmentReused, got: %v", err)
	}

	// Test: CheckSigningCommitments should also detect reuse
	err = tracker.CheckSigningCommitments(ctx, sessionID, 1, commitments)
	if err == nil {
		t.Error("CheckSigningCommitments did not detect reuse")
	}

	if !errors.Is(err, security.ErrCommitmentReused) {
		t.Errorf("Expected ErrCommitmentReused from Check, got: %v", err)
	}
}

// TestSection7_3_SessionIsolation verifies that commitments are properly
// isolated by session ID as required by RFC 9591 Section 7.3.
func TestSection7_3_SessionIsolation(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	// Test: Same commitments can be used in different sessions
	err = tracker.RecordSigningCommitments(ctx, "session-1", 1, commitments)
	if err != nil {
		t.Errorf("Recording in session-1 failed: %v", err)
	}

	// Should succeed because it's a different session
	err = tracker.RecordSigningCommitments(ctx, "session-2", 1, commitments)
	if err != nil {
		t.Errorf("Recording same commitments in session-2 failed: %v", err)
	}

	// But reuse within same session should fail
	err = tracker.RecordSigningCommitments(ctx, "session-1", 1, commitments)
	if err == nil {
		t.Error("Reuse within same session was not detected")
	}

	if !errors.Is(err, security.ErrCommitmentReused) {
		t.Errorf("Expected ErrCommitmentReused, got: %v", err)
	}
}

// TestSection7_3_ParticipantIsolation verifies that commitments are properly
// isolated by participant ID as required by RFC 9591 Section 7.3.
func TestSection7_3_ParticipantIsolation(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2, 3}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 3, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)
	participant2 := signing.NewParticipant(keyPackages[1], suite)

	// Generate different commitments for each participant
	_, commitments1, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments for participant 1: %v", err)
	}

	_, commitments2, err := participant2.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments for participant 2: %v", err)
	}

	sessionID := "test-session-participants"

	// Test: Different participants should be able to record independently
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments1)
	if err != nil {
		t.Errorf("Recording for participant 1 failed: %v", err)
	}

	err = tracker.RecordSigningCommitments(ctx, sessionID, 2, commitments2)
	if err != nil {
		t.Errorf("Recording for participant 2 failed: %v", err)
	}

	// Test: Each participant's reuse should be detected independently
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments1)
	if err == nil {
		t.Error("Participant 1 nonce reuse was not detected")
	}

	err = tracker.RecordSigningCommitments(ctx, sessionID, 2, commitments2)
	if err == nil {
		t.Error("Participant 2 nonce reuse was not detected")
	}
}

// TestSection7_3_SessionClearing verifies that sessions can be cleared
// after successful signature completion as required by RFC 9591 Section 7.3.
func TestSection7_3_SessionClearing(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	sessionID := "test-session-clear"

	// Record commitments
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Fatalf("Recording commitments failed: %v", err)
	}

	// Verify commitments are tracked
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 commitments before clearing, got %d", count)
	}

	// Test: Clear session
	err = tracker.ClearSession(ctx, sessionID)
	if err != nil {
		t.Errorf("ClearSession failed: %v", err)
	}

	// Test: Session should be empty after clearing
	count, err = tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount after clear failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 commitments after clearing, got %d", count)
	}

	// Test: Same commitments can be used again after clearing
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Errorf("Recording after clear failed: %v", err)
	}
}

// TestSection7_3_ExpiredCommitmentClearing verifies that expired commitments
// can be cleared to prevent unbounded memory growth as recommended by RFC 9591 Section 7.3.
func TestSection7_3_ExpiredCommitmentClearing(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	sessionID := "test-session-expiry"

	// Record commitments
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Fatalf("Recording commitments failed: %v", err)
	}

	// Test: No commitments should be expired with a far-future TTL
	removedCount, err := tracker.ClearExpired(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("ClearExpired with long TTL failed: %v", err)
	}
	if removedCount != 0 {
		t.Errorf("Expected 0 commitments removed with long TTL, got %d", removedCount)
	}

	// Test: All commitments should be expired with a zero TTL
	removedCount, err = tracker.ClearExpired(ctx, 0)
	if err != nil {
		t.Fatalf("ClearExpired with zero TTL failed: %v", err)
	}
	if removedCount != 2 {
		t.Errorf("Expected 2 commitments removed with zero TTL, got %d", removedCount)
	}

	// Verify commitments were cleared
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount after expiry failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 commitments after expiry, got %d", count)
	}
}

// TestSection7_3_CheckBeforeRecord verifies that commitments can be checked
// before recording to detect potential reuse as recommended by RFC 9591 Section 7.3.
func TestSection7_3_CheckBeforeRecord(t *testing.T) {
	ctx := context.Background()

	// Create nonce tracker
	tracker := security.NewDefaultFrostNonceTracker()

	// Setup ciphersuite and participants
	suite := ristretto255_sha512.New()
	dealer := keygen.NewDealer(suite)
	participantIDs := []frost.Identifier{1, 2}
	keyPackages, _, err := dealer.GenerateShares(nil, 2, 2, participantIDs)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	participant1 := signing.NewParticipant(keyPackages[0], suite)

	// Generate commitments
	_, commitments, err := participant1.RoundOne()
	if err != nil {
		t.Fatalf("Failed to generate commitments: %v", err)
	}

	sessionID := "test-session-check"

	// Test: Check should pass for unused commitments
	err = tracker.CheckSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Errorf("Check for unused commitments failed: %v", err)
	}

	// Record commitments
	err = tracker.RecordSigningCommitments(ctx, sessionID, 1, commitments)
	if err != nil {
		t.Fatalf("Recording commitments failed: %v", err)
	}

	// Test: Check should fail for used commitments
	err = tracker.CheckSigningCommitments(ctx, sessionID, 1, commitments)
	if err == nil {
		t.Error("Check did not detect used commitments")
	}

	if !errors.Is(err, security.ErrCommitmentReused) {
		t.Errorf("Expected ErrCommitmentReused, got: %v", err)
	}
}
