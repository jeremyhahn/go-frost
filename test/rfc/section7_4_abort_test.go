// RFC 9591 Section 7.4: Protocol Failures and Abort (Misbehavior Tracking)
//
// This file tests the misbehavior tracking and participant exclusion mechanisms
// required by RFC 9591 Section 7.4.
// It verifies that:
// 1. Participant misbehavior is recorded and tracked
// 2. Automatic exclusion occurs after threshold violations
// 3. Manual exclusion and reinstatement work correctly
// 4. Misbehavior history can be queried
// 5. Old records can be cleaned up
//
// RFC 9591 Section 7.4 Requirements:
// - "Implementations SHOULD track participant misbehavior"
// - "Participants who repeatedly misbehave SHOULD be excluded from future operations"
// - "The protocol MUST abort if insufficient participants remain"
// - "Implementations SHOULD support identifiable abort to detect malicious parties"
//
// Test Coverage:
// - H-3: Identifiable Abort (RFC 9591 Section 7.4)
// - M-5: Misbehavior Tracking (RFC 9591 Section 7.4)
// - Automatic exclusion after threshold violations
// - Manual exclusion and reinstatement
// - Reputation queries
// - History tracking and cleanup
package rfc

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// TestSection7_4_MisbehaviorRecording verifies that misbehavior is properly
// recorded and tracked as required by RFC 9591 Section 7.4.
func TestSection7_4_MisbehaviorRecording(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(1)

	// Test: Record authentication failure
	err := tracker.RecordMisbehavior(participantID, security.MisbehaviorAuthenticationFailure, "invalid signature")
	if err != nil {
		t.Fatalf("Failed to record authentication failure: %v", err)
	}

	// Test: Get reputation
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("Failed to get reputation: %v", err)
	}

	if rep.AuthenticationFailures != 1 {
		t.Errorf("Expected 1 authentication failure, got %d", rep.AuthenticationFailures)
	}

	if rep.TotalViolations() != 1 {
		t.Errorf("Expected 1 total violation, got %d", rep.TotalViolations())
	}

	// Test: Record invalid share
	err = tracker.RecordMisbehavior(participantID, security.MisbehaviorInvalidShare, "share verification failed")
	if err != nil {
		t.Fatalf("Failed to record invalid share: %v", err)
	}

	rep, err = tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("Failed to get reputation after second violation: %v", err)
	}

	if rep.InvalidShares != 1 {
		t.Errorf("Expected 1 invalid share, got %d", rep.InvalidShares)
	}

	if rep.TotalViolations() != 2 {
		t.Errorf("Expected 2 total violations, got %d", rep.TotalViolations())
	}
}

// TestSection7_4_AutomaticExclusionAuthFailure verifies that participants
// are automatically excluded after exceeding authentication failure threshold
// as required by RFC 9591 Section 7.4.
func TestSection7_4_AutomaticExclusionAuthFailure(t *testing.T) {
	config := security.DefaultReputationConfig()
	// Default MaxAuthenticationFailures is 3
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(1)

	// Record failures below threshold - should not be excluded
	for i := 0; i < 2; i++ {
		err := tracker.RecordMisbehavior(participantID, security.MisbehaviorAuthenticationFailure, "test failure")
		if err != nil {
			t.Fatalf("Failed to record misbehavior %d: %v", i, err)
		}
	}

	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if excluded {
		t.Error("Participant was excluded below threshold")
	}

	// Record failure that reaches threshold - should be excluded
	err = tracker.RecordMisbehavior(participantID, security.MisbehaviorAuthenticationFailure, "threshold reached")
	if err != nil {
		t.Fatalf("Failed to record threshold violation: %v", err)
	}

	excluded, err = tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded after threshold failed: %v", err)
	}
	if !excluded {
		t.Error("Participant was not excluded after reaching threshold")
	}

	// Verify reputation shows exclusion
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation failed: %v", err)
	}

	if !rep.Excluded {
		t.Error("Reputation does not show excluded status")
	}

	if rep.ExclusionReason == "" {
		t.Error("Exclusion reason is empty")
	}
}

// TestSection7_4_AutomaticExclusionNonceReuse verifies that participants
// are automatically excluded after nonce reuse as required by RFC 9591 Section 7.4.
// Nonce reuse is critical and should have a very low threshold (default: 1).
func TestSection7_4_AutomaticExclusionNonceReuse(t *testing.T) {
	config := security.DefaultReputationConfig()
	// Default MaxNonceReuses is 1 (immediate exclusion)
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(1)

	// Test: Single nonce reuse should trigger exclusion
	err := tracker.RecordMisbehavior(participantID, security.MisbehaviorNonceReuse, "CRITICAL: nonce reused")
	if err != nil {
		t.Fatalf("Failed to record nonce reuse: %v", err)
	}

	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if !excluded {
		t.Error("Participant was not immediately excluded after nonce reuse")
	}

	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation failed: %v", err)
	}

	if rep.NonceReuses != 1 {
		t.Errorf("Expected 1 nonce reuse, got %d", rep.NonceReuses)
	}
}

// TestSection7_4_AutomaticExclusionInvalidShares verifies that participants
// are automatically excluded after exceeding invalid share threshold
// as required by RFC 9591 Section 7.4.
func TestSection7_4_AutomaticExclusionInvalidShares(t *testing.T) {
	config := security.DefaultReputationConfig()
	// Default MaxInvalidShares is 2
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(2)

	// Record one invalid share - should not be excluded
	err := tracker.RecordMisbehavior(participantID, security.MisbehaviorInvalidShare, "first invalid share")
	if err != nil {
		t.Fatalf("Failed to record first invalid share: %v", err)
	}

	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if excluded {
		t.Error("Participant was excluded below threshold")
	}

	// Record second invalid share - should trigger exclusion
	err = tracker.RecordMisbehavior(participantID, security.MisbehaviorInvalidShare, "second invalid share")
	if err != nil {
		t.Fatalf("Failed to record second invalid share: %v", err)
	}

	excluded, err = tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded after threshold failed: %v", err)
	}
	if !excluded {
		t.Error("Participant was not excluded after reaching threshold")
	}
}

// TestSection7_4_ManualExclusion verifies that participants can be manually
// excluded from operations as required by RFC 9591 Section 7.4.
func TestSection7_4_ManualExclusion(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(3)

	// Test: Manually exclude participant
	err := tracker.ExcludeParticipant(participantID, "administrative decision")
	if err != nil {
		t.Fatalf("Failed to exclude participant: %v", err)
	}

	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if !excluded {
		t.Error("Participant was not excluded after manual exclusion")
	}

	// Verify reputation
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation failed: %v", err)
	}

	if !rep.Excluded {
		t.Error("Reputation does not show excluded status")
	}

	if rep.ExclusionReason != "administrative decision" {
		t.Errorf("Expected exclusion reason 'administrative decision', got '%s'", rep.ExclusionReason)
	}
}

// TestSection7_4_ParticipantReinstatement verifies that excluded participants
// can be reinstated as required by RFC 9591 Section 7.4.
func TestSection7_4_ParticipantReinstatement(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(4)

	// Exclude participant
	err := tracker.ExcludeParticipant(participantID, "test exclusion")
	if err != nil {
		t.Fatalf("Failed to exclude participant: %v", err)
	}

	// Verify exclusion
	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if !excluded {
		t.Error("Participant was not excluded")
	}

	// Test: Reinstate participant
	err = tracker.ReinstateParticipant(participantID)
	if err != nil {
		t.Fatalf("Failed to reinstate participant: %v", err)
	}

	// Verify reinstatement
	excluded, err = tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded after reinstatement failed: %v", err)
	}
	if excluded {
		t.Error("Participant is still excluded after reinstatement")
	}

	// Verify reputation updated
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation after reinstatement failed: %v", err)
	}

	if rep.Excluded {
		t.Error("Reputation still shows excluded status after reinstatement")
	}

	if rep.ExclusionReason != "" {
		t.Error("Exclusion reason not cleared after reinstatement")
	}
}

// TestSection7_4_MisbehaviorHistory verifies that misbehavior history
// can be queried as required by RFC 9591 Section 7.4.
func TestSection7_4_MisbehaviorHistory(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(5)

	// Record multiple misbehaviors
	misbehaviors := []struct {
		mtype   security.MisbehaviorType
		details string
	}{
		{security.MisbehaviorAuthenticationFailure, "auth failure 1"},
		{security.MisbehaviorInvalidShare, "invalid share 1"},
		{security.MisbehaviorTimeout, "timeout 1"},
	}

	for _, m := range misbehaviors {
		err := tracker.RecordMisbehavior(participantID, m.mtype, m.details)
		if err != nil {
			t.Fatalf("Failed to record misbehavior: %v", err)
		}
	}

	// Test: Get all history (limit = 0)
	history, err := tracker.GetMisbehaviorHistory(participantID, 0)
	if err != nil {
		t.Fatalf("Failed to get misbehavior history: %v", err)
	}

	if len(history) != 3 {
		t.Errorf("Expected 3 history records, got %d", len(history))
	}

	// Test: Get limited history
	limitedHistory, err := tracker.GetMisbehaviorHistory(participantID, 2)
	if err != nil {
		t.Fatalf("Failed to get limited history: %v", err)
	}

	if len(limitedHistory) != 2 {
		t.Errorf("Expected 2 history records with limit, got %d", len(limitedHistory))
	}

	// Test: Verify history contains correct types
	authFailureFound := false
	for _, record := range history {
		if record.Type == security.MisbehaviorAuthenticationFailure {
			authFailureFound = true
			if record.Details != "auth failure 1" {
				t.Errorf("Expected details 'auth failure 1', got '%s'", record.Details)
			}
		}
	}
	if !authFailureFound {
		t.Error("Authentication failure not found in history")
	}
}

// TestSection7_4_MultipleParticipants verifies that misbehavior tracking
// works correctly for multiple participants as required by RFC 9591 Section 7.4.
func TestSection7_4_MultipleParticipants(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	// Test: Track multiple participants independently
	for i := 1; i <= 3; i++ {
		participantID := frost.Identifier(i)

		// Record different violations for each participant
		err := tracker.RecordMisbehavior(participantID, security.MisbehaviorTimeout, "timeout")
		if err != nil {
			t.Fatalf("Failed to record misbehavior for participant %d: %v", i, err)
		}
	}

	// Verify each participant has independent tracking
	for i := 1; i <= 3; i++ {
		participantID := frost.Identifier(i)

		rep, err := tracker.GetReputation(participantID)
		if err != nil {
			t.Fatalf("Failed to get reputation for participant %d: %v", i, err)
		}

		if rep.Timeouts != 1 {
			t.Errorf("Participant %d: expected 1 timeout, got %d", i, rep.Timeouts)
		}

		if rep.TotalViolations() != 1 {
			t.Errorf("Participant %d: expected 1 total violation, got %d", i, rep.TotalViolations())
		}
	}
}

// TestSection7_4_HistoryCleanup verifies that old misbehavior records
// can be cleaned up as recommended by RFC 9591 Section 7.4.
func TestSection7_4_HistoryCleanup(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(6)

	// Record some misbehaviors
	err := tracker.RecordMisbehavior(participantID, security.MisbehaviorTimeout, "old timeout")
	if err != nil {
		t.Fatalf("Failed to record misbehavior: %v", err)
	}

	// Verify history exists
	history, err := tracker.GetMisbehaviorHistory(participantID, 0)
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	if len(history) != 1 {
		t.Errorf("Expected 1 history record, got %d", len(history))
	}

	// Test: Cleanup with far-future maxAge - should remove nothing
	removed, err := tracker.CleanupOldRecords(24 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldRecords failed: %v", err)
	}

	if removed != 0 {
		t.Errorf("Expected 0 records removed with long maxAge, got %d", removed)
	}

	// Test: Cleanup with very small maxAge after brief sleep - should remove old records
	time.Sleep(2 * time.Millisecond)
	removed, err = tracker.CleanupOldRecords(1 * time.Millisecond)
	if err != nil {
		t.Fatalf("CleanupOldRecords with small maxAge failed: %v", err)
	}

	if removed != 1 {
		t.Errorf("Expected 1 record removed, got %d", removed)
	}

	// Verify history was cleared
	_, err = tracker.GetMisbehaviorHistory(participantID, 0)
	if err != security.ErrParticipantNotFound {
		t.Error("Expected ErrParticipantNotFound after cleanup, history should be gone")
	}
}

// TestSection7_4_UnknownParticipantQueries verifies that queries for
// unknown participants are handled correctly as required by RFC 9591 Section 7.4.
func TestSection7_4_UnknownParticipantQueries(t *testing.T) {
	config := security.DefaultReputationConfig()
	tracker := security.NewInMemoryReputationTracker(config)

	unknownID := frost.Identifier(999)

	// Test: GetReputation for unknown participant
	_, err := tracker.GetReputation(unknownID)
	if err != security.ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound for unknown participant, got: %v", err)
	}

	// Test: IsExcluded for unknown participant (should return false, not error)
	excluded, err := tracker.IsExcluded(unknownID)
	if err != nil {
		t.Errorf("IsExcluded for unknown participant should not error, got: %v", err)
	}
	if excluded {
		t.Error("Unknown participant should not be considered excluded")
	}

	// Test: GetMisbehaviorHistory for unknown participant
	_, err = tracker.GetMisbehaviorHistory(unknownID, 0)
	if err != security.ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound for unknown participant history, got: %v", err)
	}

	// Test: ReinstateParticipant for unknown participant
	err = tracker.ReinstateParticipant(unknownID)
	if err != security.ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound for reinstating unknown participant, got: %v", err)
	}
}
