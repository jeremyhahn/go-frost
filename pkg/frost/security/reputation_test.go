// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

// TestReputationTracker_RecordMisbehavior tests basic misbehavior recording.
func TestReputationTracker_RecordMisbehavior(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(1)

	// Record authentication failure
	err := tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "invalid signature")
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	// Verify reputation was updated
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation failed: %v", err)
	}

	if rep.AuthenticationFailures != 1 {
		t.Errorf("Expected 1 authentication failure, got %d", rep.AuthenticationFailures)
	}

	if rep.TotalViolations() != 1 {
		t.Errorf("Expected 1 total violation, got %d", rep.TotalViolations())
	}

	// Record invalid share
	err = tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "share verification failed")
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	rep, _ = tracker.GetReputation(participantID)
	if rep.InvalidShares != 1 {
		t.Errorf("Expected 1 invalid share, got %d", rep.InvalidShares)
	}

	if rep.TotalViolations() != 2 {
		t.Errorf("Expected 2 total violations, got %d", rep.TotalViolations())
	}
}

// TestReputationTracker_AutomaticExclusion_AuthenticationFailures tests automatic exclusion
// after exceeding authentication failure threshold.
func TestReputationTracker_AutomaticExclusion_AuthenticationFailures(t *testing.T) {
	config := DefaultReputationConfig()
	config.MaxAuthenticationFailures = 3
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(1)

	// Record failures below threshold
	for i := 0; i < 2; i++ {
		err := tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "test")
		if err != nil {
			t.Fatalf("RecordMisbehavior failed: %v", err)
		}

		excluded, _ := tracker.IsExcluded(participantID)
		if excluded {
			t.Errorf("Participant should not be excluded at %d failures", i+1)
		}
	}

	// Record failure that exceeds threshold
	err := tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "test")
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	// Verify automatic exclusion
	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if !excluded {
		t.Error("Participant should be automatically excluded after threshold")
	}

	rep, _ := tracker.GetReputation(participantID)
	if !rep.Excluded {
		t.Error("Reputation record should show excluded status")
	}
	if rep.ExclusionReason == "" {
		t.Error("Exclusion reason should be set")
	}
}

// TestReputationTracker_AutomaticExclusion_InvalidShares tests automatic exclusion
// for invalid signature shares.
func TestReputationTracker_AutomaticExclusion_InvalidShares(t *testing.T) {
	config := DefaultReputationConfig()
	config.MaxInvalidShares = 2
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(2)

	// First invalid share - not excluded
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "test")
	excluded, _ := tracker.IsExcluded(participantID)
	if excluded {
		t.Error("Participant should not be excluded at 1 invalid share")
	}

	// Second invalid share - should be excluded
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "test")
	excluded, _ = tracker.IsExcluded(participantID)
	if !excluded {
		t.Error("Participant should be excluded at 2 invalid shares")
	}
}

// TestReputationTracker_AutomaticExclusion_NonceReuse tests automatic exclusion
// for nonce reuse attempts (critical security violation).
func TestReputationTracker_AutomaticExclusion_NonceReuse(t *testing.T) {
	config := DefaultReputationConfig()
	config.MaxNonceReuses = 1
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(3)

	// Single nonce reuse should trigger exclusion
	tracker.RecordMisbehavior(participantID, MisbehaviorNonceReuse, "attempted nonce reuse")

	excluded, _ := tracker.IsExcluded(participantID)
	if !excluded {
		t.Error("Participant should be immediately excluded for nonce reuse")
	}

	rep, _ := tracker.GetReputation(participantID)
	if rep.NonceReuses != 1 {
		t.Errorf("Expected 1 nonce reuse, got %d", rep.NonceReuses)
	}
}

// TestReputationTracker_AutomaticExclusion_Timeouts tests automatic exclusion
// for timeout violations.
func TestReputationTracker_AutomaticExclusion_Timeouts(t *testing.T) {
	config := DefaultReputationConfig()
	config.MaxTimeouts = 5
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(4)

	// Record timeouts below threshold
	for i := 0; i < 4; i++ {
		tracker.RecordMisbehavior(participantID, MisbehaviorTimeout, "test")
		excluded, _ := tracker.IsExcluded(participantID)
		if excluded {
			t.Errorf("Participant should not be excluded at %d timeouts", i+1)
		}
	}

	// Fifth timeout should trigger exclusion
	tracker.RecordMisbehavior(participantID, MisbehaviorTimeout, "test")
	excluded, _ := tracker.IsExcluded(participantID)
	if !excluded {
		t.Error("Participant should be excluded at 5 timeouts")
	}
}

// TestReputationTracker_ManualExclusion tests manual participant exclusion.
func TestReputationTracker_ManualExclusion(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(5)

	// Manually exclude participant
	err := tracker.ExcludeParticipant(participantID, "manual exclusion for testing")
	if err != nil {
		t.Fatalf("ExcludeParticipant failed: %v", err)
	}

	// Verify exclusion
	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded failed: %v", err)
	}
	if !excluded {
		t.Error("Participant should be excluded after manual exclusion")
	}

	rep, _ := tracker.GetReputation(participantID)
	if !rep.Excluded {
		t.Error("Reputation record should show excluded status")
	}
	if rep.ExclusionReason != "manual exclusion for testing" {
		t.Errorf("Unexpected exclusion reason: %s", rep.ExclusionReason)
	}
}

// TestReputationTracker_Reinstatement tests participant reinstatement.
func TestReputationTracker_Reinstatement(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(6)

	// Exclude participant
	tracker.ExcludeParticipant(participantID, "test exclusion")

	// Verify exclusion
	excluded, _ := tracker.IsExcluded(participantID)
	if !excluded {
		t.Fatal("Participant should be excluded")
	}

	// Reinstate participant
	err := tracker.ReinstateParticipant(participantID)
	if err != nil {
		t.Fatalf("ReinstateParticipant failed: %v", err)
	}

	// Verify reinstatement
	excluded, _ = tracker.IsExcluded(participantID)
	if excluded {
		t.Error("Participant should not be excluded after reinstatement")
	}

	rep, _ := tracker.GetReputation(participantID)
	if rep.Excluded {
		t.Error("Reputation record should not show excluded status")
	}
	if rep.ExclusionReason != "" {
		t.Error("Exclusion reason should be cleared")
	}
}

// TestReputationTracker_Reinstatement_NotFound tests reinstatement of unknown participant.
func TestReputationTracker_Reinstatement_NotFound(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(999)

	// Try to reinstate unknown participant
	err := tracker.ReinstateParticipant(participantID)
	if err != ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound, got %v", err)
	}
}

// TestReputationTracker_GetReputation_NotFound tests getting reputation for unknown participant.
func TestReputationTracker_GetReputation_NotFound(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(999)

	_, err := tracker.GetReputation(participantID)
	if err != ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound, got %v", err)
	}
}

// TestReputationTracker_IsExcluded_UnknownParticipant tests exclusion check for unknown participant.
func TestReputationTracker_IsExcluded_UnknownParticipant(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(999)

	excluded, err := tracker.IsExcluded(participantID)
	if err != nil {
		t.Fatalf("IsExcluded should not fail for unknown participant: %v", err)
	}
	if excluded {
		t.Error("Unknown participant should not be considered excluded")
	}
}

// TestReputationTracker_MisbehaviorHistory tests misbehavior history tracking.
func TestReputationTracker_MisbehaviorHistory(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(7)

	// Record multiple misbehaviors
	tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "auth failed 1")
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "invalid share 1")
	time.Sleep(10 * time.Millisecond)
	tracker.RecordMisbehavior(participantID, MisbehaviorTimeout, "timeout 1")

	// Get full history
	history, err := tracker.GetMisbehaviorHistory(participantID, 0)
	if err != nil {
		t.Fatalf("GetMisbehaviorHistory failed: %v", err)
	}

	if len(history) != 3 {
		t.Errorf("Expected 3 history records, got %d", len(history))
	}

	// Verify record details
	if history[0].Type != MisbehaviorAuthenticationFailure {
		t.Errorf("Expected first record to be authentication failure, got %v", history[0].Type)
	}
	if history[0].Details != "auth failed 1" {
		t.Errorf("Unexpected details: %s", history[0].Details)
	}

	// Get limited history
	limitedHistory, err := tracker.GetMisbehaviorHistory(participantID, 2)
	if err != nil {
		t.Fatalf("GetMisbehaviorHistory with limit failed: %v", err)
	}

	if len(limitedHistory) != 2 {
		t.Errorf("Expected 2 history records with limit, got %d", len(limitedHistory))
	}

	// Should return most recent records
	if limitedHistory[0].Type != MisbehaviorInvalidShare {
		t.Errorf("Expected most recent limited history to start with invalid share, got %v", limitedHistory[0].Type)
	}
}

// TestReputationTracker_MisbehaviorHistory_NotFound tests history for unknown participant.
func TestReputationTracker_MisbehaviorHistory_NotFound(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(999)

	_, err := tracker.GetMisbehaviorHistory(participantID, 0)
	if err != ErrParticipantNotFound {
		t.Errorf("Expected ErrParticipantNotFound, got %v", err)
	}
}

// TestReputationTracker_CleanupOldRecords tests cleanup of old misbehavior records.
func TestReputationTracker_CleanupOldRecords(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(8)

	// Record misbehavior
	tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "old record")

	// Verify record exists
	history, _ := tracker.GetMisbehaviorHistory(participantID, 0)
	if len(history) != 1 {
		t.Fatalf("Expected 1 history record, got %d", len(history))
	}

	// Cleanup records older than 1 second (should not remove anything yet)
	removed, err := tracker.CleanupOldRecords(1 * time.Second)
	if err != nil {
		t.Fatalf("CleanupOldRecords failed: %v", err)
	}
	if removed != 0 {
		t.Errorf("Expected 0 removed records, got %d", removed)
	}

	// Wait and cleanup
	time.Sleep(100 * time.Millisecond)
	removed, err = tracker.CleanupOldRecords(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("CleanupOldRecords failed: %v", err)
	}
	if removed != 1 {
		t.Errorf("Expected 1 removed record, got %d", removed)
	}

	// Verify history is now empty
	_, err = tracker.GetMisbehaviorHistory(participantID, 0)
	if err != ErrParticipantNotFound {
		t.Error("History should be removed after cleanup")
	}
}

// TestReputationTracker_CleanupOldRecords_Partial tests partial cleanup of old records.
func TestReputationTracker_CleanupOldRecords_Partial(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(9)

	// Record old misbehavior
	tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "old")

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Record new misbehavior
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "new")

	// Cleanup records older than 50ms (should remove only the old one)
	removed, err := tracker.CleanupOldRecords(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("CleanupOldRecords failed: %v", err)
	}
	if removed != 1 {
		t.Errorf("Expected 1 removed record, got %d", removed)
	}

	// Verify only new record remains
	history, err := tracker.GetMisbehaviorHistory(participantID, 0)
	if err != nil {
		t.Fatalf("GetMisbehaviorHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("Expected 1 remaining record, got %d", len(history))
	}
	if history[0].Details != "new" {
		t.Error("Wrong record remained after cleanup")
	}
}

// TestReputationTracker_MultipleParticipants tests tracking multiple participants.
func TestReputationTracker_MultipleParticipants(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	// Record misbehavior for multiple participants
	tracker.RecordMisbehavior(frost.Identifier(1), MisbehaviorAuthenticationFailure, "p1")
	tracker.RecordMisbehavior(frost.Identifier(2), MisbehaviorInvalidShare, "p2")
	tracker.RecordMisbehavior(frost.Identifier(3), MisbehaviorTimeout, "p3")

	// Verify each participant has independent reputation
	rep1, _ := tracker.GetReputation(frost.Identifier(1))
	if rep1.AuthenticationFailures != 1 || rep1.InvalidShares != 0 {
		t.Error("Participant 1 reputation incorrect")
	}

	rep2, _ := tracker.GetReputation(frost.Identifier(2))
	if rep2.InvalidShares != 1 || rep2.AuthenticationFailures != 0 {
		t.Error("Participant 2 reputation incorrect")
	}

	rep3, _ := tracker.GetReputation(frost.Identifier(3))
	if rep3.Timeouts != 1 || rep3.AuthenticationFailures != 0 {
		t.Error("Participant 3 reputation incorrect")
	}
}

// TestReputationTracker_AllViolationTypes tests all violation types are tracked correctly.
func TestReputationTracker_AllViolationTypes(t *testing.T) {
	config := DefaultReputationConfig()
	// Set high thresholds to prevent automatic exclusion
	config.MaxAuthenticationFailures = 10
	config.MaxInvalidShares = 10
	config.MaxTimeouts = 10
	config.MaxNonceReuses = 10
	config.MaxInvalidCommitments = 10
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(10)

	// Record one of each violation type
	tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "auth")
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "share")
	tracker.RecordMisbehavior(participantID, MisbehaviorTimeout, "timeout")
	tracker.RecordMisbehavior(participantID, MisbehaviorNonceReuse, "nonce")
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidCommitment, "commitment")

	rep, _ := tracker.GetReputation(participantID)

	if rep.AuthenticationFailures != 1 {
		t.Errorf("Expected 1 auth failure, got %d", rep.AuthenticationFailures)
	}
	if rep.InvalidShares != 1 {
		t.Errorf("Expected 1 invalid share, got %d", rep.InvalidShares)
	}
	if rep.Timeouts != 1 {
		t.Errorf("Expected 1 timeout, got %d", rep.Timeouts)
	}
	if rep.NonceReuses != 1 {
		t.Errorf("Expected 1 nonce reuse, got %d", rep.NonceReuses)
	}
	if rep.InvalidCommitments != 1 {
		t.Errorf("Expected 1 invalid commitment, got %d", rep.InvalidCommitments)
	}
	if rep.TotalViolations() != 5 {
		t.Errorf("Expected 5 total violations, got %d", rep.TotalViolations())
	}
}

// TestReputationTracker_Timestamps tests that timestamps are tracked correctly.
func TestReputationTracker_Timestamps(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(11)

	before := time.Now()
	tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "test")
	after := time.Now()

	rep, _ := tracker.GetReputation(participantID)

	// FirstSeen and LastSeen should be within the time window
	if rep.FirstSeen.Before(before) || rep.FirstSeen.After(after) {
		t.Error("FirstSeen timestamp is outside expected range")
	}
	if rep.LastSeen.Before(before) || rep.LastSeen.After(after) {
		t.Error("LastSeen timestamp is outside expected range")
	}

	// Record another misbehavior
	time.Sleep(10 * time.Millisecond)
	tracker.RecordMisbehavior(participantID, MisbehaviorInvalidShare, "test2")

	rep2, _ := tracker.GetReputation(participantID)

	// FirstSeen should not change, LastSeen should be updated
	if !rep2.FirstSeen.Equal(rep.FirstSeen) {
		t.Error("FirstSeen should not change on subsequent misbehavior")
	}
	if !rep2.LastSeen.After(rep.LastSeen) {
		t.Error("LastSeen should be updated on subsequent misbehavior")
	}
}

// TestReputationTracker_DisabledThresholds tests behavior when thresholds are disabled (set to 0).
func TestReputationTracker_DisabledThresholds(t *testing.T) {
	config := DefaultReputationConfig()
	// Disable automatic exclusion for authentication failures
	config.MaxAuthenticationFailures = 0
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(12)

	// Record many authentication failures
	for i := 0; i < 10; i++ {
		tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "test")
	}

	// Participant should not be excluded
	excluded, _ := tracker.IsExcluded(participantID)
	if excluded {
		t.Error("Participant should not be excluded when threshold is disabled")
	}

	rep, _ := tracker.GetReputation(participantID)
	if rep.AuthenticationFailures != 10 {
		t.Errorf("Expected 10 failures, got %d", rep.AuthenticationFailures)
	}
}

// TestReputationTracker_ConcurrentAccess tests thread safety of the tracker.
func TestReputationTracker_ConcurrentAccess(t *testing.T) {
	config := DefaultReputationConfig()
	tracker := NewInMemoryReputationTracker(config)

	participantID := frost.Identifier(13)

	// Concurrently record misbehavior from multiple goroutines
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				tracker.RecordMisbehavior(participantID, MisbehaviorAuthenticationFailure, "concurrent test")
				tracker.GetReputation(participantID)
				tracker.IsExcluded(participantID)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final state
	rep, err := tracker.GetReputation(participantID)
	if err != nil {
		t.Fatalf("GetReputation failed: %v", err)
	}

	// Should have 100 total failures
	if rep.AuthenticationFailures != 100 {
		t.Errorf("Expected 100 failures from concurrent access, got %d", rep.AuthenticationFailures)
	}
}
