// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestInMemoryCommitmentTracker_RecordCommitment tests recording a commitment.
func TestInMemoryCommitmentTracker_RecordCommitment(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	commitment := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-commitment"),
		Timestamp:      time.Now(),
	}

	// First recording should succeed
	err := tracker.RecordCommitment(ctx, commitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed: %v", err)
	}

	// Verify commitment was recorded
	count, err := tracker.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 commitment, got %d", count)
	}
}

// TestInMemoryCommitmentTracker_DetectReuse tests detecting commitment reuse.
func TestInMemoryCommitmentTracker_DetectReuse(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	commitment := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-commitment"),
		Timestamp:      time.Now(),
	}

	// First recording should succeed
	err := tracker.RecordCommitment(ctx, commitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed: %v", err)
	}

	// Second recording should fail (reuse detected)
	err = tracker.RecordCommitment(ctx, commitment)
	if err == nil {
		t.Fatal("expected error for commitment reuse, got nil")
	}

	if !errors.Is(err, ErrCommitmentReused) {
		t.Errorf("expected ErrCommitmentReused, got: %v", err)
	}
}

// TestInMemoryCommitmentTracker_CheckCommitment tests checking commitments.
func TestInMemoryCommitmentTracker_CheckCommitment(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	commitment := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-commitment"),
		Timestamp:      time.Now(),
	}

	// Check should succeed before recording
	err := tracker.CheckCommitment(ctx, commitment)
	if err != nil {
		t.Fatalf("CheckCommitment failed before recording: %v", err)
	}

	// Record commitment
	err = tracker.RecordCommitment(ctx, commitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed: %v", err)
	}

	// Check should fail after recording
	err = tracker.CheckCommitment(ctx, commitment)
	if err == nil {
		t.Fatal("expected error for commitment reuse in Check, got nil")
	}

	if !errors.Is(err, ErrCommitmentReused) {
		t.Errorf("expected ErrCommitmentReused, got: %v", err)
	}
}

// TestInMemoryCommitmentTracker_DifferentSessionsIndependent tests session isolation.
func TestInMemoryCommitmentTracker_DifferentSessionsIndependent(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	// Same commitment data but different sessions should be independent
	commitment1 := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("same-commitment"),
		Timestamp:      time.Now(),
	}

	commitment2 := CommitmentIdentifier{
		SessionID:      "session2", // Different session
		ParticipantID:  "participant1",
		CommitmentData: []byte("same-commitment"),
		Timestamp:      time.Now(),
	}

	// Both should succeed
	err := tracker.RecordCommitment(ctx, commitment1)
	if err != nil {
		t.Fatalf("RecordCommitment failed for session1: %v", err)
	}

	err = tracker.RecordCommitment(ctx, commitment2)
	if err != nil {
		t.Fatalf("RecordCommitment failed for session2: %v", err)
	}

	// Total count should be 2
	count, err := tracker.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 commitments, got %d", count)
	}
}

// TestInMemoryCommitmentTracker_ClearSession tests clearing a session.
func TestInMemoryCommitmentTracker_ClearSession(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	// Record commitments for multiple sessions
	session1Commitment := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("commitment1"),
		Timestamp:      time.Now(),
	}

	session2Commitment := CommitmentIdentifier{
		SessionID:      "session2",
		ParticipantID:  "participant1",
		CommitmentData: []byte("commitment2"),
		Timestamp:      time.Now(),
	}

	err := tracker.RecordCommitment(ctx, session1Commitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed for session1: %v", err)
	}

	err = tracker.RecordCommitment(ctx, session2Commitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed for session2: %v", err)
	}

	// Clear session1
	err = tracker.ClearSession(ctx, "session1")
	if err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}

	// Session1 should have 0 commitments
	count, err := tracker.CountSession(ctx, "session1")
	if err != nil {
		t.Fatalf("CountSession failed for session1: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 commitments for session1 after clear, got %d", count)
	}

	// Session2 should still have 1 commitment
	count, err = tracker.CountSession(ctx, "session2")
	if err != nil {
		t.Fatalf("CountSession failed for session2: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 commitment for session2, got %d", count)
	}

	// Total should be 1
	total, err := tracker.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 total commitment after clearing session1, got %d", total)
	}
}

// TestInMemoryCommitmentTracker_ClearExpired tests clearing expired commitments.
func TestInMemoryCommitmentTracker_ClearExpired(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	// Record old commitment (simulate by setting old timestamp)
	oldCommitment := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("old-commitment"),
		Timestamp:      time.Now().Add(-2 * time.Hour),
	}

	// Record recent commitment
	recentCommitment := CommitmentIdentifier{
		SessionID:      "session2",
		ParticipantID:  "participant2",
		CommitmentData: []byte("recent-commitment"),
		Timestamp:      time.Now(),
	}

	err := tracker.RecordCommitment(ctx, oldCommitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed for old commitment: %v", err)
	}

	err = tracker.RecordCommitment(ctx, recentCommitment)
	if err != nil {
		t.Fatalf("RecordCommitment failed for recent commitment: %v", err)
	}

	// Clear commitments older than 1 hour
	removed, err := tracker.ClearExpired(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("ClearExpired failed: %v", err)
	}

	if removed != 1 {
		t.Errorf("expected 1 commitment removed, got %d", removed)
	}

	// Should have 1 commitment left (the recent one)
	count, err := tracker.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 commitment after expiration, got %d", count)
	}
}

// TestInMemoryCommitmentTracker_CountSession tests counting commitments per session.
func TestInMemoryCommitmentTracker_CountSession(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	sessionID := "test-session"

	// Record 3 commitments for the same session
	for i := 0; i < 3; i++ {
		commitment := CommitmentIdentifier{
			SessionID:      sessionID,
			ParticipantID:  "participant" + string(rune('1'+i)),
			CommitmentData: []byte("commitment" + string(rune('1'+i))),
			Timestamp:      time.Now(),
		}

		err := tracker.RecordCommitment(ctx, commitment)
		if err != nil {
			t.Fatalf("RecordCommitment failed for commitment %d: %v", i, err)
		}
	}

	// Session should have 3 commitments
	count, err := tracker.CountSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("CountSession failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 commitments for session, got %d", count)
	}

	// Non-existent session should have 0 commitments
	count, err = tracker.CountSession(ctx, "non-existent-session")
	if err != nil {
		t.Fatalf("CountSession failed for non-existent session: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 commitments for non-existent session, got %d", count)
	}
}

// TestInMemoryCommitmentTracker_Hash tests commitment hash uniqueness.
func TestInMemoryCommitmentTracker_Hash(t *testing.T) {
	// Same data should produce same hash
	commitment1 := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-data"),
		Timestamp:      time.Now(),
	}

	commitment2 := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-data"),
		Timestamp:      time.Now().Add(1 * time.Hour), // Different timestamp
	}

	hash1 := commitment1.Hash()
	hash2 := commitment2.Hash()

	if hash1 != hash2 {
		t.Error("same commitment data should produce same hash (timestamp ignored)")
	}

	// Different data should produce different hash
	commitment3 := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant1",
		CommitmentData: []byte("different-data"),
		Timestamp:      time.Now(),
	}

	hash3 := commitment3.Hash()

	if hash1 == hash3 {
		t.Error("different commitment data should produce different hash")
	}

	// Different session should produce different hash
	commitment4 := CommitmentIdentifier{
		SessionID:      "session2", // Different session
		ParticipantID:  "participant1",
		CommitmentData: []byte("test-data"),
		Timestamp:      time.Now(),
	}

	hash4 := commitment4.Hash()

	if hash1 == hash4 {
		t.Error("different session should produce different hash")
	}

	// Different participant should produce different hash
	commitment5 := CommitmentIdentifier{
		SessionID:      "session1",
		ParticipantID:  "participant2", // Different participant
		CommitmentData: []byte("test-data"),
		Timestamp:      time.Now(),
	}

	hash5 := commitment5.Hash()

	if hash1 == hash5 {
		t.Error("different participant should produce different hash")
	}
}

// TestInMemoryCommitmentTracker_ConcurrentAccess tests thread safety.
func TestInMemoryCommitmentTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewInMemoryCommitmentTracker()
	ctx := context.Background()

	// Run multiple goroutines concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			commitment := CommitmentIdentifier{
				SessionID:      "concurrent-session",
				ParticipantID:  "participant" + string(rune('0'+id)),
				CommitmentData: []byte("commitment" + string(rune('0'+id))),
				Timestamp:      time.Now(),
			}

			err := tracker.RecordCommitment(ctx, commitment)
			if err != nil {
				t.Errorf("RecordCommitment failed for goroutine %d: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 10 commitments
	count, err := tracker.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 commitments after concurrent access, got %d", count)
	}
}
