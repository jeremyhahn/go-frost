// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
)

// TestFrostNonceTracker_RecordSigningCommitments tests recording commitments.
func TestFrostNonceTracker_RecordSigningCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-1"
	participantID := frost.Identifier(1)

	// Create signing commitments
	hidingNonce := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()
	commitments := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	// First recording should succeed
	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Verify commitments were recorded
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	// Should have 2 commitments (hiding + binding)
	if count != 2 {
		t.Errorf("expected 2 commitments, got %d", count)
	}
}

// TestFrostNonceTracker_DetectHidingNonceReuse tests detection of hiding nonce reuse.
func TestFrostNonceTracker_DetectHidingNonceReuse(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-reuse"
	participantID := frost.Identifier(1)

	// Create commitments with same hiding nonce
	hidingNonce := suite.Group().NewScalar()
	bindingNonce1 := suite.Group().NewScalar()
	bindingNonce2 := suite.Group().NewScalar()

	commitments1 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce1),
	}

	commitments2 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce), // REUSED!
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce2),
	}

	// First recording should succeed
	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments1)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Second recording should fail due to hiding nonce reuse
	err = tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments2)
	if err == nil {
		t.Fatal("expected error for hiding nonce reuse, got nil")
	}

	if !errors.Is(err, ErrCommitmentReused) {
		t.Errorf("expected ErrCommitmentReused, got: %v", err)
	}
}

// TestFrostNonceTracker_DetectBindingNonceReuse tests detection of binding nonce reuse.
func TestFrostNonceTracker_DetectBindingNonceReuse(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-binding-reuse"
	participantID := frost.Identifier(1)

	// Create commitments with same binding nonce
	hidingNonce1 := suite.Group().NewScalar()
	hidingNonce2 := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()

	commitments1 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce1),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	commitments2 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce2),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce), // REUSED!
	}

	// First recording should succeed
	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments1)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Second recording should fail due to binding nonce reuse
	err = tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments2)
	if err == nil {
		t.Fatal("expected error for binding nonce reuse, got nil")
	}

	if !errors.Is(err, ErrCommitmentReused) {
		t.Errorf("expected ErrCommitmentReused, got: %v", err)
	}
}

// TestFrostNonceTracker_CheckSigningCommitments tests checking commitments.
func TestFrostNonceTracker_CheckSigningCommitments(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-check"
	participantID := frost.Identifier(1)

	// Create signing commitments
	hidingNonce := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()
	commitments := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	// Check should succeed before recording
	err := tracker.CheckSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("CheckSigningCommitments failed before recording: %v", err)
	}

	// Record commitments
	err = tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Check should fail after recording (reuse detected)
	err = tracker.CheckSigningCommitments(ctx, sessionID, participantID, commitments)
	if err == nil {
		t.Fatal("expected error for commitment reuse in Check, got nil")
	}

	if !errors.Is(err, ErrCommitmentReused) {
		t.Errorf("expected ErrCommitmentReused, got: %v", err)
	}
}

// TestFrostNonceTracker_MultipleParticipants tests tracking multiple participants.
func TestFrostNonceTracker_MultipleParticipants(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-multi"

	// Create commitments for 3 participants
	for i := 1; i <= 3; i++ {
		participantID := frost.Identifier(i)
		hidingNonce := suite.Group().NewScalar()
		bindingNonce := suite.Group().NewScalar()
		commitments := frost.SigningCommitments{
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
		}

		err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
		if err != nil {
			t.Fatalf("RecordSigningCommitments failed for participant %d: %v", i, err)
		}
	}

	// Should have 6 commitments (3 participants × 2 commitments each)
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 6 {
		t.Errorf("expected 6 commitments, got %d", count)
	}
}

// TestFrostNonceTracker_ClearSession tests session clearing.
func TestFrostNonceTracker_ClearSession(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-clear"
	participantID := frost.Identifier(1)

	// Create and record commitments
	hidingNonce := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()
	commitments := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Verify commitments exist
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 commitments before clear, got %d", count)
	}

	// Clear session
	err = tracker.ClearSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}

	// Verify commitments were cleared
	count, err = tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed after clear: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 commitments after clear, got %d", count)
	}

	// Should be able to record same commitments again after clearing
	err = tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed after clear: %v", err)
	}
}

// TestFrostNonceTracker_MultipleSessions tests tracking multiple sessions.
func TestFrostNonceTracker_MultipleSessions(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	participantID := frost.Identifier(1)

	// Create commitments for 3 sessions
	for i := 1; i <= 3; i++ {
		sessionID := "test-session-" + string(rune('0'+i))
		hidingNonce := suite.Group().NewScalar()
		bindingNonce := suite.Group().NewScalar()
		commitments := frost.SigningCommitments{
			HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
			BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
		}

		err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
		if err != nil {
			t.Fatalf("RecordSigningCommitments failed for session %d: %v", i, err)
		}
	}

	// Total should be 6 commitments (3 sessions × 2 commitments each)
	total, err := tracker.TotalCommitmentCount(ctx)
	if err != nil {
		t.Fatalf("TotalCommitmentCount failed: %v", err)
	}
	if total != 6 {
		t.Errorf("expected 6 total commitments, got %d", total)
	}
}

// TestFrostNonceTracker_ClearExpired tests clearing expired commitments.
func TestFrostNonceTracker_ClearExpired(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-expire"
	participantID := frost.Identifier(1)

	// Create and record commitments
	hidingNonce := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()
	commitments := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Clear expired with 0 TTL (everything should be expired)
	removed, err := tracker.ClearExpired(ctx, 0)
	if err != nil {
		t.Fatalf("ClearExpired failed: %v", err)
	}
	if removed != 2 {
		t.Errorf("expected 2 commitments removed, got %d", removed)
	}

	// Verify commitments were cleared
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 commitments after expiration, got %d", count)
	}
}

// TestFrostNonceTracker_AtomicCommitmentRecording tests atomic recording of both commitments.
func TestFrostNonceTracker_AtomicCommitmentRecording(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session-atomic"
	participantID := frost.Identifier(1)

	// Create first set of commitments
	hidingNonce1 := suite.Group().NewScalar()
	bindingNonce1 := suite.Group().NewScalar()
	commitments1 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce1),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce1),
	}

	// Record first set
	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments1)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Create second set with same binding nonce (will fail)
	hidingNonce2 := suite.Group().NewScalar()
	commitments2 := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce2),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce1), // REUSED!
	}

	// This should fail and NOT leave the hiding commitment in the tracker
	err = tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments2)
	if err == nil {
		t.Fatal("expected error for binding nonce reuse, got nil")
	}

	// Verify we still only have the first set of commitments (2 total)
	count, err := tracker.SessionCommitmentCount(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionCommitmentCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 commitments (atomic rollback), got %d", count)
	}
}

// TestFrostNonceTracker_ClearParticipant tests clearing participant commitments.
func TestFrostNonceTracker_ClearParticipant(t *testing.T) {
	suite := ristretto255_sha512.New()
	tracker := NewDefaultFrostNonceTracker()
	ctx := context.Background()

	sessionID := "test-session"
	participantID := frost.Identifier(1)

	// Record some commitments first
	hidingNonce := suite.Group().NewScalar()
	bindingNonce := suite.Group().NewScalar()
	commitments := frost.SigningCommitments{
		HidingNonceCommitment:  suite.Group().ScalarBaseMult(hidingNonce),
		BindingNonceCommitment: suite.Group().ScalarBaseMult(bindingNonce),
	}

	err := tracker.RecordSigningCommitments(ctx, sessionID, participantID, commitments)
	if err != nil {
		t.Fatalf("RecordSigningCommitments failed: %v", err)
	}

	// Clear participant (currently a no-op)
	err = tracker.ClearParticipant(ctx, sessionID, participantID)
	if err != nil {
		t.Errorf("ClearParticipant failed: %v", err)
	}
}
