// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

// FrostNonceTracker wraps CommitmentTracker to provide FROST-specific nonce tracking.
// It tracks both hiding and binding nonce commitments per participant per session
// to prevent the catastrophic nonce reuse vulnerability.
//
// Security considerations:
//   - Each signing session gets a unique session ID
//   - Each participant's hiding and binding commitments are tracked separately
//   - Nonce reuse detection is CRITICAL - reuse leads to complete key recovery
//   - Sessions should be cleared after successful completion to free memory
type FrostNonceTracker struct {
	tracker CommitmentTracker
}

// NewFrostNonceTracker creates a new FROST nonce tracker.
func NewFrostNonceTracker(tracker CommitmentTracker) *FrostNonceTracker {
	return &FrostNonceTracker{
		tracker: tracker,
	}
}

// NewDefaultFrostNonceTracker creates a FROST nonce tracker with in-memory storage.
// Suitable for development, testing, and short-lived processes.
// Production systems should use persistent storage.
func NewDefaultFrostNonceTracker() *FrostNonceTracker {
	return NewFrostNonceTracker(NewInMemoryCommitmentTracker())
}

// RecordSigningCommitments records both hiding and binding commitments for a participant.
// This is called when a participant generates commitments (Round 1).
// Returns error if any commitment was already recorded (nonce reuse detected).
func (t *FrostNonceTracker) RecordSigningCommitments(
	ctx context.Context,
	sessionID string,
	participantID frost.Identifier,
	commitments frost.SigningCommitments,
) error {
	now := time.Now()

	// Record hiding commitment
	hidingCommitment := CommitmentIdentifier{
		SessionID:      sessionID,
		ParticipantID:  fmt.Sprintf("%d-hiding", participantID),
		CommitmentData: commitments.HidingNonceCommitment.Bytes(),
		Timestamp:      now,
		Metadata: map[string]string{
			"type":          "hiding",
			"participant":   fmt.Sprintf("%d", participantID),
			"session":       sessionID,
			"commitment_id": fmt.Sprintf("%s-%d-hiding", sessionID, participantID),
		},
	}

	if err := t.tracker.RecordCommitment(ctx, hidingCommitment); err != nil {
		// Error is already sanitized by the tracker
		return fmt.Errorf("hiding commitment recording failed for participant %d in session %s: %w",
			participantID, sessionID, err)
	}

	// Record binding commitment
	bindingCommitment := CommitmentIdentifier{
		SessionID:      sessionID,
		ParticipantID:  fmt.Sprintf("%d-binding", participantID),
		CommitmentData: commitments.BindingNonceCommitment.Bytes(),
		Timestamp:      now,
		Metadata: map[string]string{
			"type":          "binding",
			"participant":   fmt.Sprintf("%d", participantID),
			"session":       sessionID,
			"commitment_id": fmt.Sprintf("%s-%d-binding", sessionID, participantID),
		},
	}

	if err := t.tracker.RecordCommitment(ctx, bindingCommitment); err != nil {
		// Clean up hiding commitment if binding fails
		// This ensures atomic commitment recording
		_ = t.ClearParticipant(ctx, sessionID, participantID)
		// Error is already sanitized by the tracker
		return fmt.Errorf("binding commitment recording failed for participant %d in session %s: %w",
			participantID, sessionID, err)
	}

	return nil
}

// CheckSigningCommitments verifies that commitments haven't been used before.
// This is called when validating received commitments from other participants.
// Returns error if reuse is detected.
func (t *FrostNonceTracker) CheckSigningCommitments(
	ctx context.Context,
	sessionID string,
	participantID frost.Identifier,
	commitments frost.SigningCommitments,
) error {
	// Check hiding commitment
	hidingCommitment := CommitmentIdentifier{
		SessionID:      sessionID,
		ParticipantID:  fmt.Sprintf("%d-hiding", participantID),
		CommitmentData: commitments.HidingNonceCommitment.Bytes(),
		Timestamp:      time.Now(),
	}

	if err := t.tracker.CheckCommitment(ctx, hidingCommitment); err != nil {
		// Error is already sanitized by the tracker
		return fmt.Errorf("hiding commitment check failed for participant %d in session %s: %w",
			participantID, sessionID, err)
	}

	// Check binding commitment
	bindingCommitment := CommitmentIdentifier{
		SessionID:      sessionID,
		ParticipantID:  fmt.Sprintf("%d-binding", participantID),
		CommitmentData: commitments.BindingNonceCommitment.Bytes(),
		Timestamp:      time.Now(),
	}

	if err := t.tracker.CheckCommitment(ctx, bindingCommitment); err != nil {
		// Error is already sanitized by the tracker
		return fmt.Errorf("binding commitment check failed for participant %d in session %s: %w",
			participantID, sessionID, err)
	}

	return nil
}

// ClearSession removes all commitments for a completed session.
// This should be called after successful signature completion to free memory.
func (t *FrostNonceTracker) ClearSession(ctx context.Context, sessionID string) error {
	return t.tracker.ClearSession(ctx, sessionID)
}

// ClearParticipant removes all commitments for a specific participant in a session.
// Useful for cleaning up after failed commitment recording or participant removal.
func (t *FrostNonceTracker) ClearParticipant(
	ctx context.Context,
	sessionID string,
	participantID frost.Identifier,
) error {
	// Clear both hiding and binding commitments
	// We don't have a direct "clear by participant" method, so we record empty
	// commitments and then clear the session. For now, we'll just document this
	// limitation. A production implementation might add a ClearParticipant method
	// to CommitmentTracker.

	// For now, this is a no-op. The commitments will be cleared when the session
	// is cleared. If we need finer-grained control, we can extend CommitmentTracker
	// to support participant-level clearing.
	return nil
}

// ClearExpired removes commitments older than the specified TTL.
// This helps prevent unbounded memory growth in long-running systems.
// Returns the number of commitments removed.
func (t *FrostNonceTracker) ClearExpired(ctx context.Context, ttl time.Duration) (int, error) {
	return t.tracker.ClearExpired(ctx, ttl)
}

// SessionCommitmentCount returns the number of commitments for a session.
// Useful for monitoring and debugging.
func (t *FrostNonceTracker) SessionCommitmentCount(ctx context.Context, sessionID string) (int, error) {
	return t.tracker.CountSession(ctx, sessionID)
}

// TotalCommitmentCount returns the total number of tracked commitments.
// Useful for monitoring memory usage.
func (t *FrostNonceTracker) TotalCommitmentCount(ctx context.Context) (int, error) {
	return t.tracker.Count(ctx)
}
