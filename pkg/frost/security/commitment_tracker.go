// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CommitmentIdentifier uniquely identifies a cryptographic commitment.
// This is generic enough to work for both AEAD nonces and FROST signing commitments.
type CommitmentIdentifier struct {
	// SessionID groups related commitments (e.g., signing session, encryption key)
	SessionID string

	// ParticipantID identifies who made the commitment (empty for single-party operations like AEAD)
	ParticipantID string

	// CommitmentData is the actual commitment bytes (nonce, hiding commitment, etc.)
	CommitmentData []byte

	// Timestamp when the commitment was made
	Timestamp time.Time

	// Metadata for application-specific use
	Metadata map[string]string
}

// Hash returns a unique hash of the commitment for efficient lookup.
func (c *CommitmentIdentifier) Hash() string {
	h := sha256.New()
	h.Write([]byte(c.SessionID))
	h.Write([]byte(c.ParticipantID))
	h.Write(c.CommitmentData)
	return hex.EncodeToString(h.Sum(nil))
}

// CommitmentTracker provides thread-safe tracking of cryptographic commitments
// to prevent catastrophic reuse in both AEAD ciphers and threshold signature schemes.
//
// This interface is generic and can be used for:
//   - AEAD nonce tracking (AES-GCM, ChaCha20-Poly1305)
//   - FROST signing nonce commitments
//   - Any other cryptographic commitment scheme requiring uniqueness
//
// Security considerations:
//   - All implementations MUST be thread-safe
//   - Memory usage grows with tracked commitments
//   - Consider TTL-based expiration for long-running systems
//   - Persistent storage recommended for production systems
type CommitmentTracker interface {
	// RecordCommitment stores a commitment for tracking.
	// Returns error if the commitment was already recorded (reuse detected).
	RecordCommitment(ctx context.Context, commitment CommitmentIdentifier) error

	// CheckCommitment verifies a commitment hasn't been used before.
	// Returns error if reuse is detected.
	CheckCommitment(ctx context.Context, commitment CommitmentIdentifier) error

	// ClearSession removes all commitments for a completed session.
	// Use this after successful completion to free memory.
	ClearSession(ctx context.Context, sessionID string) error

	// ClearExpired removes commitments older than the specified TTL.
	// Returns the number of commitments removed.
	ClearExpired(ctx context.Context, ttl time.Duration) (int, error)

	// Count returns the total number of tracked commitments.
	// Useful for monitoring memory usage.
	Count(ctx context.Context) (int, error)

	// CountSession returns the number of commitments for a specific session.
	CountSession(ctx context.Context, sessionID string) (int, error)
}

// InMemoryCommitmentTracker is an in-memory implementation of CommitmentTracker.
// Suitable for development, testing, and short-lived processes.
// Production systems should use persistent storage.
type InMemoryCommitmentTracker struct {
	// Map of commitment hash -> commitment details
	commitments map[string]CommitmentIdentifier

	// Index by session for efficient session clearing
	sessionIndex map[string]map[string]bool // sessionID -> commitment hashes

	mu sync.RWMutex
}

// NewInMemoryCommitmentTracker creates a new in-memory commitment tracker.
func NewInMemoryCommitmentTracker() *InMemoryCommitmentTracker {
	return &InMemoryCommitmentTracker{
		commitments:  make(map[string]CommitmentIdentifier),
		sessionIndex: make(map[string]map[string]bool),
	}
}

// RecordCommitment implements CommitmentTracker.RecordCommitment
func (t *InMemoryCommitmentTracker) RecordCommitment(_ context.Context, commitment CommitmentIdentifier) error {
	hash := commitment.Hash()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check for reuse
	if _, exists := t.commitments[hash]; exists {
		// Use sanitized error - don't leak commitment data
		sanitizer := globalSanitizer
		return sanitizer.SanitizeCommitmentError(commitment.SessionID, commitment.ParticipantID, ErrCommitmentReused)
	}

	// Record commitment
	t.commitments[hash] = commitment

	// Update session index
	if t.sessionIndex[commitment.SessionID] == nil {
		t.sessionIndex[commitment.SessionID] = make(map[string]bool)
	}
	t.sessionIndex[commitment.SessionID][hash] = true

	return nil
}

// CheckCommitment implements CommitmentTracker.CheckCommitment
func (t *InMemoryCommitmentTracker) CheckCommitment(_ context.Context, commitment CommitmentIdentifier) error {
	hash := commitment.Hash()

	t.mu.RLock()
	defer t.mu.RUnlock()

	if _, exists := t.commitments[hash]; exists {
		// Use sanitized error - don't leak commitment data
		sanitizer := globalSanitizer
		return sanitizer.SanitizeCommitmentError(commitment.SessionID, commitment.ParticipantID, ErrCommitmentReused)
	}

	return nil
}

// ClearSession implements CommitmentTracker.ClearSession
func (t *InMemoryCommitmentTracker) ClearSession(_ context.Context, sessionID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get all commitment hashes for this session
	hashes, exists := t.sessionIndex[sessionID]
	if !exists {
		return nil // Session not found, nothing to clear
	}

	// Remove all commitments for this session
	for hash := range hashes {
		delete(t.commitments, hash)
	}

	// Remove session index entry
	delete(t.sessionIndex, sessionID)

	return nil
}

// ClearExpired implements CommitmentTracker.ClearExpired
func (t *InMemoryCommitmentTracker) ClearExpired(_ context.Context, ttl time.Duration) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	expiredCount := 0
	expiredSessions := make(map[string]bool)

	// Find expired commitments
	for hash, commitment := range t.commitments {
		if now.Sub(commitment.Timestamp) > ttl {
			delete(t.commitments, hash)
			expiredSessions[commitment.SessionID] = true
			expiredCount++
		}
	}

	// Clean up session index for expired sessions
	for sessionID := range expiredSessions {
		// Rebuild session index (only keep non-expired)
		sessionHashes := make(map[string]bool)
		for hash := range t.sessionIndex[sessionID] {
			if _, exists := t.commitments[hash]; exists {
				sessionHashes[hash] = true
			}
		}

		if len(sessionHashes) == 0 {
			delete(t.sessionIndex, sessionID)
		} else {
			t.sessionIndex[sessionID] = sessionHashes
		}
	}

	return expiredCount, nil
}

// Count implements CommitmentTracker.Count
func (t *InMemoryCommitmentTracker) Count(_ context.Context) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.commitments), nil
}

// CountSession implements CommitmentTracker.CountSession
func (t *InMemoryCommitmentTracker) CountSession(_ context.Context, sessionID string) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hashes, exists := t.sessionIndex[sessionID]
	if !exists {
		return 0, nil
	}

	return len(hashes), nil
}

// Verify interface compliance
var _ CommitmentTracker = (*InMemoryCommitmentTracker)(nil)
