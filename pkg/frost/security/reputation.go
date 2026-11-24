// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"sync"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

// MisbehaviorType represents the type of misbehavior detected.
type MisbehaviorType string

const (
	// MisbehaviorAuthenticationFailure indicates a participant failed authentication.
	MisbehaviorAuthenticationFailure MisbehaviorType = "authentication_failure"

	// MisbehaviorInvalidShare indicates a participant produced an invalid signature share.
	MisbehaviorInvalidShare MisbehaviorType = "invalid_share"

	// MisbehaviorTimeout indicates a participant failed to respond within the timeout.
	MisbehaviorTimeout MisbehaviorType = "timeout"

	// MisbehaviorNonceReuse indicates a participant attempted to reuse a nonce.
	MisbehaviorNonceReuse MisbehaviorType = "nonce_reuse"

	// MisbehaviorInvalidCommitment indicates a participant produced an invalid commitment.
	MisbehaviorInvalidCommitment MisbehaviorType = "invalid_commitment"
)

// MisbehaviorRecord represents a single instance of participant misbehavior.
type MisbehaviorRecord struct {
	// ParticipantID is the identifier of the misbehaving participant.
	ParticipantID frost.Identifier

	// Type is the type of misbehavior detected.
	Type MisbehaviorType

	// Timestamp is when the misbehavior was recorded.
	Timestamp time.Time

	// Details provides additional context about the misbehavior.
	Details string
}

// ParticipantReputation tracks the reputation of a participant.
type ParticipantReputation struct {
	// ParticipantID is the identifier of the participant.
	ParticipantID frost.Identifier

	// AuthenticationFailures is the count of authentication failures.
	AuthenticationFailures int

	// InvalidShares is the count of invalid signature shares.
	InvalidShares int

	// Timeouts is the count of timeout violations.
	Timeouts int

	// NonceReuses is the count of nonce reuse attempts.
	NonceReuses int

	// InvalidCommitments is the count of invalid commitments.
	InvalidCommitments int

	// FirstSeen is when the participant was first tracked.
	FirstSeen time.Time

	// LastSeen is when the participant was last active.
	LastSeen time.Time

	// Excluded indicates if the participant is currently excluded.
	Excluded bool

	// ExcludedAt is when the participant was excluded (if applicable).
	ExcludedAt time.Time

	// ExclusionReason describes why the participant was excluded.
	ExclusionReason string
}

// TotalViolations returns the total number of violations across all categories.
func (r *ParticipantReputation) TotalViolations() int {
	return r.AuthenticationFailures +
		r.InvalidShares +
		r.Timeouts +
		r.NonceReuses +
		r.InvalidCommitments
}

// ReputationTracker is a thread-safe record of participant misbehavior with automatic exclusion past thresholds.
type ReputationTracker interface {
	// RecordMisbehavior records a misbehavior of the given type for a participant.
	RecordMisbehavior(participantID frost.Identifier, misbehaviorType MisbehaviorType, details string) error

	// GetReputation returns a participant's reputation, or ErrParticipantNotFound.
	GetReputation(participantID frost.Identifier) (ParticipantReputation, error)

	// IsExcluded reports whether a participant is excluded.
	IsExcluded(participantID frost.Identifier) (bool, error)

	// ExcludeParticipant excludes a participant for the given reason.
	ExcludeParticipant(participantID frost.Identifier, reason string) error

	// ReinstateParticipant lifts a participant's exclusion.
	ReinstateParticipant(participantID frost.Identifier) error

	// GetMisbehaviorHistory returns up to limit records (0 = all), or ErrParticipantNotFound.
	GetMisbehaviorHistory(participantID frost.Identifier, limit int) ([]MisbehaviorRecord, error)

	// CleanupOldRecords removes records older than maxAge and returns how many.
	CleanupOldRecords(maxAge time.Duration) (int, error)
}

// ReputationConfig configures reputation tracking behavior.
type ReputationConfig struct {
	// MaxAuthenticationFailures before exclusion; 0 disables; default 3.
	MaxAuthenticationFailures int

	// MaxInvalidShares before exclusion; 0 disables; default 2.
	MaxInvalidShares int

	// MaxTimeouts before exclusion; 0 disables; default 5.
	MaxTimeouts int

	// MaxNonceReuses before exclusion; default 1.
	MaxNonceReuses int

	// MaxInvalidCommitments before exclusion; 0 disables; default 3.
	MaxInvalidCommitments int

	// RecordRetention is how long records are kept; 0 keeps them forever; default 30 days.
	RecordRetention time.Duration
}

// DefaultReputationConfig returns the default reputation configuration.
func DefaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		MaxAuthenticationFailures: 3,
		MaxInvalidShares:          2,
		MaxTimeouts:               5,
		MaxNonceReuses:            1,
		MaxInvalidCommitments:     3,
		RecordRetention:           30 * 24 * time.Hour, // 30 days
	}
}

// InMemoryReputationTracker is a thread-safe in-memory ReputationTracker for single-node use.
type InMemoryReputationTracker struct {
	config      ReputationConfig
	mu          sync.RWMutex
	reputations map[frost.Identifier]*ParticipantReputation
	history     map[frost.Identifier][]MisbehaviorRecord
}

// NewInMemoryReputationTracker creates a new in-memory reputation tracker.
func NewInMemoryReputationTracker(config ReputationConfig) *InMemoryReputationTracker {
	return &InMemoryReputationTracker{
		config:      config,
		reputations: make(map[frost.Identifier]*ParticipantReputation),
		history:     make(map[frost.Identifier][]MisbehaviorRecord),
	}
}

// RecordMisbehavior implements ReputationTracker.RecordMisbehavior
func (t *InMemoryReputationTracker) RecordMisbehavior(participantID frost.Identifier, misbehaviorType MisbehaviorType, details string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Get or create reputation record
	rep, exists := t.reputations[participantID]
	if !exists {
		rep = &ParticipantReputation{
			ParticipantID: participantID,
			FirstSeen:     now,
		}
		t.reputations[participantID] = rep
	}
	rep.LastSeen = now

	// Update violation count based on type
	switch misbehaviorType {
	case MisbehaviorAuthenticationFailure:
		rep.AuthenticationFailures++
		if t.config.MaxAuthenticationFailures > 0 && rep.AuthenticationFailures >= t.config.MaxAuthenticationFailures {
			t.excludeParticipantLocked(participantID, "exceeded authentication failure threshold")
		}
	case MisbehaviorInvalidShare:
		rep.InvalidShares++
		if t.config.MaxInvalidShares > 0 && rep.InvalidShares >= t.config.MaxInvalidShares {
			t.excludeParticipantLocked(participantID, "exceeded invalid share threshold")
		}
	case MisbehaviorTimeout:
		rep.Timeouts++
		if t.config.MaxTimeouts > 0 && rep.Timeouts >= t.config.MaxTimeouts {
			t.excludeParticipantLocked(participantID, "exceeded timeout threshold")
		}
	case MisbehaviorNonceReuse:
		rep.NonceReuses++
		if t.config.MaxNonceReuses > 0 && rep.NonceReuses >= t.config.MaxNonceReuses {
			t.excludeParticipantLocked(participantID, "exceeded nonce reuse threshold")
		}
	case MisbehaviorInvalidCommitment:
		rep.InvalidCommitments++
		if t.config.MaxInvalidCommitments > 0 && rep.InvalidCommitments >= t.config.MaxInvalidCommitments {
			t.excludeParticipantLocked(participantID, "exceeded invalid commitment threshold")
		}
	}

	// Record the misbehavior in history
	record := MisbehaviorRecord{
		ParticipantID: participantID,
		Type:          misbehaviorType,
		Timestamp:     now,
		Details:       details,
	}
	t.history[participantID] = append(t.history[participantID], record)

	return nil
}

// excludeParticipantLocked excludes a participant (internal, assumes lock is held).
func (t *InMemoryReputationTracker) excludeParticipantLocked(participantID frost.Identifier, reason string) {
	rep := t.reputations[participantID]
	if rep.Excluded {
		return // Already excluded
	}
	rep.Excluded = true
	rep.ExcludedAt = time.Now()
	rep.ExclusionReason = reason
}

// GetReputation implements ReputationTracker.GetReputation
func (t *InMemoryReputationTracker) GetReputation(participantID frost.Identifier) (ParticipantReputation, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rep, exists := t.reputations[participantID]
	if !exists {
		return ParticipantReputation{}, ErrParticipantNotFound
	}

	// Return a copy to prevent external modification
	return *rep, nil
}

// IsExcluded implements ReputationTracker.IsExcluded
func (t *InMemoryReputationTracker) IsExcluded(participantID frost.Identifier) (bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rep, exists := t.reputations[participantID]
	if !exists {
		return false, nil // Unknown participants are not excluded
	}

	return rep.Excluded, nil
}

// ExcludeParticipant implements ReputationTracker.ExcludeParticipant
func (t *InMemoryReputationTracker) ExcludeParticipant(participantID frost.Identifier, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get or create reputation record
	_, exists := t.reputations[participantID]
	if !exists {
		now := time.Now()
		t.reputations[participantID] = &ParticipantReputation{
			ParticipantID: participantID,
			FirstSeen:     now,
			LastSeen:      now,
		}
	}

	t.excludeParticipantLocked(participantID, reason)
	return nil
}

// ReinstateParticipant implements ReputationTracker.ReinstateParticipant
func (t *InMemoryReputationTracker) ReinstateParticipant(participantID frost.Identifier) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	rep, exists := t.reputations[participantID]
	if !exists {
		return ErrParticipantNotFound
	}

	rep.Excluded = false
	rep.ExcludedAt = time.Time{}
	rep.ExclusionReason = ""

	return nil
}

// GetMisbehaviorHistory implements ReputationTracker.GetMisbehaviorHistory
func (t *InMemoryReputationTracker) GetMisbehaviorHistory(participantID frost.Identifier, limit int) ([]MisbehaviorRecord, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	records, exists := t.history[participantID]
	if !exists {
		return nil, ErrParticipantNotFound
	}

	// Return all records if limit is 0 or greater than available
	if limit <= 0 || limit >= len(records) {
		// Return a copy to prevent external modification
		result := make([]MisbehaviorRecord, len(records))
		copy(result, records)
		return result, nil
	}

	// Return the most recent 'limit' records
	start := len(records) - limit
	result := make([]MisbehaviorRecord, limit)
	copy(result, records[start:])
	return result, nil
}

// CleanupOldRecords implements ReputationTracker.CleanupOldRecords
func (t *InMemoryReputationTracker) CleanupOldRecords(maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil // No cleanup if maxAge is 0 or negative
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	// Clean up history records
	for participantID, records := range t.history {
		newRecords := make([]MisbehaviorRecord, 0, len(records))
		for _, record := range records {
			if record.Timestamp.After(cutoff) {
				newRecords = append(newRecords, record)
			} else {
				removed++
			}
		}

		if len(newRecords) == 0 {
			delete(t.history, participantID)
		} else {
			t.history[participantID] = newRecords
		}
	}

	return removed, nil
}
