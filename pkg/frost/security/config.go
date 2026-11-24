// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import "time"

// SecurityConfig configures FROST hardening; use DefaultProductionConfig in production.
type SecurityConfig struct {
	// IdentifiableAbortEnabled verifies shares before aggregation (RFC 9591 Section 7.6); default true.
	IdentifiableAbortEnabled bool

	// NonceReuseProtection tracks nonce commitments, since reuse reveals the key; default true.
	NonceReuseProtection bool

	// NonceTracker detects nonce reuse; nil creates an in-memory tracker, production should use a persistent one.
	NonceTracker CommitmentTracker

	// SessionTimeout is the maximum signing session lifetime; default 1 hour.
	SessionTimeout time.Duration

	// CommitmentExpiration is the TTL of tracked commitments; default 24 hours.
	CommitmentExpiration time.Duration

	// MaxSignersPerSession limits the number of participants per signing session.
	// This prevents DoS attacks via excessive participant lists.
	// Default: 1000 (very generous for most use cases)
	MaxSignersPerSession uint32

	// RequireCommitmentsSorted requires sorted commitment lists (RFC 9591); default true.
	RequireCommitmentsSorted bool

	// MessageValidator validates messages before signing; nil disables it; default a 1 MB SizeValidator.
	MessageValidator MessageValidator

	// MaxMessageSize limits message size for the default SizeValidator; 0 disables; default 1 MB.
	MaxMessageSize int

	// ParticipantAuthenticator authenticates participants' messages (RFC 9591 Section 7.2); default nil, none.
	ParticipantAuthenticator ParticipantAuthenticator

	// ReputationTracker excludes participants over misbehavior thresholds; default nil, none.
	ReputationTracker ReputationTracker

	// ReputationConfig configures reputation tracking thresholds.
	// Only used if ReputationTracker is set.
	// Default: DefaultReputationConfig()
	ReputationConfig ReputationConfig
}

// DefaultProductionConfig enables every protection; supply a persistent NonceTracker, an authenticator and a reputation tracker.
func DefaultProductionConfig() SecurityConfig {
	const defaultMaxMessageSize = 1024 * 1024 // 1 MB
	reputationConfig := DefaultReputationConfig()
	return SecurityConfig{
		IdentifiableAbortEnabled: true,
		NonceReuseProtection:     true,
		NonceTracker:             nil, // Will create in-memory, override for production
		SessionTimeout:           1 * time.Hour,
		CommitmentExpiration:     24 * time.Hour,
		MaxSignersPerSession:     1000,
		RequireCommitmentsSorted: true,
		MessageValidator:         NewSizeValidator(defaultMaxMessageSize),
		MaxMessageSize:           defaultMaxMessageSize,
		ReputationTracker:        NewInMemoryReputationTracker(reputationConfig),
		ReputationConfig:         reputationConfig,
	}
}

// DefaultDevelopmentConfig returns security configuration for development/testing.
// This uses the same settings as production (secure by default), but with
// shorter timeouts for faster testing.
func DefaultDevelopmentConfig() SecurityConfig {
	config := DefaultProductionConfig()
	config.SessionTimeout = 5 * time.Minute
	config.CommitmentExpiration = 1 * time.Hour
	// Message validation settings remain the same as production
	return config
}

// InsecureConfig disables every protection; only for benchmarks and tests, never with real keys.
func InsecureConfig() SecurityConfig {
	return SecurityConfig{
		IdentifiableAbortEnabled: false,
		NonceReuseProtection:     false,
		NonceTracker:             nil,
		SessionTimeout:           0,                  // No timeout
		CommitmentExpiration:     0,                  // No expiration
		MaxSignersPerSession:     0,                  // No limit
		RequireCommitmentsSorted: true,               // Keep this for protocol correctness
		MessageValidator:         NewNoOpValidator(), // No validation
		MaxMessageSize:           0,                  // No size limit
		ReputationTracker:        nil,                // No reputation tracking
	}
}

// Validate checks if the security configuration is valid.
func (c *SecurityConfig) Validate() error {
	// If nonce reuse protection is enabled but no tracker provided,
	// we'll create one - this is okay

	// Session timeout should be positive if set
	if c.SessionTimeout < 0 {
		return ErrInvalidSession
	}

	// Commitment expiration should be positive if set
	if c.CommitmentExpiration < 0 {
		return ErrInvalidCommitmentData
	}

	// Max signers should be reasonable
	if c.MaxSignersPerSession > 10000 {
		return ErrInvalidCommitmentData
	}

	return nil
}

// GetOrCreateNonceTracker returns the configured nonce tracker,
// or creates a new in-memory tracker if none is configured.
func (c *SecurityConfig) GetOrCreateNonceTracker() *FrostNonceTracker {
	if c.NonceTracker == nil {
		c.NonceTracker = NewInMemoryCommitmentTracker()
	}
	return NewFrostNonceTracker(c.NonceTracker)
}
