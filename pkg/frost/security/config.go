// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import "time"

// SecurityConfig configures security features for FROST protocol operations.
//
// This configuration enables various security hardening features to prevent
// common attacks and vulnerabilities in threshold signature schemes.
//
// Production deployments should use DefaultProductionConfig() which enables
// all security features by default (secure by default principle).
type SecurityConfig struct {
	// IdentifiableAbortEnabled enables signature share verification before aggregation.
	// When enabled, malicious participants can be identified if they produce invalid shares.
	// RECOMMENDED: true (RFC 9591 Section 7.6)
	// Default: true
	IdentifiableAbortEnabled bool

	// NonceReuseProtection enables tracking of nonce commitments to prevent reuse.
	// Nonce reuse is CRITICAL - it leads to complete key recovery.
	// REQUIRED: true for production systems
	// Default: true
	NonceReuseProtection bool

	// NonceTracker is the commitment tracker to use for nonce reuse detection.
	// If nil and NonceReuseProtection is true, an in-memory tracker will be created.
	// Production systems should provide a persistent tracker.
	// Default: nil (creates in-memory tracker)
	NonceTracker CommitmentTracker

	// SessionTimeout is the maximum time a signing session can remain active.
	// After this timeout, session data is automatically cleared.
	// This prevents unbounded memory growth in long-running systems.
	// Default: 1 hour
	SessionTimeout time.Duration

	// CommitmentExpiration is the TTL for tracked commitments.
	// Commitments older than this are periodically removed.
	// This prevents memory exhaustion from long-running sessions.
	// Default: 24 hours
	CommitmentExpiration time.Duration

	// MaxSignersPerSession limits the number of participants per signing session.
	// This prevents DoS attacks via excessive participant lists.
	// Default: 1000 (very generous for most use cases)
	MaxSignersPerSession uint32

	// RequireCommitmentsSorted requires commitment lists to be sorted.
	// This is required by RFC 9591 for deterministic binding factor computation.
	// REQUIRED: true (protocol correctness)
	// Default: true
	RequireCommitmentsSorted bool

	// MessageValidator validates messages before signing.
	// This prevents signing oracle attacks and DoS via malformed messages.
	// If nil, no validation is performed (not recommended for production).
	// Default: SizeValidator with 1 MB limit
	MessageValidator MessageValidator

	// MaxMessageSize is the maximum allowed message size in bytes.
	// This is used by the default SizeValidator to prevent DoS attacks.
	// Set to 0 to disable size validation (not recommended).
	// Default: 1 MB (1024 * 1024)
	MaxMessageSize int

	// ParticipantAuthenticator authenticates participants' messages.
	// This prevents impersonation attacks as required by RFC 9591 Section 7.2.
	// If nil, no authentication is performed (not recommended for production).
	// RECOMMENDED: Set to Ed25519Authenticator for production
	// Default: nil (no authentication)
	ParticipantAuthenticator ParticipantAuthenticator

	// ReputationTracker tracks participant misbehavior for DoS prevention.
	// When enabled, participants exceeding misbehavior thresholds are automatically excluded.
	// If nil, no reputation tracking is performed.
	// RECOMMENDED: Enable for production to prevent repeated DoS attacks
	// Default: nil (no reputation tracking)
	ReputationTracker ReputationTracker

	// ReputationConfig configures reputation tracking thresholds.
	// Only used if ReputationTracker is set.
	// Default: DefaultReputationConfig()
	ReputationConfig ReputationConfig
}

// DefaultProductionConfig returns security configuration for production deployments.
// This enables all security features with secure defaults.
//
// Production recommendations:
//   - Provide a persistent NonceTracker (not in-memory)
//   - Set ParticipantAuthenticator to Ed25519Authenticator with participant public keys
//   - Enable ReputationTracker to prevent repeated DoS attacks
//   - Monitor SessionTimeout and adjust based on your use case
//   - Consider shorter CommitmentExpiration for high-security environments
//   - Implement regular cleanup of expired commitments
//   - Override MessageValidator if custom validation logic is needed
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

// InsecureConfig returns security configuration with all protections DISABLED.
//
// WARNING: This is INSECURE and should ONLY be used for:
//   - Performance benchmarking
//   - Testing specific edge cases
//   - Educational demonstrations
//
// NEVER use this in production or with real key material!
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
