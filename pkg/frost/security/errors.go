// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Security-related errors for FROST protocol operations.

var (
	// ErrCommitmentReused is returned when a commitment (nonce) is reused.
	// This is a CRITICAL security violation that can lead to complete key recovery.
	ErrCommitmentReused = errors.New("commitment reused - CRITICAL security violation")

	// ErrInvalidSession is returned when a session ID is invalid or not found.
	ErrInvalidSession = errors.New("invalid session ID")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")

	// ErrParticipantNotFound is returned when a participant is not found in the session.
	ErrParticipantNotFound = errors.New("participant not found")

	// ErrInvalidCommitmentData is returned when commitment data is malformed.
	ErrInvalidCommitmentData = errors.New("invalid commitment data")

	// ErrMessageTooLarge is returned when a message exceeds the maximum allowed size.
	// This prevents DoS attacks via extremely large messages.
	ErrMessageTooLarge = errors.New("message size exceeds maximum allowed")

	// ErrMessageValidationFailed is returned when message validation fails.
	ErrMessageValidationFailed = errors.New("message validation failed")

	// ErrAuthenticationFailed is returned when participant authentication fails.
	// This prevents impersonation attacks.
	ErrAuthenticationFailed = errors.New("participant authentication failed")

	// ErrParticipantExcluded is returned when an excluded participant attempts to participate.
	// This indicates the participant has exceeded misbehavior thresholds.
	ErrParticipantExcluded = errors.New("participant is excluded due to misbehavior")
)

type ErrorSanitizationMode int

const (
	// ErrorSanitizationProduction removes all sensitive information from errors.
	// Use this mode in production environments to prevent information leakage.
	ErrorSanitizationProduction ErrorSanitizationMode = iota

	// ErrorSanitizationDevelopment includes detailed error information for debugging.
	// Use this mode only in development/testing environments.
	ErrorSanitizationDevelopment

	// ErrorSanitizationDisabled bypasses all sanitization.
	// WARNING: This may leak sensitive cryptographic information. Use only for testing.
	ErrorSanitizationDisabled
)

// ErrorSanitizerConfig configures error sanitization behavior.
type ErrorSanitizerConfig struct {
	// Mode controls the sanitization level
	Mode ErrorSanitizationMode

	// AllowParticipantID allows participant IDs in error messages (production-safe)
	AllowParticipantID bool

	// AllowSessionID allows session IDs in error messages (production-safe)
	AllowSessionID bool
}

// DefaultProductionErrorConfig returns error sanitization config for production.
func DefaultProductionErrorConfig() ErrorSanitizerConfig {
	return ErrorSanitizerConfig{
		Mode:               ErrorSanitizationProduction,
		AllowParticipantID: true,
		AllowSessionID:     false, // Session IDs might be predictable/enumerable
	}
}

// DefaultDevelopmentErrorConfig returns error sanitization config for development.
func DefaultDevelopmentErrorConfig() ErrorSanitizerConfig {
	return ErrorSanitizerConfig{
		Mode:               ErrorSanitizationDevelopment,
		AllowParticipantID: true,
		AllowSessionID:     true,
	}
}

// ErrorSanitizer sanitizes error messages to prevent sensitive information leakage.
//
// Security considerations:
//   - Removes hexadecimal values that might represent cryptographic material
//   - Removes base64-encoded data
//   - Removes byte arrays and scalar values
//   - Preserves enough context for debugging in development mode
//   - Configurable for production vs development environments
//
// Example:
//
//	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())
//	err := fmt.Errorf("signature verification failed: scalar=0x1234abcd")
//	safe := sanitizer.Sanitize(err) // Returns "signature verification failed"
type ErrorSanitizer struct {
	config ErrorSanitizerConfig

	// Compiled regexes for efficient pattern matching
	hexPattern        *regexp.Regexp
	base64Pattern     *regexp.Regexp
	byteArrayPattern  *regexp.Regexp
	scalarPattern     *regexp.Regexp
	commitmentPattern *regexp.Regexp
	signaturePattern  *regexp.Regexp
}

// NewErrorSanitizer creates a new error sanitizer with the given configuration.
func NewErrorSanitizer(config ErrorSanitizerConfig) *ErrorSanitizer {
	return &ErrorSanitizer{
		config: config,
		// Match hex strings of 8+ characters (4+ bytes of crypto material)
		hexPattern: regexp.MustCompile(`0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{16,}`),
		// Match base64 strings (common in serialized crypto)
		base64Pattern: regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`),
		// Match byte array representations
		byteArrayPattern: regexp.MustCompile(`\[[0-9 ,]{16,}\]`),
		// Match scalar/nonce/key value patterns
		scalarPattern: regexp.MustCompile(`(?i)(scalar|nonce|key|secret|share)[=:]\s*[^\s,)]+`),
		// Match commitment value patterns
		commitmentPattern: regexp.MustCompile(`(?i)(commitment|hiding|binding)[=:]\s*[^\s,)]+`),
		// Match signature value patterns
		signaturePattern: regexp.MustCompile(`(?i)(signature|sig_share|z)[=:]\s*[^\s,)]+`),
	}
}

// Sanitize sanitizes an error message according to the configured mode.
//
// Returns:
//   - In production mode: Generic error with sensitive data removed
//   - In development mode: Error with sensitive data redacted but structure preserved
//   - In disabled mode: Original error unchanged
func (s *ErrorSanitizer) Sanitize(err error) error {
	if err == nil {
		return nil
	}

	// Disabled mode: return original error
	if s.config.Mode == ErrorSanitizationDisabled {
		return err
	}

	msg := err.Error()

	// Production mode: aggressive sanitization
	if s.config.Mode == ErrorSanitizationProduction {
		msg = s.sanitizeProduction(msg)
	} else {
		// Development mode: redact sensitive values but preserve structure
		msg = s.sanitizeDevelopment(msg)
	}

	// Preserve the error type if it's a known error
	if errors.Is(err, ErrCommitmentReused) {
		return fmt.Errorf("%s: %w", msg, ErrCommitmentReused)
	}
	if errors.Is(err, ErrAuthenticationFailed) {
		return fmt.Errorf("%s: %w", msg, ErrAuthenticationFailed)
	}
	if errors.Is(err, ErrMessageValidationFailed) {
		return fmt.Errorf("%s: %w", msg, ErrMessageValidationFailed)
	}

	return errors.New(msg)
}

// sanitizeProduction performs aggressive sanitization for production environments.
func (s *ErrorSanitizer) sanitizeProduction(msg string) string {
	// Remove all cryptographic values
	msg = s.hexPattern.ReplaceAllString(msg, "[REDACTED]")
	msg = s.base64Pattern.ReplaceAllString(msg, "[REDACTED]")
	msg = s.byteArrayPattern.ReplaceAllString(msg, "[REDACTED]")
	msg = s.scalarPattern.ReplaceAllString(msg, "$1=[REDACTED]")
	msg = s.commitmentPattern.ReplaceAllString(msg, "$1=[REDACTED]")
	msg = s.signaturePattern.ReplaceAllString(msg, "$1=[REDACTED]")

	// Remove session IDs if not allowed
	if !s.config.AllowSessionID {
		// Replace session IDs (UUIDs and similar patterns)
		msg = regexp.MustCompile(`(?i)session[: ]+([a-z0-9-]+)`).ReplaceAllString(msg, "session: [REDACTED]")
	}

	// Clean up multiple consecutive redactions
	msg = regexp.MustCompile(`(\[REDACTED\]\s*){2,}`).ReplaceAllString(msg, "[REDACTED]")

	// Clean up extra whitespace
	msg = strings.TrimSpace(msg)

	return msg
}

// sanitizeDevelopment performs moderate sanitization for development environments.
// Preserves structure and non-sensitive details for debugging.
func (s *ErrorSanitizer) sanitizeDevelopment(msg string) string {
	// First, handle field=value patterns by replacing values with placeholders
	// Do this before hex/base64 replacement to preserve field names

	// For scalar/nonce/key/secret/share fields, replace the value part only
	msg = s.scalarPattern.ReplaceAllStringFunc(msg, func(match string) string {
		// Extract field name from pattern like "scalar=value"
		parts := regexp.MustCompile(`(?i)(scalar|nonce|key|secret|share)[=:]\s*`).FindStringSubmatch(match)
		if len(parts) >= 2 {
			return parts[1] + "=[REDACTED]"
		}
		return "[REDACTED]"
	})

	msg = s.commitmentPattern.ReplaceAllStringFunc(msg, func(match string) string {
		parts := regexp.MustCompile(`(?i)(commitment|hiding|binding)[=:]\s*`).FindStringSubmatch(match)
		if len(parts) >= 2 {
			return parts[1] + "=[REDACTED]"
		}
		return "[REDACTED]"
	})

	msg = s.signaturePattern.ReplaceAllStringFunc(msg, func(match string) string {
		parts := regexp.MustCompile(`(?i)(signature|sig_share|z)[=:]\s*`).FindStringSubmatch(match)
		if len(parts) >= 2 {
			return parts[1] + "=[REDACTED]"
		}
		return "[REDACTED]"
	})

	// Now redact remaining hex values (not part of field=value patterns) but show length
	msg = s.hexPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return fmt.Sprintf("[HEX:%d]", len(match))
	})

	// Redact base64 but show length
	msg = s.base64Pattern.ReplaceAllStringFunc(msg, func(match string) string {
		return fmt.Sprintf("[B64:%d]", len(match))
	})

	// Redact byte arrays but show length
	msg = s.byteArrayPattern.ReplaceAllStringFunc(msg, func(match string) string {
		return fmt.Sprintf("[BYTES:%d]", len(match))
	})

	return strings.TrimSpace(msg)
}

// SanitizeCommitmentError creates a sanitized error for commitment-related failures.
// Preserves participant/session information based on configuration.
func (s *ErrorSanitizer) SanitizeCommitmentError(sessionID string, participantID interface{}, baseErr error) error {
	if s.config.Mode == ErrorSanitizationDisabled {
		return baseErr
	}

	// Sanitize the base error first to remove sensitive cryptographic material
	sanitizedBase := s.Sanitize(baseErr)

	var msg string
	if s.config.AllowParticipantID && s.config.AllowSessionID {
		msg = fmt.Sprintf("commitment validation failed for participant %v in session %s", participantID, sessionID)
	} else if s.config.AllowParticipantID {
		msg = fmt.Sprintf("commitment validation failed for participant %v", participantID)
	} else {
		msg = "commitment validation failed"
	}

	return fmt.Errorf("%s: %w", msg, sanitizedBase)
}

// SanitizeVerificationError creates a sanitized error for verification failures.
func (s *ErrorSanitizer) SanitizeVerificationError(operation string, baseErr error) error {
	if s.config.Mode == ErrorSanitizationDisabled {
		return baseErr
	}

	// Sanitize the base error first to remove sensitive cryptographic material
	sanitizedBase := s.Sanitize(baseErr)

	msg := fmt.Sprintf("verification failed for %s", operation)
	if sanitizedBase != nil {
		return fmt.Errorf("%s: %w", msg, sanitizedBase)
	}
	return errors.New(msg)
}

// Global sanitizer instance (defaults to production mode)
var globalSanitizer = NewErrorSanitizer(DefaultProductionErrorConfig())

// SetGlobalSanitizer sets the global error sanitizer instance.
// This should be called during application initialization.
func SetGlobalSanitizer(sanitizer *ErrorSanitizer) {
	if sanitizer != nil {
		globalSanitizer = sanitizer
	}
}

// SanitizeError sanitizes an error using the global sanitizer.
// This is a convenience function for common usage.
func SanitizeError(err error) error {
	return globalSanitizer.Sanitize(err)
}
