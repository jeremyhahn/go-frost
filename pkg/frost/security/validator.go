// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"fmt"
)

// MessageValidator validates messages before signing to prevent various attacks.
//
// This interface enables applications to implement custom validation logic
// to protect against:
//   - Signing oracle attacks (unintended message signatures)
//   - DoS attacks via extremely large messages
//   - Malformed or malicious message content
//   - Policy violations (e.g., signing forbidden content)
//
// Implementations should be stateless and thread-safe.
type MessageValidator interface {
	// ValidateStructure checks if the message has a valid structure.
	// This might include format validation, encoding checks, etc.
	ValidateStructure(msg []byte) error

	// ValidateSize checks if the message size is within acceptable limits.
	// This prevents DoS attacks via extremely large messages.
	ValidateSize(msg []byte) error

	// ValidatePolicy checks if the message complies with application policies.
	// This might include content filtering, allowlists/denylists, etc.
	ValidatePolicy(msg []byte) error

	// Validate performs all validation checks.
	// This is a convenience method that calls all other validation methods.
	Validate(msg []byte) error
}

// NoOpValidator is a validator that performs no validation.
// This is useful for testing, development, or when validation is handled externally.
//
// WARNING: Using NoOpValidator in production bypasses all message validation
// and should only be done if validation is performed at a higher layer.
type NoOpValidator struct{}

// NewNoOpValidator creates a new no-op validator.
func NewNoOpValidator() *NoOpValidator {
	return &NoOpValidator{}
}

// ValidateStructure always returns nil (no validation).
func (v *NoOpValidator) ValidateStructure(msg []byte) error {
	return nil
}

// ValidateSize always returns nil (no validation).
func (v *NoOpValidator) ValidateSize(msg []byte) error {
	return nil
}

// ValidatePolicy always returns nil (no validation).
func (v *NoOpValidator) ValidatePolicy(msg []byte) error {
	return nil
}

// Validate always returns nil (no validation).
func (v *NoOpValidator) Validate(msg []byte) error {
	return nil
}

// SizeValidator validates message size limits.
// This prevents DoS attacks via extremely large messages that could
// exhaust memory or cause excessive computation.
type SizeValidator struct {
	maxSize int // Maximum message size in bytes
}

// NewSizeValidator creates a new size validator with the specified maximum size.
// The maxSize parameter specifies the maximum allowed message size in bytes.
//
// Recommended limits:
//   - 1 MB (1024*1024) for general use
//   - 10 MB for applications that need to sign larger messages
//   - 100 KB for high-security environments
func NewSizeValidator(maxSize int) *SizeValidator {
	return &SizeValidator{
		maxSize: maxSize,
	}
}

// ValidateStructure always returns nil (no structure validation).
func (v *SizeValidator) ValidateStructure(msg []byte) error {
	return nil
}

// ValidateSize checks if the message size is within the configured limit.
func (v *SizeValidator) ValidateSize(msg []byte) error {
	if len(msg) > v.maxSize {
		return fmt.Errorf("message size %d exceeds maximum allowed size %d: %w",
			len(msg), v.maxSize, ErrMessageTooLarge)
	}
	return nil
}

// ValidatePolicy always returns nil (no policy validation).
func (v *SizeValidator) ValidatePolicy(msg []byte) error {
	return nil
}

// Validate performs size validation.
func (v *SizeValidator) Validate(msg []byte) error {
	return v.ValidateSize(msg)
}

// MaxSize returns the maximum allowed message size.
func (v *SizeValidator) MaxSize() int {
	return v.maxSize
}

// CompositeValidator combines multiple validators.
// All validators are executed in order, and validation fails on the first error.
type CompositeValidator struct {
	validators []MessageValidator
}

// NewCompositeValidator creates a new composite validator from multiple validators.
func NewCompositeValidator(validators ...MessageValidator) *CompositeValidator {
	return &CompositeValidator{
		validators: validators,
	}
}

// ValidateStructure runs structure validation on all validators.
func (v *CompositeValidator) ValidateStructure(msg []byte) error {
	for _, validator := range v.validators {
		if err := validator.ValidateStructure(msg); err != nil {
			return err
		}
	}
	return nil
}

// ValidateSize runs size validation on all validators.
func (v *CompositeValidator) ValidateSize(msg []byte) error {
	for _, validator := range v.validators {
		if err := validator.ValidateSize(msg); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePolicy runs policy validation on all validators.
func (v *CompositeValidator) ValidatePolicy(msg []byte) error {
	for _, validator := range v.validators {
		if err := validator.ValidatePolicy(msg); err != nil {
			return err
		}
	}
	return nil
}

// Validate runs all validation checks on all validators.
func (v *CompositeValidator) Validate(msg []byte) error {
	for _, validator := range v.validators {
		if err := validator.Validate(msg); err != nil {
			return err
		}
	}
	return nil
}

// Add appends a validator to the composite validator.
func (v *CompositeValidator) Add(validator MessageValidator) {
	v.validators = append(v.validators, validator)
}
