// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

func TestErrorSanitizer_Sanitize_ProductionMode(t *testing.T) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())

	tests := []struct {
		name        string
		input       error
		wantContain string
		wantNotContain []string
	}{
		{
			name:        "hex values are redacted",
			input:       fmt.Errorf("scalar value: 0x1234567890abcdef1234567890abcdef"),
			wantContain: "scalar value",
			wantNotContain: []string{"0x1234567890abcdef", "1234567890abcdef"},
		},
		{
			name:        "base64 values are redacted",
			input:       fmt.Errorf("commitment: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0"),
			wantContain: "commitment",
			wantNotContain: []string{"SGVsbG8gV29ybGQ"},
		},
		{
			name:        "byte arrays are redacted",
			input:       fmt.Errorf("nonce bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]"),
			wantContain: "nonce bytes",
			wantNotContain: []string{"[1, 2, 3,", "16]"},
		},
		{
			name:        "scalar field values are redacted",
			input:       fmt.Errorf("verification failed: scalar=0xabcd1234abcd1234abcd1234"),
			wantContain: "verification failed",
			wantNotContain: []string{"0xabcd1234"},
		},
		{
			name:        "nonce values are redacted",
			input:       fmt.Errorf("nonce reuse: nonce=secret_nonce_value_123456789"),
			wantContain: "nonce reuse",
			wantNotContain: []string{"secret_nonce_value"},
		},
		{
			name:        "commitment values are redacted",
			input:       fmt.Errorf("hiding=0x123456789abcdef0123456789abcdef0, binding=0xfedcba9876543210fedcba9876543210"),
			wantContain: "hiding=[REDACTED]",
			wantNotContain: []string{"0x123456789abcdef0", "0xfedcba987654"},
		},
		{
			name:        "signature values are redacted",
			input:       fmt.Errorf("signature verification failed: signature=0x9876543210abcdef9876543210abcdef"),
			wantContain: "signature=[REDACTED]",
			wantNotContain: []string{"0x987654321"},
		},
		{
			name:        "session IDs are redacted in production",
			input:       fmt.Errorf("session abc-123-def failed"),
			wantContain: "[REDACTED]",
			wantNotContain: []string{"abc-123-def"},
		},
		{
			name:        "multiple sensitive values are redacted",
			input:       fmt.Errorf("failed: scalar=0x1234567890abcdef1234, nonce=0xabcdefabcdefabcdefabcdef"),
			wantContain: "failed",
			wantNotContain: []string{"0x1234567890", "0xabcdefabcdef"},
		},
		{
			name:        "preserves error type for commitment reuse",
			input:       fmt.Errorf("commitment reuse detected: %w", ErrCommitmentReused),
			wantContain: "commitment reuse",
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)
			if result == nil {
				t.Fatal("expected error, got nil")
			}

			resultStr := result.Error()

			if tt.wantContain != "" && !strings.Contains(resultStr, tt.wantContain) {
				t.Errorf("expected result to contain %q, got: %s", tt.wantContain, resultStr)
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("expected result NOT to contain %q, but it does. Got: %s", notWant, resultStr)
				}
			}
		})
	}
}

func TestErrorSanitizer_Sanitize_DevelopmentMode(t *testing.T) {
	config := DefaultDevelopmentErrorConfig()
	sanitizer := NewErrorSanitizer(config)

	tests := []struct {
		name        string
		input       error
		wantContain []string
		wantNotContain []string
	}{
		{
			name:        "hex values show length in development (without field name)",
			input:       fmt.Errorf("error with standalone hex: 0x1234567890abcdef1234567890abcdef"),
			wantContain: []string{"error with standalone hex", "[HEX:"},
			wantNotContain: []string{"0x1234567890abcdef"},
		},
		{
			name:        "base64 values show length in development (without field name)",
			input:       fmt.Errorf("error with standalone base64: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0"),
			wantContain: []string{"error with standalone base64", "[B64:"},
			wantNotContain: []string{"SGVsbG8gV29ybGQ"},
		},
		{
			name:        "scalar fields are redacted but field name preserved",
			input:       fmt.Errorf("nonce=secret_value_12345678"),
			wantContain: []string{"nonce=[REDACTED]"},
			wantNotContain: []string{"secret_value"},
		},
		{
			name:        "commitment fields are redacted but field name preserved",
			input:       fmt.Errorf("hiding=0x1234567890abcdef1234567890abcdef"),
			wantContain: []string{"hiding=[REDACTED]"},
			wantNotContain: []string{"0x123456789"},
		},
		{
			name:        "session IDs preserved in development",
			input:       fmt.Errorf("session abc-123-def failed"),
			wantContain: []string{"session abc-123-def"},
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)
			if result == nil {
				t.Fatal("expected error, got nil")
			}

			resultStr := result.Error()

			for _, want := range tt.wantContain {
				if !strings.Contains(resultStr, want) {
					t.Errorf("expected result to contain %q, got: %s", want, resultStr)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("expected result NOT to contain %q, but it does. Got: %s", notWant, resultStr)
				}
			}
		})
	}
}

func TestErrorSanitizer_Sanitize_DisabledMode(t *testing.T) {
	config := ErrorSanitizerConfig{
		Mode:               ErrorSanitizationDisabled,
		AllowParticipantID: true,
		AllowSessionID:     true,
	}
	sanitizer := NewErrorSanitizer(config)

	input := fmt.Errorf("scalar=0x1234567890abcdef1234567890abcdef, nonce=secret")
	result := sanitizer.Sanitize(input)

	// In disabled mode, error should be unchanged
	if result.Error() != input.Error() {
		t.Errorf("expected error unchanged in disabled mode\ngot:  %s\nwant: %s", result.Error(), input.Error())
	}
}

func TestErrorSanitizer_Sanitize_NilError(t *testing.T) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())
	result := sanitizer.Sanitize(nil)
	if result != nil {
		t.Errorf("expected nil, got: %v", result)
	}
}

func TestErrorSanitizer_SanitizeCommitmentError(t *testing.T) {
	tests := []struct {
		name           string
		config         ErrorSanitizerConfig
		sessionID      string
		participantID  interface{}
		baseErr        error
		wantContain    []string
		wantNotContain []string
	}{
		{
			name:          "production mode with participant ID",
			config:        DefaultProductionErrorConfig(),
			sessionID:     "session-123",
			participantID: 42,
			baseErr:       ErrCommitmentReused,
			wantContain:   []string{"commitment validation failed", "participant 42"},
			wantNotContain: []string{"session-123"},
		},
		{
			name: "production mode without participant ID",
			config: ErrorSanitizerConfig{
				Mode:               ErrorSanitizationProduction,
				AllowParticipantID: false,
				AllowSessionID:     false,
			},
			sessionID:     "session-123",
			participantID: 42,
			baseErr:       ErrCommitmentReused,
			wantContain:   []string{"commitment validation failed"},
			wantNotContain: []string{"42", "session-123"},
		},
		{
			name:          "development mode with all IDs",
			config:        DefaultDevelopmentErrorConfig(),
			sessionID:     "session-123",
			participantID: 42,
			baseErr:       ErrCommitmentReused,
			wantContain:   []string{"commitment validation failed", "participant 42", "session session-123"},
			wantNotContain: []string{},
		},
		{
			name:          "disabled mode returns base error",
			config: ErrorSanitizerConfig{
				Mode:               ErrorSanitizationDisabled,
				AllowParticipantID: true,
				AllowSessionID:     true,
			},
			sessionID:     "session-123",
			participantID: 42,
			baseErr:       ErrCommitmentReused,
			wantContain:   []string{"commitment reused"},
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizer := NewErrorSanitizer(tt.config)
			result := sanitizer.SanitizeCommitmentError(tt.sessionID, tt.participantID, tt.baseErr)

			if result == nil {
				t.Fatal("expected error, got nil")
			}

			resultStr := result.Error()

			for _, want := range tt.wantContain {
				if !strings.Contains(resultStr, want) {
					t.Errorf("expected result to contain %q, got: %s", want, resultStr)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("expected result NOT to contain %q, but it does. Got: %s", notWant, resultStr)
				}
			}
		})
	}
}

func TestErrorSanitizer_SanitizeVerificationError(t *testing.T) {
	tests := []struct {
		name        string
		config      ErrorSanitizerConfig
		operation   string
		baseErr     error
		wantContain []string
	}{
		{
			name:        "production mode",
			config:      DefaultProductionErrorConfig(),
			operation:   "signature share",
			baseErr:     frost.ErrInvalidSignatureShare,
			wantContain: []string{"verification failed for signature share"},
		},
		{
			name:        "development mode",
			config:      DefaultDevelopmentErrorConfig(),
			operation:   "commitment",
			baseErr:     frost.ErrInvalidCommitment,
			wantContain: []string{"verification failed for commitment"},
		},
		{
			name: "disabled mode returns base error",
			config: ErrorSanitizerConfig{
				Mode:               ErrorSanitizationDisabled,
				AllowParticipantID: true,
				AllowSessionID:     true,
			},
			operation:   "signature",
			baseErr:     frost.ErrInvalidSignature,
			wantContain: []string{"invalid signature"},
		},
		{
			name:        "nil base error",
			config:      DefaultProductionErrorConfig(),
			operation:   "signature",
			baseErr:     nil,
			wantContain: []string{"verification failed for signature"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizer := NewErrorSanitizer(tt.config)
			result := sanitizer.SanitizeVerificationError(tt.operation, tt.baseErr)

			if result == nil {
				t.Fatal("expected error, got nil")
			}

			resultStr := result.Error()

			for _, want := range tt.wantContain {
				if !strings.Contains(resultStr, want) {
					t.Errorf("expected result to contain %q, got: %s", want, resultStr)
				}
			}
		})
	}
}

func TestSetGlobalSanitizer(t *testing.T) {
	// Save original sanitizer
	originalSanitizer := globalSanitizer

	// Test setting a new sanitizer
	newSanitizer := NewErrorSanitizer(DefaultDevelopmentErrorConfig())
	SetGlobalSanitizer(newSanitizer)

	if globalSanitizer != newSanitizer {
		t.Error("global sanitizer was not updated")
	}

	// Test setting nil (should not change)
	SetGlobalSanitizer(nil)
	if globalSanitizer != newSanitizer {
		t.Error("global sanitizer should not change when nil is passed")
	}

	// Restore original sanitizer
	globalSanitizer = originalSanitizer
}

func TestSanitizeError_GlobalSanitizer(t *testing.T) {
	// Save original sanitizer
	originalSanitizer := globalSanitizer
	defer func() { globalSanitizer = originalSanitizer }()

	// Set development mode globally
	SetGlobalSanitizer(NewErrorSanitizer(DefaultDevelopmentErrorConfig()))

	input := fmt.Errorf("error with standalone hex: 0x1234567890abcdef1234567890abcdef")
	result := SanitizeError(input)

	if result == nil {
		t.Fatal("expected error, got nil")
	}

	resultStr := result.Error()

	// Should contain HEX length indicator in development mode (for non-field hex values)
	if !strings.Contains(resultStr, "[HEX:") {
		t.Errorf("expected development mode sanitization with [HEX:], got: %s", resultStr)
	}

	// Should not contain the actual hex value
	if strings.Contains(resultStr, "0x1234567890abcdef") {
		t.Errorf("expected hex value to be redacted, got: %s", resultStr)
	}
}

func TestErrorSanitizer_PreservesErrorTypes(t *testing.T) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())

	tests := []struct {
		name     string
		input    error
		wantType error
	}{
		{
			name:     "commitment reused error preserved",
			input:    fmt.Errorf("some details: %w", ErrCommitmentReused),
			wantType: ErrCommitmentReused,
		},
		{
			name:     "authentication failed error preserved",
			input:    fmt.Errorf("auth details: %w", ErrAuthenticationFailed),
			wantType: ErrAuthenticationFailed,
		},
		{
			name:     "message validation failed error preserved",
			input:    fmt.Errorf("validation details: %w", ErrMessageValidationFailed),
			wantType: ErrMessageValidationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)

			if !errors.Is(result, tt.wantType) {
				t.Errorf("expected error to wrap %v, got: %v", tt.wantType, result)
			}
		})
	}
}

func TestErrorSanitizer_EdgeCases(t *testing.T) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())

	tests := []struct {
		name        string
		input       error
		description string
	}{
		{
			name:        "empty error message",
			input:       errors.New(""),
			description: "should handle empty messages gracefully",
		},
		{
			name:        "very long error message",
			input:       errors.New(strings.Repeat("test ", 1000)),
			description: "should handle long messages",
		},
		{
			name:        "special characters",
			input:       errors.New("error with \n newlines \t tabs \r returns"),
			description: "should handle special characters",
		},
		{
			name:        "unicode characters",
			input:       errors.New("error with unicode: 你好世界 🔐"),
			description: "should handle unicode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)
			if result == nil {
				t.Errorf("%s: expected error, got nil", tt.description)
			}
		})
	}
}

func TestErrorSanitizer_RealWorldExamples(t *testing.T) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())

	tests := []struct {
		name           string
		input          error
		wantNotContain []string
	}{
		{
			name:           "commitment reuse with actual commitment values",
			input:          fmt.Errorf("hiding commitment reuse detected for participant 2 in session abc-123: hiding=e2f207c98f6b7b1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6"),
			wantNotContain: []string{"e2f207c98f6b7b1a", "abc-123"},
		},
		{
			name:           "signature share verification failure",
			input:          fmt.Errorf("signature share verification failed: z=0x9876543210fedcba9876543210fedcba9876543210fedcba"),
			wantNotContain: []string{"0x9876543210fedcba"},
		},
		{
			name:           "nonce generation error with secret material",
			input:          fmt.Errorf("nonce generation failed: secret_share=abcdef1234567890abcdef1234567890, random=fedcba0987654321fedcba0987654321"),
			wantNotContain: []string{"abcdef1234567890", "fedcba0987654321"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)
			if result == nil {
				t.Fatal("expected error, got nil")
			}

			resultStr := result.Error()

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("expected result NOT to contain sensitive value %q, but it does. Got: %s", notWant, resultStr)
				}
			}
		})
	}
}

// Benchmark tests to ensure sanitization doesn't have excessive overhead
func BenchmarkErrorSanitizer_Production(b *testing.B) {
	sanitizer := NewErrorSanitizer(DefaultProductionErrorConfig())
	err := fmt.Errorf("signature verification failed: scalar=0x1234567890abcdef1234567890abcdef, nonce=0xfedcba0987654321fedcba0987654321")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.Sanitize(err)
	}
}

func BenchmarkErrorSanitizer_Development(b *testing.B) {
	sanitizer := NewErrorSanitizer(DefaultDevelopmentErrorConfig())
	err := fmt.Errorf("signature verification failed: scalar=0x1234567890abcdef1234567890abcdef, nonce=0xfedcba0987654321fedcba0987654321")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.Sanitize(err)
	}
}

func BenchmarkErrorSanitizer_Disabled(b *testing.B) {
	config := ErrorSanitizerConfig{
		Mode:               ErrorSanitizationDisabled,
		AllowParticipantID: true,
		AllowSessionID:     true,
	}
	sanitizer := NewErrorSanitizer(config)
	err := fmt.Errorf("signature verification failed: scalar=0x1234567890abcdef1234567890abcdef")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.Sanitize(err)
	}
}
