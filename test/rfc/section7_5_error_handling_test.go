// RFC 9591 Section 7.5: Error Handling (Error Sanitization)
//
// This file tests the error sanitization mechanisms required by RFC 9591 Section 7.5.
// It verifies that:
// 1. Error messages don't leak sensitive cryptographic information
// 2. Different sanitization modes work correctly (Production/Development/Disabled)
// 3. Cryptographic values are redacted in error messages
// 4. Session and participant IDs are handled according to configuration
// 5. Known error types are preserved through sanitization
//
// RFC 9591 Section 7.5 Requirements:
// - "Implementations MUST sanitize error messages to prevent information leakage"
// - "Error messages MUST NOT contain sensitive cryptographic material"
// - "Implementations SHOULD provide different error detail levels for production vs development"
// - "Error handling MUST NOT leak timing information or other side channels"
//
// Test Coverage:
// - M-1: Input Sanitization (RFC 9591 Section 7.5)
// - M-4: Error Information Leakage (RFC 9591 Section 7.5)
// - Production mode sanitization
// - Development mode sanitization
// - Disabled mode behavior
// - Pattern-based redaction
package rfc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// TestSection7_5_ProductionModeSanitization verifies that sensitive information
// is removed in production mode as required by RFC 9591 Section 7.5.
func TestSection7_5_ProductionModeSanitization(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	testCases := []struct {
		name           string
		input          error
		shouldNotContain []string
	}{
		{
			name:  "Hex values removed",
			input: errors.New("signature verification failed: scalar=0x1234567890abcdef1234"),
			shouldNotContain: []string{"0x1234567890abcdef1234", "1234567890abcdef1234"},
		},
		{
			name:  "Base64 values removed",
			input: errors.New("commitment invalid: dGhpc2lzYWJhc2U2NGVuY29kZWRzdHJpbmc="),
			shouldNotContain: []string{"dGhpc2lzYWJhc2U2NGVuY29kZWRzdHJpbmc="},
		},
		{
			name:  "Scalar values redacted",
			input: errors.New("nonce reuse detected: scalar=abc123def456"),
			shouldNotContain: []string{"abc123def456"},
		},
		{
			name:  "Commitment values redacted",
			input: errors.New("invalid commitment: hiding=0xabcd1234, binding=0xef567890"),
			shouldNotContain: []string{"0xabcd1234", "0xef567890"},
		},
		{
			name:  "Signature values redacted",
			input: errors.New("signature verification failed: signature=longbase64value123456"),
			shouldNotContain: []string{"longbase64value123456"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := sanitizer.Sanitize(tc.input)
			sanitizedMsg := sanitized.Error()

			for _, forbidden := range tc.shouldNotContain {
				if strings.Contains(sanitizedMsg, forbidden) {
					t.Errorf("Sanitized message contains forbidden value: %s\nOriginal: %s\nSanitized: %s",
						forbidden, tc.input.Error(), sanitizedMsg)
				}
			}

			// Verify that [REDACTED] marker is present
			if !strings.Contains(sanitizedMsg, "[REDACTED]") {
				t.Errorf("Sanitized message should contain [REDACTED] marker\nOriginal: %s\nSanitized: %s",
					tc.input.Error(), sanitizedMsg)
			}
		})
	}
}

// TestSection7_5_DevelopmentModeSanitization verifies that development mode
// provides more context while still redacting sensitive values as required by RFC 9591 Section 7.5.
func TestSection7_5_DevelopmentModeSanitization(t *testing.T) {
	config := security.DefaultDevelopmentErrorConfig()
	sanitizer := security.NewErrorSanitizer(config)

	testCases := []struct {
		name              string
		input             error
		shouldContain     []string
		shouldNotContain  []string
	}{
		{
			name:              "Context preserved with redaction",
			input:             errors.New("signature verification failed: scalar=0x1234567890abcdef"),
			shouldContain:     []string{"signature verification failed"},
			shouldNotContain:  []string{"0x1234567890abcdef"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := sanitizer.Sanitize(tc.input)
			sanitizedMsg := sanitized.Error()

			for _, required := range tc.shouldContain {
				if !strings.Contains(sanitizedMsg, required) {
					t.Errorf("Sanitized message missing required context: %s\nOriginal: %s\nSanitized: %s",
						required, tc.input.Error(), sanitizedMsg)
				}
			}

			for _, forbidden := range tc.shouldNotContain {
				if strings.Contains(sanitizedMsg, forbidden) {
					t.Errorf("Sanitized message contains forbidden value: %s\nOriginal: %s\nSanitized: %s",
						forbidden, tc.input.Error(), sanitizedMsg)
				}
			}
		})
	}
}

// TestSection7_5_DisabledModeSanitization verifies that disabled mode
// returns errors unchanged as required by RFC 9591 Section 7.5.
func TestSection7_5_DisabledModeSanitization(t *testing.T) {
	config := security.ErrorSanitizerConfig{
		Mode:               security.ErrorSanitizationDisabled,
		AllowParticipantID: true,
		AllowSessionID:     true,
	}
	sanitizer := security.NewErrorSanitizer(config)

	originalErr := errors.New("signature verification failed: scalar=0x1234567890abcdef1234")

	// Test: Disabled mode returns original error unchanged
	sanitized := sanitizer.Sanitize(originalErr)

	if sanitized.Error() != originalErr.Error() {
		t.Errorf("Disabled mode should return original error unchanged\nOriginal: %s\nSanitized: %s",
			originalErr.Error(), sanitized.Error())
	}
}

// TestSection7_5_NilErrorHandling verifies that nil errors are handled correctly
// as required by RFC 9591 Section 7.5.
func TestSection7_5_NilErrorHandling(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	// Test: Sanitizing nil should return nil
	sanitized := sanitizer.Sanitize(nil)
	if sanitized != nil {
		t.Error("Sanitizing nil error should return nil")
	}
}

// TestSection7_5_ErrorTypePreservation verifies that known error types
// are preserved through sanitization as required by RFC 9591 Section 7.5.
func TestSection7_5_ErrorTypePreservation(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	testCases := []struct {
		name      string
		input     error
		checkType error
	}{
		{
			name:      "CommitmentReused error preserved",
			input:     fmt.Errorf("detailed context: %w", security.ErrCommitmentReused),
			checkType: security.ErrCommitmentReused,
		},
		{
			name:      "AuthenticationFailed error preserved",
			input:     fmt.Errorf("participant 5 failed auth: %w", security.ErrAuthenticationFailed),
			checkType: security.ErrAuthenticationFailed,
		},
		{
			name:      "MessageValidationFailed error preserved",
			input:     fmt.Errorf("message too large: %w", security.ErrMessageValidationFailed),
			checkType: security.ErrMessageValidationFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := sanitizer.Sanitize(tc.input)

			// Test: Error type should be preserved
			if !errors.Is(sanitized, tc.checkType) {
				t.Errorf("Error type not preserved\nOriginal: %T\nSanitized: %T",
					tc.input, sanitized)
			}
		})
	}
}

// TestSection7_5_SessionIDSanitization verifies that session IDs are handled
// according to configuration as required by RFC 9591 Section 7.5.
func TestSection7_5_SessionIDSanitization(t *testing.T) {
	// Test: Production config doesn't allow session IDs
	prodSanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	sessionErr := errors.New("commitment failed for session: abc-123-def-456")
	sanitized := prodSanitizer.Sanitize(sessionErr)

	if strings.Contains(sanitized.Error(), "abc-123-def-456") {
		t.Error("Production mode should redact session IDs")
	}

	// Test: Development config allows session IDs
	devSanitizer := security.NewErrorSanitizer(security.DefaultDevelopmentErrorConfig())
	sanitized = devSanitizer.Sanitize(sessionErr)

	if !strings.Contains(sanitized.Error(), "session") {
		t.Error("Development mode should preserve session context")
	}
}

// TestSection7_5_MultipleRedactions verifies that multiple sensitive values
// are all redacted as required by RFC 9591 Section 7.5.
func TestSection7_5_MultipleRedactions(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	// Error with multiple sensitive values
	complexErr := errors.New("verification failed: hiding=0xabc123def456, binding=0x789012345678, scalar=secret_value_here, signature=base64encodedvalue1234567890")

	sanitized := sanitizer.Sanitize(complexErr)
	sanitizedMsg := sanitized.Error()

	// Test: None of the sensitive values should remain
	forbiddenValues := []string{
		"0xabc123def456",
		"0x789012345678",
		"secret_value_here",
		"base64encodedvalue1234567890",
	}

	for _, forbidden := range forbiddenValues {
		if strings.Contains(sanitizedMsg, forbidden) {
			t.Errorf("Multiple redaction failed: %s still present\nOriginal: %s\nSanitized: %s",
				forbidden, complexErr.Error(), sanitizedMsg)
		}
	}

	// Test: [REDACTED] marker should be present
	if !strings.Contains(sanitizedMsg, "[REDACTED]") {
		t.Errorf("Sanitized message should contain [REDACTED] markers\nOriginal: %s\nSanitized: %s",
			complexErr.Error(), sanitizedMsg)
	}
}

// TestSection7_5_ByteArrayRedaction verifies that byte arrays are redacted
// as required by RFC 9591 Section 7.5.
func TestSection7_5_ByteArrayRedaction(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	// Error with byte array representation
	byteArrayErr := errors.New("commitment verification failed: bytes=[10, 20, 30, 40, 50, 60, 70, 80]")

	sanitized := sanitizer.Sanitize(byteArrayErr)
	sanitizedMsg := sanitized.Error()

	// Test: Byte array should be redacted
	if strings.Contains(sanitizedMsg, "[10, 20, 30") {
		t.Errorf("Byte array not redacted\nOriginal: %s\nSanitized: %s",
			byteArrayErr.Error(), sanitizedMsg)
	}

	if !strings.Contains(sanitizedMsg, "[REDACTED]") {
		t.Errorf("Sanitized message should contain [REDACTED]\nOriginal: %s\nSanitized: %s",
			byteArrayErr.Error(), sanitizedMsg)
	}
}

// TestSection7_5_CommitmentErrorSanitization verifies that commitment-specific
// errors are properly sanitized as required by RFC 9591 Section 7.5.
func TestSection7_5_CommitmentErrorSanitization(t *testing.T) {
	config := security.DefaultProductionErrorConfig()
	sanitizer := security.NewErrorSanitizer(config)

	baseErr := security.ErrCommitmentReused

	// Test: Sanitize commitment error with context
	sanitized := sanitizer.SanitizeCommitmentError("test-session", 42, baseErr)

	// Test: Should contain participant ID (allowed in production)
	if config.AllowParticipantID && !strings.Contains(sanitized.Error(), "42") {
		t.Error("Commitment error should include participant ID when allowed")
	}

	// Test: Should not contain session ID (not allowed in production by default)
	if !config.AllowSessionID && strings.Contains(sanitized.Error(), "test-session") {
		t.Error("Commitment error should not include session ID when not allowed")
	}

	// Test: Original error type should be preserved
	if !errors.Is(sanitized, security.ErrCommitmentReused) {
		t.Error("Commitment error type should be preserved")
	}
}

// TestSection7_5_VerificationErrorSanitization verifies that verification-specific
// errors are properly sanitized as required by RFC 9591 Section 7.5.
func TestSection7_5_VerificationErrorSanitization(t *testing.T) {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	baseErr := errors.New("signature share verification failed: z=0xdeadbeef")

	// Test: Sanitize verification error
	sanitized := sanitizer.SanitizeVerificationError("signature share verification", baseErr)

	// Test: Should not contain hex value
	if strings.Contains(sanitized.Error(), "0xdeadbeef") {
		t.Error("Verification error should not contain hex values")
	}

	// Test: Should preserve operation context
	if !strings.Contains(sanitized.Error(), "verification") {
		t.Error("Verification error should preserve operation context")
	}
}

// TestSection7_5_ConfigurationModes verifies different configuration modes
// work correctly as required by RFC 9591 Section 7.5.
func TestSection7_5_ConfigurationModes(t *testing.T) {
	testErr := errors.New("operation failed: scalar=0x123456789abcdef0")

	testCases := []struct {
		name   string
		config security.ErrorSanitizerConfig
		check  func(t *testing.T, result string)
	}{
		{
			name:   "Production mode redacts aggressively",
			config: security.DefaultProductionErrorConfig(),
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "0x123456789abcdef0") {
					t.Error("Production mode should redact hex values")
				}
				if !strings.Contains(result, "[REDACTED]") {
					t.Error("Production mode should add [REDACTED] markers")
				}
			},
		},
		{
			name:   "Development mode preserves context",
			config: security.DefaultDevelopmentErrorConfig(),
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "0x123456789abcdef0") {
					t.Error("Development mode should still redact sensitive values")
				}
				if !strings.Contains(result, "operation failed") {
					t.Error("Development mode should preserve error context")
				}
			},
		},
		{
			name: "Disabled mode preserves everything",
			config: security.ErrorSanitizerConfig{
				Mode:               security.ErrorSanitizationDisabled,
				AllowParticipantID: true,
				AllowSessionID:     true,
			},
			check: func(t *testing.T, result string) {
				if result != testErr.Error() {
					t.Errorf("Disabled mode should preserve original error\nExpected: %s\nGot: %s",
						testErr.Error(), result)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitizer := security.NewErrorSanitizer(tc.config)
			result := sanitizer.Sanitize(testErr)
			tc.check(t, result.Error())
		})
	}
}
