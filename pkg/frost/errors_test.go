package frost

import (
	"errors"
	"testing"
)

// TestParameterError_Error tests the Error() method of ParameterError.
func TestParameterError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParameterError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &ParameterError{
				Parameter: "threshold",
				Reason:    "must be greater than zero",
				Err:       ErrInvalidThreshold,
			},
			expected: "parameter threshold is invalid: must be greater than zero: invalid threshold",
		},
		{
			name: "without wrapped error",
			err: &ParameterError{
				Parameter: "maxParticipants",
				Reason:    "cannot exceed 65535",
				Err:       nil,
			},
			expected: "parameter maxParticipants is invalid: cannot exceed 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestParameterError_Unwrap tests the Unwrap() method of ParameterError.
func TestParameterError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParameterError
		expected error
	}{
		{
			name: "with wrapped error",
			err: &ParameterError{
				Parameter: "threshold",
				Reason:    "invalid value",
				Err:       ErrInvalidThreshold,
			},
			expected: ErrInvalidThreshold,
		},
		{
			name: "without wrapped error",
			err: &ParameterError{
				Parameter: "maxParticipants",
				Reason:    "invalid value",
				Err:       nil,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Unwrap()
			if result != tt.expected {
				t.Errorf("Unwrap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestNewParameterError tests the NewParameterError constructor.
func TestNewParameterError(t *testing.T) {
	tests := []struct {
		name      string
		parameter string
		reason    string
		err       error
	}{
		{
			name:      "with wrapped error",
			parameter: "threshold",
			reason:    "must be positive",
			err:       ErrInvalidThreshold,
		},
		{
			name:      "without wrapped error",
			parameter: "participants",
			reason:    "cannot be empty",
			err:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewParameterError(tt.parameter, tt.reason, tt.err)

			if result.Parameter != tt.parameter {
				t.Errorf("Parameter = %q, want %q", result.Parameter, tt.parameter)
			}
			if result.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.reason)
			}
			if result.Err != tt.err {
				t.Errorf("Err = %v, want %v", result.Err, tt.err)
			}

			// Verify it's usable with errors.Is
			if tt.err != nil && !errors.Is(result, tt.err) {
				t.Errorf("errors.Is() = false, want true for wrapped error")
			}
		})
	}
}

// TestParticipantError_Error tests the Error() method of ParticipantError.
func TestParticipantError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParticipantError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &ParticipantError{
				Identifier: Identifier(5),
				Reason:     "not found",
				Err:        ErrInvalidParticipant,
			},
			expected: "participant 5: not found: invalid participant",
		},
		{
			name: "without wrapped error",
			err: &ParticipantError{
				Identifier: Identifier(10),
				Reason:     "duplicate identifier",
				Err:        nil,
			},
			expected: "participant 10: duplicate identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestParticipantError_Unwrap tests the Unwrap() method of ParticipantError.
func TestParticipantError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParticipantError
		expected error
	}{
		{
			name: "with wrapped error",
			err: &ParticipantError{
				Identifier: Identifier(3),
				Reason:     "invalid",
				Err:        ErrInvalidParticipant,
			},
			expected: ErrInvalidParticipant,
		},
		{
			name: "without wrapped error",
			err: &ParticipantError{
				Identifier: Identifier(7),
				Reason:     "test",
				Err:        nil,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Unwrap()
			if result != tt.expected {
				t.Errorf("Unwrap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestNewParticipantError tests the NewParticipantError constructor.
func TestNewParticipantError(t *testing.T) {
	tests := []struct {
		name       string
		identifier Identifier
		reason     string
		err        error
	}{
		{
			name:       "with wrapped error",
			identifier: Identifier(1),
			reason:     "commitment missing",
			err:        ErrInvalidCommitment,
		},
		{
			name:       "without wrapped error",
			identifier: Identifier(2),
			reason:     "invalid signature share",
			err:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewParticipantError(tt.identifier, tt.reason, tt.err)

			if result.Identifier != tt.identifier {
				t.Errorf("Identifier = %d, want %d", result.Identifier, tt.identifier)
			}
			if result.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.reason)
			}
			if result.Err != tt.err {
				t.Errorf("Err = %v, want %v", result.Err, tt.err)
			}

			// Verify it's usable with errors.Is
			if tt.err != nil && !errors.Is(result, tt.err) {
				t.Errorf("errors.Is() = false, want true for wrapped error")
			}
		})
	}
}

// TestVerificationError_Error tests the Error() method of VerificationError.
func TestVerificationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *VerificationError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &VerificationError{
				Operation: "signature share",
				Reason:    "invalid proof",
				Err:       ErrInvalidSignatureShare,
			},
			expected: "verification failed for signature share: invalid proof: invalid signature share",
		},
		{
			name: "without wrapped error",
			err: &VerificationError{
				Operation: "group commitment",
				Reason:    "commitment mismatch",
				Err:       nil,
			},
			expected: "verification failed for group commitment: commitment mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestVerificationError_Unwrap tests the Unwrap() method of VerificationError.
func TestVerificationError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      *VerificationError
		expected error
	}{
		{
			name: "with wrapped error",
			err: &VerificationError{
				Operation: "commitment",
				Reason:    "invalid",
				Err:       ErrInvalidCommitment,
			},
			expected: ErrInvalidCommitment,
		},
		{
			name: "without wrapped error",
			err: &VerificationError{
				Operation: "signature",
				Reason:    "test",
				Err:       nil,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Unwrap()
			if result != tt.expected {
				t.Errorf("Unwrap() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestNewVerificationError tests the NewVerificationError constructor.
func TestNewVerificationError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		reason    string
		err       error
	}{
		{
			name:      "with wrapped error",
			operation: "VSS share",
			reason:    "polynomial evaluation mismatch",
			err:       ErrInvalidKeyShare,
		},
		{
			name:      "without wrapped error",
			operation: "challenge",
			reason:    "hash mismatch",
			err:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewVerificationError(tt.operation, tt.reason, tt.err)

			if result.Operation != tt.operation {
				t.Errorf("Operation = %q, want %q", result.Operation, tt.operation)
			}
			if result.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.reason)
			}
			if result.Err != tt.err {
				t.Errorf("Err = %v, want %v", result.Err, tt.err)
			}

			// Verify it's usable with errors.Is
			if tt.err != nil && !errors.Is(result, tt.err) {
				t.Errorf("errors.Is() = false, want true for wrapped error")
			}
		})
	}
}

// TestErrorTypes_Sentinel verifies that all sentinel errors are defined.
func TestErrorTypes_Sentinel(t *testing.T) {
	sentinelErrors := []error{
		ErrInvalidParameters,
		ErrInvalidParticipant,
		ErrInvalidCommitment,
		ErrInvalidSignatureShare,
		ErrInvalidSignature,
		ErrInvalidThreshold,
		ErrInsufficientParticipants,
		ErrDuplicateParticipant,
		ErrInvalidKeyShare,
		ErrInvalidPolynomial,
		ErrDeserializationFailed,
		ErrSerializationFailed,
		ErrIdentityElement,
		ErrZeroScalar,
		ErrInvalidNonce,
		ErrInvalidBindingFactor,
		ErrInvalidGroupCommitment,
		ErrInvalidChallenge,
		ErrUnsortedCommitments,
		ErrEmptyCommitmentList,
		ErrInvalidConfiguration,
	}

	for _, err := range sentinelErrors {
		if err == nil {
			t.Errorf("sentinel error is nil")
		}
		if err.Error() == "" {
			t.Errorf("sentinel error has empty message")
		}
	}
}

// TestErrorTypes_IsComparison tests that errors.Is works correctly with wrapped errors.
func TestErrorTypes_IsComparison(t *testing.T) {
	baseErr := ErrInvalidThreshold

	paramErr := NewParameterError("threshold", "too small", baseErr)
	if !errors.Is(paramErr, baseErr) {
		t.Error("ParameterError should unwrap to base error")
	}

	participantErr := NewParticipantError(Identifier(1), "invalid threshold", baseErr)
	if !errors.Is(participantErr, baseErr) {
		t.Error("ParticipantError should unwrap to base error")
	}

	verificationErr := NewVerificationError("threshold check", "failed", baseErr)
	if !errors.Is(verificationErr, baseErr) {
		t.Error("VerificationError should unwrap to base error")
	}
}

// TestErrorTypes_AsConversion tests that errors.As works correctly with typed errors.
func TestErrorTypes_AsConversion(t *testing.T) {
	t.Run("ParameterError", func(t *testing.T) {
		err := NewParameterError("test", "reason", nil)
		var paramErr *ParameterError
		if !errors.As(err, &paramErr) {
			t.Error("errors.As should succeed for ParameterError")
		}
		if paramErr.Parameter != "test" {
			t.Errorf("Parameter = %q, want %q", paramErr.Parameter, "test")
		}
	})

	t.Run("ParticipantError", func(t *testing.T) {
		err := NewParticipantError(Identifier(42), "reason", nil)
		var participantErr *ParticipantError
		if !errors.As(err, &participantErr) {
			t.Error("errors.As should succeed for ParticipantError")
		}
		if participantErr.Identifier != Identifier(42) {
			t.Errorf("Identifier = %d, want %d", participantErr.Identifier, 42)
		}
	})

	t.Run("VerificationError", func(t *testing.T) {
		err := NewVerificationError("test op", "reason", nil)
		var verifyErr *VerificationError
		if !errors.As(err, &verifyErr) {
			t.Error("errors.As should succeed for VerificationError")
		}
		if verifyErr.Operation != "test op" {
			t.Errorf("Operation = %q, want %q", verifyErr.Operation, "test op")
		}
	})
}
