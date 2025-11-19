package frost

import (
	"errors"
	"fmt"
)

// Error types for FROST protocol operations.
// All errors are typed to enable proper error handling and testing.

var (
	// ErrInvalidParameters is returned when function parameters are invalid.
	ErrInvalidParameters = errors.New("invalid parameters")

	// ErrInvalidParticipant is returned when a participant identifier is not recognized.
	ErrInvalidParticipant = errors.New("invalid participant")

	// ErrInvalidCommitment is returned when a commitment is invalid.
	ErrInvalidCommitment = errors.New("invalid commitment")

	// ErrInvalidSignatureShare is returned when a signature share is invalid.
	ErrInvalidSignatureShare = errors.New("invalid signature share")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidThreshold is returned when threshold parameters are invalid.
	ErrInvalidThreshold = errors.New("invalid threshold")

	// ErrInsufficientParticipants is returned when not enough participants are available.
	ErrInsufficientParticipants = errors.New("insufficient participants")

	// ErrDuplicateParticipant is returned when duplicate participant identifiers are detected.
	ErrDuplicateParticipant = errors.New("duplicate participant")

	// ErrInvalidKeyShare is returned when a key share is invalid.
	ErrInvalidKeyShare = errors.New("invalid key share")

	// ErrInvalidPolynomial is returned when a polynomial is invalid.
	ErrInvalidPolynomial = errors.New("invalid polynomial")

	// ErrDeserializationFailed is returned when deserialization of group elements or scalars fails.
	ErrDeserializationFailed = errors.New("deserialization failed")

	// ErrSerializationFailed is returned when serialization of group elements or scalars fails.
	ErrSerializationFailed = errors.New("serialization failed")

	// ErrIdentityElement is returned when an identity element is encountered where not allowed.
	ErrIdentityElement = errors.New("identity element not allowed")

	// ErrZeroScalar is returned when a zero scalar is encountered where not allowed.
	ErrZeroScalar = errors.New("zero scalar not allowed")

	// ErrInvalidNonce is returned when a nonce is invalid or has been reused.
	ErrInvalidNonce = errors.New("invalid nonce")

	// ErrInvalidBindingFactor is returned when a binding factor computation fails.
	ErrInvalidBindingFactor = errors.New("invalid binding factor")

	// ErrInvalidGroupCommitment is returned when group commitment computation fails.
	ErrInvalidGroupCommitment = errors.New("invalid group commitment")

	// ErrInvalidChallenge is returned when challenge computation fails.
	ErrInvalidChallenge = errors.New("invalid challenge")

	// ErrUnsortedCommitments is returned when commitment list is not sorted.
	ErrUnsortedCommitments = errors.New("commitment list must be sorted by identifier")

	// ErrEmptyCommitmentList is returned when commitment list is empty.
	ErrEmptyCommitmentList = errors.New("commitment list cannot be empty")

	// ErrInvalidConfiguration is returned when FROST configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid configuration")
)

// ParameterError wraps an error with additional context about invalid parameters.
type ParameterError struct {
	Parameter string
	Reason    string
	Err       error
}

func (e *ParameterError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("parameter %s is invalid: %s: %v", e.Parameter, e.Reason, e.Err)
	}
	return fmt.Sprintf("parameter %s is invalid: %s", e.Parameter, e.Reason)
}

func (e *ParameterError) Unwrap() error {
	return e.Err
}

// NewParameterError creates a new ParameterError.
func NewParameterError(parameter, reason string, err error) *ParameterError {
	return &ParameterError{
		Parameter: parameter,
		Reason:    reason,
		Err:       err,
	}
}

// ParticipantError wraps an error with additional context about a participant.
type ParticipantError struct {
	Identifier Identifier
	Reason     string
	Err        error
}

func (e *ParticipantError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("participant %d: %s: %v", e.Identifier, e.Reason, e.Err)
	}
	return fmt.Sprintf("participant %d: %s", e.Identifier, e.Reason)
}

func (e *ParticipantError) Unwrap() error {
	return e.Err
}

// NewParticipantError creates a new ParticipantError.
func NewParticipantError(identifier Identifier, reason string, err error) *ParticipantError {
	return &ParticipantError{
		Identifier: identifier,
		Reason:     reason,
		Err:        err,
	}
}

// VerificationError wraps an error that occurs during verification operations.
type VerificationError struct {
	Operation string
	Reason    string
	Err       error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("verification failed for %s: %s: %v", e.Operation, e.Reason, e.Err)
	}
	return fmt.Sprintf("verification failed for %s: %s", e.Operation, e.Reason)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// NewVerificationError creates a new VerificationError.
func NewVerificationError(operation, reason string, err error) *VerificationError {
	return &VerificationError{
		Operation: operation,
		Reason:    reason,
		Err:       err,
	}
}
