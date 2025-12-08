package frost

import (
	"errors"
	"fmt"
)

// Error types for FROST protocol operations.
// All errors are typed to enable proper error handling and testing.

// CulpritError is an interface for errors that can identify malicious participants.
// This enables cheater detection and blame attribution in the FROST protocol.
type CulpritError interface {
	error
	// Culprits returns the identifiers of participants who caused the error.
	// An empty slice means no specific participant could be identified.
	Culprits() []Identifier
}

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
// It implements CulpritError for single-participant blame attribution.
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

// Culprits returns the single participant who caused this error.
func (e *ParticipantError) Culprits() []Identifier {
	return []Identifier{e.Identifier}
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

// SignatureShareError represents an error with one or more invalid signature shares.
// It implements CulpritError to identify which participants submitted invalid shares.
type SignatureShareError struct {
	culprits []Identifier
	Reason   string
	Err      error
}

func (e *SignatureShareError) Error() string {
	if len(e.culprits) == 0 {
		if e.Err != nil {
			return fmt.Sprintf("invalid signature share: %s: %v", e.Reason, e.Err)
		}
		return fmt.Sprintf("invalid signature share: %s", e.Reason)
	}
	if len(e.culprits) == 1 {
		if e.Err != nil {
			return fmt.Sprintf("invalid signature share from participant %d: %s: %v", e.culprits[0], e.Reason, e.Err)
		}
		return fmt.Sprintf("invalid signature share from participant %d: %s", e.culprits[0], e.Reason)
	}
	if e.Err != nil {
		return fmt.Sprintf("invalid signature shares from %d participants: %s: %v", len(e.culprits), e.Reason, e.Err)
	}
	return fmt.Sprintf("invalid signature shares from %d participants: %s", len(e.culprits), e.Reason)
}

func (e *SignatureShareError) Unwrap() error {
	return e.Err
}

// Culprits returns the identifiers of participants who submitted invalid shares.
func (e *SignatureShareError) Culprits() []Identifier {
	result := make([]Identifier, len(e.culprits))
	copy(result, e.culprits)
	return result
}

// NewSignatureShareError creates a new SignatureShareError with the given culprits.
func NewSignatureShareError(culprits []Identifier, reason string, err error) *SignatureShareError {
	c := make([]Identifier, len(culprits))
	copy(c, culprits)
	return &SignatureShareError{
		culprits: c,
		Reason:   reason,
		Err:      err,
	}
}

// AddCulprit adds a culprit to the error and returns the updated error.
func (e *SignatureShareError) AddCulprit(id Identifier) *SignatureShareError {
	e.culprits = append(e.culprits, id)
	return e
}

// ProofOfKnowledgeError represents an error with a proof of knowledge.
// It implements CulpritError to identify which participant submitted an invalid proof.
type ProofOfKnowledgeError struct {
	Identifier Identifier
	Reason     string
	Err        error
}

func (e *ProofOfKnowledgeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid proof of knowledge from participant %d: %s: %v", e.Identifier, e.Reason, e.Err)
	}
	return fmt.Sprintf("invalid proof of knowledge from participant %d: %s", e.Identifier, e.Reason)
}

func (e *ProofOfKnowledgeError) Unwrap() error {
	return e.Err
}

// Culprits returns the identifier of the participant who submitted an invalid proof.
func (e *ProofOfKnowledgeError) Culprits() []Identifier {
	return []Identifier{e.Identifier}
}

// NewProofOfKnowledgeError creates a new ProofOfKnowledgeError.
func NewProofOfKnowledgeError(identifier Identifier, reason string, err error) *ProofOfKnowledgeError {
	return &ProofOfKnowledgeError{
		Identifier: identifier,
		Reason:     reason,
		Err:        err,
	}
}

// SecretShareError represents an error with a secret share.
// It implements CulpritError to identify which participant sent an invalid share.
type SecretShareError struct {
	Identifier Identifier
	Reason     string
	Err        error
}

func (e *SecretShareError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid secret share from participant %d: %s: %v", e.Identifier, e.Reason, e.Err)
	}
	return fmt.Sprintf("invalid secret share from participant %d: %s", e.Identifier, e.Reason)
}

func (e *SecretShareError) Unwrap() error {
	return e.Err
}

// Culprits returns the identifier of the participant who sent an invalid share.
func (e *SecretShareError) Culprits() []Identifier {
	return []Identifier{e.Identifier}
}

// NewSecretShareError creates a new SecretShareError.
func NewSecretShareError(identifier Identifier, reason string, err error) *SecretShareError {
	return &SecretShareError{
		Identifier: identifier,
		Reason:     reason,
		Err:        err,
	}
}

// GetCulprits extracts culprits from an error if it implements CulpritError.
// Returns nil if the error does not implement CulpritError.
func GetCulprits(err error) []Identifier {
	var culpritErr CulpritError
	if errors.As(err, &culpritErr) {
		return culpritErr.Culprits()
	}
	return nil
}
