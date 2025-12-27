// Package service provides the service layer for FROST operations.
//
// The service layer provides clean separation between the public API and
// business logic. It orchestrates operations across multiple components
// (key generation, signing, verification) and enforces business rules.
package service

import (
	"sort"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// FrostService provides high-level FROST protocol operations.
// This is the main service interface that applications should use.
type FrostService interface {
	// GenerateKeys generates key shares for participants using a trusted dealer.
	//
	// Inputs:
	// - config: FROST configuration (min/max signers, group)
	// - participantIDs: List of participant identifiers
	//
	// Outputs:
	// - keyPackages: Key packages for each participant
	// - groupPublicKey: The group's public key
	GenerateKeys(config frost.Configuration, participantIDs []frost.Identifier) ([]frost.KeyPackage, group.Element, error)

	// Sign generates a FROST threshold signature.
	//
	// Inputs:
	// - keyPackages: Key packages for signing participants
	// - msg: The message to sign
	//
	// Outputs:
	// - signature: The FROST threshold signature
	//
	// This orchestrates the complete two-round signing protocol.
	Sign(keyPackages []frost.KeyPackage, msg []byte) (frost.Signature, error)

	// Verify verifies a FROST signature.
	//
	// Inputs:
	// - msg: The message that was signed
	// - signature: The signature to verify
	// - publicKey: The group's public key
	//
	// Errors:
	// - Returns error if signature verification fails
	Verify(msg []byte, signature frost.Signature, publicKey group.Element) error

	// VerifyKeyShare verifies a participant's key share.
	//
	// Inputs:
	// - keyPackage: The key package to verify
	//
	// Errors:
	// - Returns error if verification fails
	VerifyKeyShare(keyPackage frost.KeyPackage) error

	// GetCiphersuite returns the ciphersuite being used.
	GetCiphersuite() ciphersuite.Ciphersuite
}

// NewFrostService creates a new FROST service.
func NewFrostService(suite ciphersuite.Ciphersuite) FrostService {
	return &frostService{
		suite: suite,
	}
}

type frostService struct {
	suite ciphersuite.Ciphersuite
}

// GenerateKeys implements FrostService.GenerateKeys
func (s *frostService) GenerateKeys(config frost.Configuration, participantIDs []frost.Identifier) ([]frost.KeyPackage, group.Element, error) {
	// 1. Validate configuration
	if err := s.validateConfiguration(config); err != nil {
		return nil, nil, err
	}

	if err := s.validateParticipantIDs(participantIDs, config.MaxSigners); err != nil {
		return nil, nil, err
	}

	// 2. Create dealer
	dealer := keygen.NewDealer(s.suite)

	// 3. Generate shares (dealer will generate random secret if nil)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(nil, config.MinSigners, config.MaxSigners, participantIDs)
	if err != nil {
		return nil, nil, err
	}

	// 4. Return key packages and group public key
	return keyPackages, groupPublicKey, nil
}

// Sign implements FrostService.Sign
func (s *frostService) Sign(keyPackages []frost.KeyPackage, msg []byte) (frost.Signature, error) {
	// 1. Validate key packages
	if err := s.validateKeyPackages(keyPackages); err != nil {
		return frost.Signature{}, err
	}

	// Get min signers from first key package's verification shares length
	// The threshold is len(verificationShares) - 1 + 1 = len(verificationShares)
	// Actually, minSigners should be derived from polynomial degree
	// For simplicity, we check that we have enough participants
	if len(keyPackages) < 2 {
		return frost.Signature{}, frost.NewParameterError("keyPackages", "must have at least 2 participants", frost.ErrInsufficientParticipants)
	}

	// Extract minimum signers from the verification shares
	// The number of verification shares equals the polynomial degree + 1
	// which equals minSigners
	//nolint:gosec // len() cannot exceed uint32 max for FROST participants
	minSigners := uint32(len(keyPackages))
	if len(keyPackages[0].VerificationShares) > 0 {
		//nolint:gosec // len() cannot exceed uint32 max for FROST participants
		minSigners = uint32(len(keyPackages[0].VerificationShares))
	}

	// 2. Create participants from key packages
	participants := make([]signing.Participant, len(keyPackages))
	for i, pkg := range keyPackages {
		participants[i] = signing.NewParticipant(pkg, s.suite)
	}

	// 3. Execute round one - collect commitments and nonces
	noncesMap := make(map[frost.Identifier]frost.SigningNonces)
	commitments := make(frost.CommitmentList, len(participants))

	for i, participant := range participants {
		nonces, commitment, err := participant.RoundOne()
		if err != nil {
			return frost.Signature{}, frost.NewParticipantError(participant.Identifier(), "round one failed", err)
		}
		noncesMap[participant.Identifier()] = nonces
		commitments[i] = commitment
	}

	// 4. Sort commitment list
	s.sortCommitments(commitments)

	// 5. Execute round two - collect signature shares
	signatureShares := make([]frost.SignatureShare, len(participants))

	for i, participant := range participants {
		nonces := noncesMap[participant.Identifier()]
		share, err := participant.RoundTwo(nonces, msg, commitments)

		// Zeroize nonces immediately after use per RFC 9591 Section 7.3
		// This prevents nonces from remaining in memory longer than necessary
		nonces.Zeroize()

		if err != nil {
			return frost.Signature{}, frost.NewParticipantError(participant.Identifier(), "round two failed", err)
		}
		signatureShares[i] = share
	}

	// 6. Create aggregator and aggregate signature shares
	groupPublicKey := keyPackages[0].GroupPublicKey
	aggregator := signing.NewAggregator(s.suite, minSigners)

	signature, err := aggregator.Aggregate(groupPublicKey, commitments, msg, signatureShares)
	if err != nil {
		return frost.Signature{}, err
	}

	// 7. Return signature
	return signature, nil
}

// Verify implements FrostService.Verify
func (s *frostService) Verify(msg []byte, signature frost.Signature, publicKey group.Element) error {
	// 1. Validate inputs
	if signature.R == nil {
		return frost.NewParameterError("signature.R", "cannot be nil", frost.ErrInvalidSignature)
	}
	if signature.Z == nil {
		return frost.NewParameterError("signature.Z", "cannot be nil", frost.ErrInvalidSignature)
	}
	if publicKey == nil {
		return frost.NewParameterError("publicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	// 2. Create aggregator (minSigners doesn't matter for verification)
	aggregator := signing.NewAggregator(s.suite, 2)

	// 3. Verify signature
	err := aggregator.Verify(msg, signature, publicKey)
	if err != nil {
		return err
	}

	// 4. Return result
	return nil
}

// VerifyKeyShare implements FrostService.VerifyKeyShare
func (s *frostService) VerifyKeyShare(keyPackage frost.KeyPackage) error {
	// 1. Validate key package
	if keyPackage.SecretShare == nil {
		return frost.NewParameterError("keyPackage.SecretShare", "cannot be nil", frost.ErrInvalidKeyShare)
	}
	if len(keyPackage.VerificationShares) == 0 {
		return frost.NewParameterError("keyPackage.VerificationShares", "cannot be empty", frost.ErrInvalidKeyShare)
	}

	// 2. Create dealer
	dealer := keygen.NewDealer(s.suite)

	// 3. Verify share using verification shares
	err := dealer.VerifyShare(keyPackage.Identifier, keyPackage.SecretShare, keyPackage.VerificationShares)
	if err != nil {
		return err
	}

	// 4. Return result
	return nil
}

// GetCiphersuite implements FrostService.GetCiphersuite
func (s *frostService) GetCiphersuite() ciphersuite.Ciphersuite {
	return s.suite
}

// SigningSession manages state for a multi-round signing session.
// This is useful for asynchronous or distributed signing scenarios.
type SigningSession interface {
	// ID returns the unique session identifier.
	ID() string

	// AddCommitment adds a participant's commitment from round one.
	AddCommitment(commitment frost.SigningCommitments) error

	// GetCommitmentList returns the aggregated commitment list.
	// Returns error if insufficient commitments.
	GetCommitmentList() (frost.CommitmentList, error)

	// AddSignatureShare adds a participant's signature share from round two.
	AddSignatureShare(share frost.SignatureShare) error

	// GetSignature aggregates signature shares and returns the final signature.
	// Returns error if insufficient shares.
	GetSignature() (frost.Signature, error)

	// IsComplete returns true if the session has produced a final signature.
	IsComplete() bool

	// Cancel cancels the signing session.
	Cancel() error
}

// SessionManager manages multiple signing sessions.
type SessionManager interface {
	// CreateSession creates a new signing session.
	CreateSession(participantIDs []frost.Identifier, msg []byte) (SigningSession, error)

	// GetSession retrieves a signing session by ID.
	GetSession(sessionID string) (SigningSession, error)

	// DeleteSession removes a signing session.
	DeleteSession(sessionID string) error

	// ListSessions returns all active session IDs.
	ListSessions() []string
}

// NewSessionManager creates a new session manager.
func NewSessionManager(service FrostService) SessionManager {
	return newSessionManager(service)
}

// validateConfiguration validates FROST configuration parameters.
func (s *frostService) validateConfiguration(config frost.Configuration) error {
	if config.MinSigners < 2 {
		return frost.NewParameterError("minSigners", "must be at least 2", frost.ErrInvalidThreshold)
	}

	if config.MinSigners > config.MaxSigners {
		return frost.NewParameterError("minSigners", "cannot exceed maxSigners", frost.ErrInvalidThreshold)
	}

	if config.Group == nil {
		return frost.NewParameterError("group", "cannot be nil", frost.ErrInvalidConfiguration)
	}

	return nil
}

// validateParticipantIDs validates participant identifiers.
func (s *frostService) validateParticipantIDs(participantIDs []frost.Identifier, maxSigners uint32) error {
	if participantIDs == nil {
		return frost.NewParameterError("participantIDs", "cannot be nil", frost.ErrInvalidParameters)
	}

	if uint(len(participantIDs)) != uint(maxSigners) {
		return frost.NewParameterError("participantIDs", "length must equal maxSigners", frost.ErrInvalidParameters)
	}

	// Check for duplicate and zero participant IDs
	seen := make(map[frost.Identifier]bool)
	for _, id := range participantIDs {
		if id == 0 {
			return frost.NewParameterError("participantIDs", "cannot contain zero", frost.ErrInvalidParticipant)
		}
		if seen[id] {
			return frost.NewParameterError("participantIDs", "contains duplicate", frost.ErrDuplicateParticipant)
		}
		seen[id] = true
	}

	return nil
}

// validateKeyPackages validates key packages for signing.
func (s *frostService) validateKeyPackages(keyPackages []frost.KeyPackage) error {
	if keyPackages == nil {
		return frost.NewParameterError("keyPackages", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(keyPackages) == 0 {
		return frost.NewParameterError("keyPackages", "cannot be empty", frost.ErrInsufficientParticipants)
	}

	// Verify all key packages have the same group public key
	if len(keyPackages) > 1 {
		firstGroupPubKey := keyPackages[0].GroupPublicKey
		for i, pkg := range keyPackages[1:] {
			if !pkg.GroupPublicKey.Equal(firstGroupPubKey) {
				return frost.NewParticipantError(pkg.Identifier, "group public key mismatch", frost.ErrInvalidKeyShare)
			}

			// Check for duplicate participants
			for j := 0; j < i+1; j++ {
				if keyPackages[j].Identifier == pkg.Identifier {
					return frost.NewParticipantError(pkg.Identifier, "duplicate participant", frost.ErrDuplicateParticipant)
				}
			}
		}
	}

	return nil
}

// sortCommitments sorts a commitment list by participant identifier.
func (s *frostService) sortCommitments(commitments frost.CommitmentList) {
	sort.Slice(commitments, func(i, j int) bool {
		return commitments[i].Identifier < commitments[j].Identifier
	})
}
