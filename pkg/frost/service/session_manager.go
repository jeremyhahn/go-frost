package service

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"

	"github.com/jeremyhahn/go-frost/pkg/frost"
)

// signingSession implements SigningSession interface.
type signingSession struct {
	id              string
	participantIDs  []frost.Identifier
	message         []byte
	commitments     map[frost.Identifier]frost.SigningCommitments
	signatureShares map[frost.Identifier]frost.SignatureShare
	commitmentList  frost.CommitmentList
	finalSignature  frost.Signature
	isComplete      bool
	isCanceled      bool
	service         FrostService
	minParticipants int
	mu              sync.RWMutex
}

// newSigningSession creates a new signing session.
func newSigningSession(id string, participantIDs []frost.Identifier, message []byte, service FrostService) *signingSession {
	return &signingSession{
		id:              id,
		participantIDs:  participantIDs,
		message:         message,
		commitments:     make(map[frost.Identifier]frost.SigningCommitments),
		signatureShares: make(map[frost.Identifier]frost.SignatureShare),
		service:         service,
		minParticipants: len(participantIDs),
	}
}

// ID implements SigningSession.ID
func (s *signingSession) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

// AddCommitment implements SigningSession.AddCommitment
func (s *signingSession) AddCommitment(commitment frost.SigningCommitments) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isCanceled {
		return frost.NewParameterError("session", "session is canceled", frost.ErrInvalidParameters)
	}

	if s.isComplete {
		return frost.NewParameterError("session", "session is already complete", frost.ErrInvalidParameters)
	}

	// Check if this participant is expected
	found := false
	for _, id := range s.participantIDs {
		if id == commitment.Identifier {
			found = true
			break
		}
	}

	if !found {
		return frost.NewParticipantError(commitment.Identifier, "not in participant list", frost.ErrInvalidParticipant)
	}

	// Check for duplicate
	if _, exists := s.commitments[commitment.Identifier]; exists {
		return frost.NewParticipantError(commitment.Identifier, "commitment already added", frost.ErrDuplicateParticipant)
	}

	s.commitments[commitment.Identifier] = commitment
	return nil
}

// GetCommitmentList implements SigningSession.GetCommitmentList
func (s *signingSession) GetCommitmentList() (frost.CommitmentList, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.isCanceled {
		return nil, frost.NewParameterError("session", "session is canceled", frost.ErrInvalidParameters)
	}

	if len(s.commitments) < s.minParticipants {
		return nil, frost.NewParameterError("commitments", "insufficient commitments", frost.ErrInsufficientParticipants)
	}

	// Build and sort commitment list
	commitmentList := make(frost.CommitmentList, 0, len(s.commitments))
	for _, commitment := range s.commitments {
		commitmentList = append(commitmentList, commitment)
	}

	// Sort by identifier
	sort.Slice(commitmentList, func(i, j int) bool {
		return commitmentList[i].Identifier < commitmentList[j].Identifier
	})

	return commitmentList, nil
}

// AddSignatureShare implements SigningSession.AddSignatureShare
func (s *signingSession) AddSignatureShare(share frost.SignatureShare) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isCanceled {
		return frost.NewParameterError("session", "session is canceled", frost.ErrInvalidParameters)
	}

	if s.isComplete {
		return frost.NewParameterError("session", "session is already complete", frost.ErrInvalidParameters)
	}

	// Check if this participant is expected
	found := false
	for _, id := range s.participantIDs {
		if id == share.Identifier {
			found = true
			break
		}
	}

	if !found {
		return frost.NewParticipantError(share.Identifier, "not in participant list", frost.ErrInvalidParticipant)
	}

	// Check for duplicate
	if _, exists := s.signatureShares[share.Identifier]; exists {
		return frost.NewParticipantError(share.Identifier, "signature share already added", frost.ErrDuplicateParticipant)
	}

	s.signatureShares[share.Identifier] = share
	return nil
}

// GetSignature implements SigningSession.GetSignature
func (s *signingSession) GetSignature() (frost.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isCanceled {
		return frost.Signature{}, frost.NewParameterError("session", "session is canceled", frost.ErrInvalidParameters)
	}

	if s.isComplete {
		return s.finalSignature, nil
	}

	if len(s.signatureShares) < s.minParticipants {
		return frost.Signature{}, frost.NewParameterError("signatureShares", "insufficient signature shares", frost.ErrInsufficientParticipants)
	}

	// Build commitment list
	commitmentList := make(frost.CommitmentList, 0, len(s.commitments))
	for _, commitment := range s.commitments {
		commitmentList = append(commitmentList, commitment)
	}

	// Sort by identifier
	sort.Slice(commitmentList, func(i, j int) bool {
		return commitmentList[i].Identifier < commitmentList[j].Identifier
	})

	// Build signature share list
	signatureShares := make([]frost.SignatureShare, 0, len(s.signatureShares))
	for _, share := range s.signatureShares {
		signatureShares = append(signatureShares, share)
	}

	// For a complete session-based signing implementation, we would need to:
	// 1. Store the group public key in the session
	// 2. Store key packages or participant information
	// 3. Use the aggregator to combine the signature shares
	//
	// Since this is a simplified implementation and the Sign method in FrostService
	// handles the complete flow, sessions are primarily useful for async/distributed scenarios
	// where the service layer would need more context.
	//
	// For now, return an error indicating this limitation
	return frost.Signature{}, frost.NewParameterError("session", "session-based aggregation requires group public key context", frost.ErrInvalidConfiguration)
}

// IsComplete implements SigningSession.IsComplete
func (s *signingSession) IsComplete() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isComplete
}

// Cancel implements SigningSession.Cancel
func (s *signingSession) Cancel() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isComplete {
		return frost.NewParameterError("session", "cannot cancel completed session", frost.ErrInvalidParameters)
	}

	s.isCanceled = true
	return nil
}

// sessionManager implements SessionManager interface.
type sessionManagerImpl struct {
	service  FrostService
	sessions map[string]SigningSession
	mu       sync.RWMutex
}

// NewSessionManager implements the package-level function.
func newSessionManager(service FrostService) SessionManager {
	return &sessionManagerImpl{
		service:  service,
		sessions: make(map[string]SigningSession),
	}
}

// CreateSession implements SessionManager.CreateSession
func (m *sessionManagerImpl) CreateSession(participantIDs []frost.Identifier, msg []byte) (SigningSession, error) {
	if participantIDs == nil {
		return nil, frost.NewParameterError("participantIDs", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(participantIDs) == 0 {
		return nil, frost.NewParameterError("participantIDs", "cannot be empty", frost.ErrInsufficientParticipants)
	}

	// Generate unique session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	// Create new session
	session := newSigningSession(sessionID, participantIDs, msg, m.service)

	// Store session
	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return session, nil
}

// GetSession implements SessionManager.GetSession
func (m *sessionManagerImpl) GetSession(sessionID string) (SigningSession, error) {
	if sessionID == "" {
		return nil, frost.NewParameterError("sessionID", "cannot be empty", frost.ErrInvalidParameters)
	}

	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, frost.NewParameterError("sessionID", "session not found", frost.ErrInvalidParameters)
	}

	return session, nil
}

// DeleteSession implements SessionManager.DeleteSession
func (m *sessionManagerImpl) DeleteSession(sessionID string) error {
	if sessionID == "" {
		return frost.NewParameterError("sessionID", "cannot be empty", frost.ErrInvalidParameters)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[sessionID]; !exists {
		return frost.NewParameterError("sessionID", "session not found", frost.ErrInvalidParameters)
	}

	delete(m.sessions, sessionID)
	return nil
}

// ListSessions implements SessionManager.ListSessions
func (m *sessionManagerImpl) ListSessions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionIDs := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		sessionIDs = append(sessionIDs, id)
	}

	return sessionIDs
}

// generateSessionID generates a unique session identifier.
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
