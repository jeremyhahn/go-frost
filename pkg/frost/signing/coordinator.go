package signing

import (
	"sort"
	"sync"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Coordinator runs the signing protocol among participants; the role is optional.
type Coordinator interface {
	// RequestCommitments runs round one and returns the sorted commitment list.
	RequestCommitments(participantIDs []frost.Identifier, msg []byte) (frost.CommitmentList, error)

	// RequestSignatureShares runs round two and returns the participants' signature shares.
	RequestSignatureShares(commitmentList frost.CommitmentList, msg []byte) ([]frost.SignatureShare, error)

	// Sign runs both rounds and aggregation.
	Sign(participantIDs []frost.Identifier, msg []byte) (frost.Signature, error)
}

// NewCoordinator creates a new signing coordinator.
func NewCoordinator(suite ciphersuite.Ciphersuite, participants map[frost.Identifier]Participant, aggregator Aggregator) Coordinator {
	return &coordinator{
		suite:        suite,
		participants: participants,
		aggregator:   aggregator,
	}
}

// NewCoordinatorWithPublicKey creates a new signing coordinator with a group public key.
func NewCoordinatorWithPublicKey(suite ciphersuite.Ciphersuite, participants map[frost.Identifier]Participant, aggregator Aggregator, groupPublicKey group.Element) Coordinator {
	return &coordinator{
		suite:          suite,
		participants:   participants,
		aggregator:     aggregator,
		groupPublicKey: groupPublicKey,
	}
}

// NewCoordinatorWithAuthenticator returns a coordinator that authenticates commitments and shares (RFC 9591 Section 7.2).
func NewCoordinatorWithAuthenticator(suite ciphersuite.Ciphersuite, participants map[frost.Identifier]Participant, aggregator Aggregator, groupPublicKey group.Element, authenticator security.ParticipantAuthenticator) Coordinator {
	return &coordinator{
		suite:          suite,
		participants:   participants,
		aggregator:     aggregator,
		groupPublicKey: groupPublicKey,
		authenticator:  authenticator,
	}
}

// NewCoordinatorWithSecurity returns a coordinator with participant authentication and reputation tracking.
func NewCoordinatorWithSecurity(suite ciphersuite.Ciphersuite, participants map[frost.Identifier]Participant, aggregator Aggregator, groupPublicKey group.Element, authenticator security.ParticipantAuthenticator, reputationTracker security.ReputationTracker) Coordinator {
	return &coordinator{
		suite:             suite,
		participants:      participants,
		aggregator:        aggregator,
		groupPublicKey:    groupPublicKey,
		authenticator:     authenticator,
		reputationTracker: reputationTracker,
	}
}

type coordinator struct {
	suite             ciphersuite.Ciphersuite
	participants      map[frost.Identifier]Participant
	aggregator        Aggregator
	groupPublicKey    group.Element
	authenticator     security.ParticipantAuthenticator // Optional: for authenticated channels (RFC 9591 Section 7.2)
	reputationTracker security.ReputationTracker        // Optional: for misbehavior tracking and DoS prevention

	// Nonce management for stateful signing sessions
	mu        sync.Mutex
	noncesMap map[frost.Identifier]frost.SigningNonces
}

// RequestCommitments implements Coordinator.RequestCommitments per RFC 9591 Section 5.1.
func (c *coordinator) RequestCommitments(participantIDs []frost.Identifier, _ []byte) (frost.CommitmentList, error) {
	// 1. Validate participant IDs exist
	if len(participantIDs) == 0 {
		return nil, frost.ErrInsufficientParticipants
	}

	// 1.5. Check reputation tracker for excluded participants
	if c.reputationTracker != nil {
		for _, id := range participantIDs {
			excluded, err := c.reputationTracker.IsExcluded(id)
			if err != nil {
				return nil, frost.NewParticipantError(id, "failed to check reputation", err)
			}
			if excluded {
				return nil, frost.NewParticipantError(id, "participant is excluded", security.ErrParticipantExcluded)
			}
		}
	}

	// 2 & 3. Request and collect commitments from each participant
	commitments := make(frost.CommitmentList, 0, len(participantIDs))

	// Initialize nonces storage for this signing session
	c.mu.Lock()
	c.noncesMap = make(map[frost.Identifier]frost.SigningNonces)
	c.mu.Unlock()

	for _, id := range participantIDs {
		participant, exists := c.participants[id]
		if !exists {
			return nil, frost.ErrInvalidParticipant
		}

		// Request round one from participant
		nonces, commitment, err := participant.RoundOne()
		if err != nil {
			// Track invalid commitment misbehavior (best-effort, original error takes precedence)
			if c.reputationTracker != nil {
				_ = c.reputationTracker.RecordMisbehavior(id, security.MisbehaviorInvalidCommitment, err.Error())
			}
			return nil, frost.NewParticipantError(id, "failed to generate commitment", err)
		}

		// Store nonces for use in round two
		c.mu.Lock()
		c.noncesMap[id] = nonces
		c.mu.Unlock()

		commitments = append(commitments, commitment)
	}

	// 4. Sort commitment list by identifier
	sort.Slice(commitments, func(i, j int) bool {
		return commitments[i].Identifier < commitments[j].Identifier
	})

	// 5. Validate commitment list
	encoder := helpers.NewCommitmentListEncoder(c.suite.Group())
	if err := encoder.ValidateCommitmentList(commitments); err != nil {
		return nil, err
	}

	// 6. Return sorted list
	return commitments, nil
}

// RequestSignatureShares implements Coordinator.RequestSignatureShares per RFC 9591 Section 5.2.
func (c *coordinator) RequestSignatureShares(commitmentList frost.CommitmentList, msg []byte) ([]frost.SignatureShare, error) {
	// 1. Validate commitment list
	encoder := helpers.NewCommitmentListEncoder(c.suite.Group())
	if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
		return nil, err
	}

	// 2. For each participant in commitment list
	signatureShares := make([]frost.SignatureShare, 0, len(commitmentList))

	for _, commitment := range commitmentList {
		// a. Look up participant
		participant, exists := c.participants[commitment.Identifier]
		if !exists {
			return nil, frost.NewParticipantError(commitment.Identifier, "not found in participant map", frost.ErrInvalidParticipant)
		}

		// b. Retrieve stored nonces from round one
		c.mu.Lock()
		nonces, nonceExists := c.noncesMap[commitment.Identifier]
		if nonceExists {
			// Remove from map immediately (will be zeroized after use)
			delete(c.noncesMap, commitment.Identifier)
		}
		c.mu.Unlock()

		if !nonceExists {
			return nil, frost.NewParticipantError(commitment.Identifier, "nonces not found - RequestCommitments must be called first", frost.ErrInvalidNonce)
		}

		// c. Request signature share with stored nonces
		share, err := participant.RoundTwo(nonces, msg, commitmentList)

		// Zeroize nonces immediately after use per RFC 9591 Section 7.3
		nonces.Zeroize()

		if err != nil {
			// Track invalid share misbehavior (best-effort, original error takes precedence)
			if c.reputationTracker != nil {
				_ = c.reputationTracker.RecordMisbehavior(commitment.Identifier, security.MisbehaviorInvalidShare, err.Error())
			}
			return nil, frost.NewParticipantError(commitment.Identifier, "failed to generate signature share", err)
		}

		// Share verification (RFC 9591 Section 7.4) happens in AggregateWithVerification.

		// 3. Collect signature share
		signatureShares = append(signatureShares, share)
	}

	// 4. Return signature shares
	return signatureShares, nil
}

// Sign implements Coordinator.Sign: commitments, shares, then aggregation.
func (c *coordinator) Sign(participantIDs []frost.Identifier, msg []byte) (frost.Signature, error) {
	// Validate group public key is set
	if c.groupPublicKey == nil {
		return frost.Signature{}, frost.NewParameterError("groupPublicKey", "must be set before signing", frost.ErrInvalidParameters)
	}

	// 1. Request commitments from participants
	commitmentList, err := c.RequestCommitments(participantIDs, msg)
	if err != nil {
		return frost.Signature{}, err
	}

	// 2. Request signature shares using commitment list
	signatureShares, err := c.RequestSignatureShares(commitmentList, msg)
	if err != nil {
		return frost.Signature{}, err
	}

	// 3. Aggregate signature shares into final signature
	signature, err := c.aggregator.Aggregate(c.groupPublicKey, commitmentList, msg, signatureShares)
	if err != nil {
		return frost.Signature{}, err
	}

	// 4. Return signature
	return signature, nil
}

// AuthenticateCommitment verifies a remote participant's commitment before RequestCommitments; errors without an authenticator.
func (c *coordinator) AuthenticateCommitment(participantID frost.Identifier, commitment frost.SigningCommitments, proof []byte) error {
	if c.authenticator == nil {
		return frost.NewParameterError("authenticator", "no authenticator configured", frost.ErrInvalidParameters)
	}

	err := c.authenticator.AuthenticateCommitment(participantID, commitment, proof)
	if err != nil {
		// Track authentication failure (best-effort, original error takes precedence)
		if c.reputationTracker != nil {
			_ = c.reputationTracker.RecordMisbehavior(participantID, security.MisbehaviorAuthenticationFailure, "commitment authentication failed")
		}
	}
	return err
}

// AuthenticateSignatureShare verifies a remote participant's share before RequestSignatureShares; errors without an authenticator.
func (c *coordinator) AuthenticateSignatureShare(participantID frost.Identifier, share frost.SignatureShare, proof []byte) error {
	if c.authenticator == nil {
		return frost.NewParameterError("authenticator", "no authenticator configured", frost.ErrInvalidParameters)
	}

	err := c.authenticator.AuthenticateSignatureShare(participantID, share, proof)
	if err != nil {
		// Track authentication failure (best-effort, original error takes precedence)
		if c.reputationTracker != nil {
			_ = c.reputationTracker.RecordMisbehavior(participantID, security.MisbehaviorAuthenticationFailure, "signature share authentication failed")
		}
	}
	return err
}
