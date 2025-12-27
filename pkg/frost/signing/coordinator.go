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

// Coordinator orchestrates the signing protocol among participants.
// The coordinator role is optional and can be removed for a fully distributed protocol.
type Coordinator interface {
	// RequestCommitments initiates round one by requesting commitments from participants.
	//
	// Inputs:
	// - participantIDs: List of participant identifiers to include in signing
	// - msg: The message to be signed
	//
	// Outputs:
	// - commitmentList: Aggregated and sorted commitment list
	//
	// The coordinator collects commitments from all participants and ensures
	// the list is properly sorted by identifier.
	RequestCommitments(participantIDs []frost.Identifier, msg []byte) (frost.CommitmentList, error)

	// RequestSignatureShares initiates round two by requesting signature shares.
	//
	// Inputs:
	// - commitmentList: The commitment list from round one
	// - msg: The message being signed
	//
	// Outputs:
	// - signatureShares: List of signature shares from participants
	//
	// The coordinator distributes the commitment list to all participants and
	// collects their signature shares.
	RequestSignatureShares(commitmentList frost.CommitmentList, msg []byte) ([]frost.SignatureShare, error)

	// Sign orchestrates the complete signing protocol.
	//
	// Inputs:
	// - participantIDs: List of participant identifiers to include
	// - msg: The message to sign
	//
	// Outputs:
	// - signature: The complete FROST signature
	//
	// This is a convenience method that runs both rounds and aggregation.
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

// NewCoordinatorWithAuthenticator creates a new signing coordinator with participant authentication.
//
// The authenticator is used to verify that commitments and signature shares
// come from legitimate participants, preventing impersonation attacks.
// This implements RFC 9591 Section 7.2 (authenticated channels).
//
// Production deployments should use Ed25519Authenticator or equivalent.
// For testing, use NoOpAuthenticator (insecure, skips authentication).
func NewCoordinatorWithAuthenticator(suite ciphersuite.Ciphersuite, participants map[frost.Identifier]Participant, aggregator Aggregator, groupPublicKey group.Element, authenticator security.ParticipantAuthenticator) Coordinator {
	return &coordinator{
		suite:          suite,
		participants:   participants,
		aggregator:     aggregator,
		groupPublicKey: groupPublicKey,
		authenticator:  authenticator,
	}
}

// NewCoordinatorWithSecurity creates a new signing coordinator with full security features.
//
// This constructor enables both authentication and reputation tracking for production deployments.
//
// Parameters:
//   - suite: The ciphersuite to use for cryptographic operations
//   - participants: Map of participant IDs to Participant instances
//   - aggregator: The signature aggregator
//   - groupPublicKey: The group's public verification key
//   - authenticator: Participant authenticator (use Ed25519Authenticator for production)
//   - reputationTracker: Reputation tracker for misbehavior tracking and DoS prevention
//
// Production deployments should use:
//   - Ed25519Authenticator for authentication
//   - InMemoryReputationTracker (or persistent implementation) for reputation tracking
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

// RequestCommitments implements Coordinator.RequestCommitments
//
// Initiates round one by requesting commitments from participants.
// The coordinator collects commitments from all participants and ensures
// the list is properly sorted by identifier.
//
// Algorithm (from RFC 9591 Section 5.1):
// 1. Validate participant IDs exist
// 2. Request commitments from each participant (RoundOne)
// 3. Collect commitments
// 4. Sort commitment list by identifier
// 5. Validate commitment list
// 6. Return sorted list
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

// RequestSignatureShares implements Coordinator.RequestSignatureShares
//
// Initiates round two by requesting signature shares.
// The coordinator distributes the commitment list to all participants and
// collects their signature shares.
//
// Algorithm (from RFC 9591 Section 5.2):
//  1. Validate commitment list
//  2. For each participant in commitment list:
//     a. Look up participant
//     b. Request signature share with commitment list and message
//     c. Optionally verify signature share (identifiable abort)
//  3. Collect all signature shares
//  4. Return signature shares
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

		// d. Optionally verify signature share (identifiable abort)
		// Per RFC 9591 Section 7.4, share verification is optional but enables identifying
		// malicious participants. Use AggregateWithVerification() instead of Aggregate()
		// to enable signature share verification with identifiable abort support.

		// 3. Collect signature share
		signatureShares = append(signatureShares, share)
	}

	// 4. Return signature shares
	return signatureShares, nil
}

// Sign implements Coordinator.Sign
//
// Orchestrates the complete signing protocol by running both rounds and aggregation.
// This is a convenience method that combines RequestCommitments, RequestSignatureShares,
// and Aggregate into a single operation.
//
// Algorithm (from RFC 9591 Section 5):
// 1. Request commitments from participants (Round 1)
// 2. Request signature shares using commitment list (Round 2)
// 3. Aggregate signature shares into final signature
// 4. Return signature
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

// AuthenticateCommitment verifies the authenticity of a commitment from a participant.
//
// This method should be called when receiving commitments from remote participants
// to prevent impersonation attacks (RFC 9591 Section 7.2).
//
// In a distributed FROST system, this would be called by the network/transport layer
// when a commitment message is received, before passing it to RequestCommitments.
//
// Parameters:
//   - participantID: The claimed sender of the commitment
//   - commitment: The signing commitments to verify
//   - proof: Authentication proof (e.g., digital signature over the commitment)
//
// Returns error if:
//   - No authenticator is configured
//   - Authentication fails (invalid proof, unknown participant, etc.)
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

// AuthenticateSignatureShare verifies the authenticity of a signature share from a participant.
//
// This method should be called when receiving signature shares from remote participants
// to prevent impersonation attacks (RFC 9591 Section 7.2).
//
// In a distributed FROST system, this would be called by the network/transport layer
// when a signature share message is received, before passing it to RequestSignatureShares.
//
// Parameters:
//   - participantID: The claimed sender of the signature share
//   - share: The signature share to verify
//   - proof: Authentication proof (e.g., digital signature over the share)
//
// Returns error if:
//   - No authenticator is configured
//   - Authentication fails (invalid proof, unknown participant, etc.)
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
