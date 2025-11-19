//go:build integration

package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// NetworkCoordinator orchestrates distributed FROST signing over HTTP.
type NetworkCoordinator struct {
	suite          ciphersuite.Ciphersuite
	nodeAddrs      map[frost.Identifier]string
	groupPublicKey []byte
	minSigners     uint32
	client         *http.Client
}

// NewNetworkCoordinator creates a new network coordinator.
func NewNetworkCoordinator(
	suite ciphersuite.Ciphersuite,
	nodeAddrs map[frost.Identifier]string,
	groupPublicKey []byte,
	minSigners uint32,
) *NetworkCoordinator {
	return &NetworkCoordinator{
		suite:          suite,
		nodeAddrs:      nodeAddrs,
		groupPublicKey: groupPublicKey,
		minSigners:     minSigners,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Sign orchestrates a complete distributed signing session.
func (nc *NetworkCoordinator) Sign(participantIDs []frost.Identifier, message []byte) (frost.Signature, error) {
	// Generate unique session ID
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())

	// Round 1: Collect commitments from all participants
	commitments, err := nc.collectCommitments(sessionID, participantIDs)
	if err != nil {
		return frost.Signature{}, fmt.Errorf("failed to collect commitments: %w", err)
	}

	// Sort commitments by identifier
	sort.Slice(commitments, func(i, j int) bool {
		return commitments[i].Identifier < commitments[j].Identifier
	})

	// Round 2: Collect signature shares from all participants
	shares, err := nc.collectSignatureShares(sessionID, participantIDs, message, commitments)
	if err != nil {
		return frost.Signature{}, fmt.Errorf("failed to collect signature shares: %w", err)
	}

	// Deserialize signature shares
	signatureShares := make([]frost.SignatureShare, len(shares))
	for i, share := range shares {
		z, err := nc.suite.Group().DeserializeScalar(share.SignatureShare)
		if err != nil {
			return frost.Signature{}, fmt.Errorf("failed to deserialize signature share %d: %w", i, err)
		}
		signatureShares[i] = frost.SignatureShare{
			Identifier:     share.Identifier,
			SignatureShare: z,
		}
	}

	// Deserialize commitments for aggregation
	frostCommitments := make(frost.CommitmentList, len(commitments))
	for i, sc := range commitments {
		hiding, err := nc.suite.Group().DeserializeElement(sc.HidingNonceCommitment)
		if err != nil {
			return frost.Signature{}, fmt.Errorf("failed to deserialize hiding commitment: %w", err)
		}

		binding, err := nc.suite.Group().DeserializeElement(sc.BindingNonceCommitment)
		if err != nil {
			return frost.Signature{}, fmt.Errorf("failed to deserialize binding commitment: %w", err)
		}

		frostCommitments[i] = frost.SigningCommitments{
			Identifier:             sc.Identifier,
			HidingNonceCommitment:  hiding,
			BindingNonceCommitment: binding,
		}
	}

	// Deserialize group public key
	groupPubKey, err := nc.suite.Group().DeserializeElement(nc.groupPublicKey)
	if err != nil {
		return frost.Signature{}, fmt.Errorf("failed to deserialize group public key: %w", err)
	}

	// Aggregate signature shares
	aggregator := signing.NewAggregator(nc.suite, nc.minSigners)
	signature, err := aggregator.Aggregate(groupPubKey, frostCommitments, message, signatureShares)
	if err != nil {
		return frost.Signature{}, fmt.Errorf("failed to aggregate signature: %w", err)
	}

	return signature, nil
}

// collectCommitments collects commitments from all participants in round one.
func (nc *NetworkCoordinator) collectCommitments(sessionID string, participantIDs []frost.Identifier) ([]SerializableCommitments, error) {
	commitments := make([]SerializableCommitments, len(participantIDs))
	errors := make(chan error, len(participantIDs))

	// Collect commitments concurrently
	for i, id := range participantIDs {
		go func(index int, participantID frost.Identifier) {
			commitment, err := nc.requestRoundOne(participantID, sessionID)
			if err != nil {
				errors <- fmt.Errorf("participant %d round one failed: %w", participantID, err)
				return
			}
			commitments[index] = commitment
			errors <- nil
		}(i, id)
	}

	// Wait for all responses
	for range participantIDs {
		if err := <-errors; err != nil {
			return nil, err
		}
	}

	return commitments, nil
}

// collectSignatureShares collects signature shares from all participants in round two.
func (nc *NetworkCoordinator) collectSignatureShares(
	sessionID string,
	participantIDs []frost.Identifier,
	message []byte,
	commitments []SerializableCommitments,
) ([]RoundTwoResponse, error) {
	shares := make([]RoundTwoResponse, len(participantIDs))
	errors := make(chan error, len(participantIDs))

	// Collect signature shares concurrently
	for i, id := range participantIDs {
		go func(index int, participantID frost.Identifier) {
			share, err := nc.requestRoundTwo(participantID, sessionID, message, commitments)
			if err != nil {
				errors <- fmt.Errorf("participant %d round two failed: %w", participantID, err)
				return
			}
			shares[index] = share
			errors <- nil
		}(i, id)
	}

	// Wait for all responses
	for range participantIDs {
		if err := <-errors; err != nil {
			return nil, err
		}
	}

	return shares, nil
}

// requestRoundOne sends a round one request to a participant node.
func (nc *NetworkCoordinator) requestRoundOne(participantID frost.Identifier, sessionID string) (SerializableCommitments, error) {
	addr, exists := nc.nodeAddrs[participantID]
	if !exists {
		return SerializableCommitments{}, fmt.Errorf("no address found for participant %d", participantID)
	}

	req := RoundOneRequest{
		SessionID: sessionID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return SerializableCommitments{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("http://%s/round1", addr)
	resp, err := nc.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return SerializableCommitments{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return SerializableCommitments{}, fmt.Errorf("round one failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var roundOneResp RoundOneResponse
	if err := json.NewDecoder(resp.Body).Decode(&roundOneResp); err != nil {
		return SerializableCommitments{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return roundOneResp.Commitments, nil
}

// requestRoundTwo sends a round two request to a participant node.
func (nc *NetworkCoordinator) requestRoundTwo(
	participantID frost.Identifier,
	sessionID string,
	message []byte,
	commitments []SerializableCommitments,
) (RoundTwoResponse, error) {
	addr, exists := nc.nodeAddrs[participantID]
	if !exists {
		return RoundTwoResponse{}, fmt.Errorf("no address found for participant %d", participantID)
	}

	req := RoundTwoRequest{
		SessionID:      sessionID,
		Message:        message,
		CommitmentList: commitments,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return RoundTwoResponse{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("http://%s/round2", addr)
	resp, err := nc.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return RoundTwoResponse{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return RoundTwoResponse{}, fmt.Errorf("round two failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var roundTwoResp RoundTwoResponse
	if err := json.NewDecoder(resp.Body).Decode(&roundTwoResp); err != nil {
		return RoundTwoResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return roundTwoResp, nil
}

// VerifySignature verifies a signature by querying a node.
func (nc *NetworkCoordinator) VerifySignature(
	participantID frost.Identifier,
	message []byte,
	signature frost.Signature,
) (bool, error) {
	addr, exists := nc.nodeAddrs[participantID]
	if !exists {
		return false, fmt.Errorf("no address found for participant %d", participantID)
	}

	req := VerifyRequest{
		Message:        message,
		SignatureR:     signature.R.Bytes(),
		SignatureZ:     signature.Z.Bytes(),
		GroupPublicKey: nc.groupPublicKey,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("http://%s/verify", addr)
	resp, err := nc.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("verify failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var verifyResp VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return verifyResp.Valid, nil
}
