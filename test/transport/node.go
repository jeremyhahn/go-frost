//go:build integration

// Package transport provides distributed network transport tests for the FROST protocol.
// These tests verify that FROST works correctly in a real distributed environment with
// actual HTTP network communication between independent participant nodes.
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// Node represents a FROST participant node that exposes HTTP endpoints
// for participating in distributed signing protocols.
type Node struct {
	id          frost.Identifier
	addr        string
	suite       ciphersuite.Ciphersuite
	keyPackage  frost.KeyPackage
	participant signing.Participant
	server      *http.Server
	listener    net.Listener

	// Session management
	sessions map[string]*NodeSession
	mu       sync.RWMutex
}

// NodeSession represents a signing session on a node.
type NodeSession struct {
	sessionID   string
	nonces      frost.SigningNonces
	commitments frost.SigningCommitments
	createdAt   time.Time
}

// NewNode creates a new FROST participant node.
func NewNode(id frost.Identifier, addr string, suite ciphersuite.Ciphersuite, keyPackage frost.KeyPackage) *Node {
	node := &Node{
		id:          id,
		addr:        addr,
		suite:       suite,
		keyPackage:  keyPackage,
		participant: signing.NewParticipant(keyPackage, suite),
		sessions:    make(map[string]*NodeSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/round1", node.handleRoundOne)
	mux.HandleFunc("/round2", node.handleRoundTwo)
	mux.HandleFunc("/verify", node.handleVerify)
	mux.HandleFunc("/health", node.handleHealth)

	node.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return node
}

// Addr returns the address the node is actually listening on. It is only
// meaningful after a successful Start: when the node is constructed with port
// 0 the real port is not known until the listener is bound.
func (n *Node) Addr() string {
	return n.addr
}

// Start binds the node's listener and serves on it in a background goroutine.
//
// The bind is deliberately synchronous. The previous version called
// ListenAndServe inside the goroutine, printed any error, and then decided the
// node was ready as soon as *something* answered GET /health on the configured
// address. When the port was already taken that probe was answered by the
// unrelated process holding it, so Start reported success for a node that had
// never bound — and the test then spoke FROST to a stranger. Binding here
// means a port conflict fails immediately, with the address in the error,
// instead of being papered over by a readiness check that cannot tell this
// node's server from anyone else's.
func (n *Node) Start() error {
	ln, err := net.Listen("tcp", n.server.Addr)
	if err != nil {
		return fmt.Errorf("node %d: listen on %s: %w", n.id, n.server.Addr, err)
	}

	// Record the bound address: with port 0 the kernel picks the port, and
	// that resolved value is what peers must be told to dial.
	n.addr = ln.Addr().String()
	n.listener = ln

	go func() {
		if err := n.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Node %d server error: %v\n", n.id, err)
		}
	}()

	// The listener is already accepting by the time Serve is called, so this
	// only waits for the handler goroutine to be scheduled. Poll until the
	// node answers rather than sleeping a fixed amount.
	for i := 0; i < 50; i++ {
		resp, err := http.Get(fmt.Sprintf("http://%s/health", n.addr))
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = n.Stop()
	return fmt.Errorf("node %d bound %s but never answered /health", n.id, n.addr)
}

// Stop stops the HTTP server.
func (n *Node) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return n.server.Shutdown(ctx)
}

// RoundOneRequest represents a request to initiate round one.
type RoundOneRequest struct {
	SessionID string `json:"session_id"`
}

// RoundOneResponse represents the response from round one.
type RoundOneResponse struct {
	SessionID   string                  `json:"session_id"`
	Identifier  frost.Identifier        `json:"identifier"`
	Commitments SerializableCommitments `json:"commitments"`
}

// RoundTwoRequest represents a request to perform round two.
type RoundTwoRequest struct {
	SessionID      string                    `json:"session_id"`
	Message        []byte                    `json:"message"`
	CommitmentList []SerializableCommitments `json:"commitment_list"`
}

// RoundTwoResponse represents the response from round two.
type RoundTwoResponse struct {
	Identifier     frost.Identifier `json:"identifier"`
	SignatureShare []byte           `json:"signature_share"`
}

// VerifyRequest represents a signature verification request.
type VerifyRequest struct {
	Message        []byte `json:"message"`
	SignatureR     []byte `json:"signature_r"`
	SignatureZ     []byte `json:"signature_z"`
	GroupPublicKey []byte `json:"group_public_key"`
}

// VerifyResponse represents a signature verification response.
type VerifyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// SerializableCommitments represents commitments in a serializable format.
type SerializableCommitments struct {
	Identifier             frost.Identifier `json:"identifier"`
	HidingNonceCommitment  []byte           `json:"hiding_nonce_commitment"`
	BindingNonceCommitment []byte           `json:"binding_nonce_commitment"`
}

// handleRoundOne handles round one requests.
func (n *Node) handleRoundOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RoundOneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Generate nonces and commitments
	nonces, commitments, err := n.participant.RoundOne()
	if err != nil {
		http.Error(w, fmt.Sprintf("Round one failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session
	n.mu.Lock()
	n.sessions[req.SessionID] = &NodeSession{
		sessionID:   req.SessionID,
		nonces:      nonces,
		commitments: commitments,
		createdAt:   time.Now(),
	}
	n.mu.Unlock()

	// Serialize commitments
	serializableCommitments := SerializableCommitments{
		Identifier:             commitments.Identifier,
		HidingNonceCommitment:  commitments.HidingNonceCommitment.Bytes(),
		BindingNonceCommitment: commitments.BindingNonceCommitment.Bytes(),
	}

	resp := RoundOneResponse{
		SessionID:   req.SessionID,
		Identifier:  n.id,
		Commitments: serializableCommitments,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRoundTwo handles round two requests.
func (n *Node) handleRoundTwo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RoundTwoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Retrieve session
	n.mu.RLock()
	session, exists := n.sessions[req.SessionID]
	n.mu.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Deserialize commitment list
	commitmentList := make(frost.CommitmentList, len(req.CommitmentList))
	for i, sc := range req.CommitmentList {
		hiding, err := n.suite.Group().DeserializeElement(sc.HidingNonceCommitment)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to deserialize hiding commitment: %v", err), http.StatusBadRequest)
			return
		}

		binding, err := n.suite.Group().DeserializeElement(sc.BindingNonceCommitment)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to deserialize binding commitment: %v", err), http.StatusBadRequest)
			return
		}

		commitmentList[i] = frost.SigningCommitments{
			Identifier:             sc.Identifier,
			HidingNonceCommitment:  hiding,
			BindingNonceCommitment: binding,
		}
	}

	// Generate signature share
	share, err := n.participant.RoundTwo(session.nonces, req.Message, commitmentList)
	if err != nil {
		http.Error(w, fmt.Sprintf("Round two failed: %v", err), http.StatusInternalServerError)
		return
	}

	resp := RoundTwoResponse{
		Identifier:     share.Identifier,
		SignatureShare: share.SignatureShare.Bytes(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleVerify handles signature verification requests.
func (n *Node) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Deserialize signature components
	sigR, err := n.suite.Group().DeserializeElement(req.SignatureR)
	if err != nil {
		resp := VerifyResponse{Valid: false, Error: fmt.Sprintf("Invalid signature R: %v", err)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	sigZ, err := n.suite.Group().DeserializeScalar(req.SignatureZ)
	if err != nil {
		resp := VerifyResponse{Valid: false, Error: fmt.Sprintf("Invalid signature Z: %v", err)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	groupPubKey, err := n.suite.Group().DeserializeElement(req.GroupPublicKey)
	if err != nil {
		resp := VerifyResponse{Valid: false, Error: fmt.Sprintf("Invalid group public key: %v", err)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create aggregator and verify
	aggregator := signing.NewAggregator(n.suite, 2) // minSigners doesn't matter for verification
	signature := frost.Signature{R: sigR, Z: sigZ}

	err = aggregator.Verify(req.Message, signature, groupPubKey)

	resp := VerifyResponse{
		Valid: err == nil,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleHealth handles health check requests.
func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
