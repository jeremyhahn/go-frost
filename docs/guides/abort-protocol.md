# FROST Abort Protocol

This document describes how to handle signing session aborts and cleanup in go-frost. It covers scenarios requiring abort, cleanup procedures, state management, and integration with identifiable abort for detecting malicious participants.

## Table of Contents

1. [Overview](#overview)
2. [Abort Scenarios](#abort-scenarios)
3. [Coordinator Abort Procedures](#coordinator-abort-procedures)
4. [Participant Abort Procedures](#participant-abort-procedures)
5. [Session Cleanup](#session-cleanup)
6. [Nonce Cleanup](#nonce-cleanup)
7. [Identifiable Abort](#identifiable-abort)
8. [State Management](#state-management)
9. [Code Examples](#code-examples)
10. [Best Practices](#best-practices)

## Overview

The FROST signing protocol requires proper abort handling to maintain security and prevent resource exhaustion. When a signing session fails or is interrupted, proper cleanup is essential to:

- **Prevent nonce reuse**: Critical security requirement - nonces must never be reused
- **Free system resources**: Release memory and session state
- **Identify malicious participants**: Use identifiable abort to detect and exclude bad actors
- **Maintain system availability**: Prevent DoS through proper resource management

### Key Principles

1. **Fail-safe**: Always abort when security cannot be guaranteed
2. **Clean state**: Never leave partial state that could be reused
3. **Accountability**: Track and identify misbehaving participants
4. **Resource management**: Prevent memory leaks and session accumulation

## Abort Scenarios

### 1. Participant Timeout

**When**: A participant fails to respond within the expected time window.

**Cause**:
- Network connectivity issues
- Participant crashed or went offline
- Deliberate DoS attack
- Processing delays

**Detection**:
```go
// Coordinator-side timeout detection
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

commitment, err := participant.RoundOne()
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        // Timeout detected
        return handleTimeout(participantID)
    }
}
```

**Response**:
- Record timeout misbehavior
- Abort current session
- Clean up session state
- Consider excluding participant after threshold violations

### 2. Invalid Commitment

**When**: A participant provides a malformed or invalid commitment.

**Cause**:
- Malicious participant
- Implementation bug
- Corrupted network transmission
- Invalid nonce generation

**Detection**:
```go
// Validate commitment structure
encoder := helpers.NewCommitmentListEncoder(suite.Group())
if err := encoder.ValidateCommitmentList(commitmentList); err != nil {
    // Invalid commitment detected
    return handleInvalidCommitment(err)
}

// Check for identity elements (security violation)
if commitment.HidingNonceCommitment.IsIdentity() {
    return handleSecurityViolation(participantID, "identity element in hiding commitment")
}
```

**Response**:
- Record invalid commitment misbehavior
- Abort current session immediately
- Clean up all session state
- Consider excluding participant

### 3. Invalid Signature Share

**When**: A participant provides a signature share that fails verification.

**Cause**:
- Malicious participant attempting to disrupt signing
- Implementation bug in share computation
- Nonce state inconsistency
- Key share corruption

**Detection** (requires identifiable abort):
```go
// Verify each signature share before aggregation
err := participant.VerifySignatureShare(share, msg, commitmentList)
if err != nil {
    // Malicious participant detected
    return handleMaliciousParticipant(share.Identifier, err)
}
```

**Response**:
- Identify the malicious participant
- Record invalid share misbehavior
- Abort current session
- Exclude participant after threshold violations
- Alert system administrators

### 4. Network Failure

**When**: Network communication fails during the signing process.

**Cause**:
- Connection loss
- Packet loss or corruption
- Firewall/routing issues
- DDoS attack

**Detection**:
```go
// Network error during communication
err := sendCommitment(participantID, commitment)
if err != nil {
    if isNetworkError(err) {
        return handleNetworkFailure(participantID, err)
    }
}
```

**Response**:
- Abort current session
- Retry with exponential backoff (if appropriate)
- Log network errors for monitoring
- Do not penalize participant for transient network issues

### 5. Coordinator Failure

**When**: The coordinator crashes or becomes unavailable.

**Cause**:
- Coordinator process crash
- Hardware failure
- Network partition
- Resource exhaustion

**Detection**: Handled by heartbeat/monitoring systems

**Response**:
- All participants should abort after timeout
- Clean up local session state
- Wait for coordinator recovery or new coordinator election
- Do not reuse nonces in subsequent attempts

### 6. Nonce Reuse Detection

**When**: A participant attempts to reuse a previously used nonce.

**Cause**:
- Malicious participant attempting key recovery attack
- Implementation bug
- Improper session cleanup
- Concurrent session handling error

**Detection**:
```go
// Check for nonce reuse using FrostNonceTracker
err := nonceTracker.CheckSigningCommitments(ctx, sessionID, participantID, commitments)
if err != nil {
    if errors.Is(err, security.ErrCommitmentReused) {
        // CRITICAL: Nonce reuse detected
        return handleNonceReuse(participantID)
    }
}
```

**Response**:
- **IMMEDIATELY** abort all sessions for this participant
- Exclude participant permanently (threshold = 1)
- Alert system administrators
- Audit all recent signatures from this participant
- Consider this a critical security incident

### 7. Insufficient Participants

**When**: Fewer than threshold participants are available or respond.

**Cause**:
- Participants went offline
- Coordinator selected insufficient participants
- Participants were excluded due to misbehavior
- Mass network failure

**Detection**:
```go
if len(signatureShares) < minSigners {
    return handleInsufficientParticipants(len(signatureShares), minSigners)
}
```

**Response**:
- Abort current session gracefully
- Clean up session state
- Select additional participants if available
- Retry with different participant set

### 8. User-Initiated Abort

**When**: An authorized user or administrator cancels a signing operation.

**Cause**:
- Changed mind about signing
- Detected suspicious activity
- Emergency shutdown
- Testing/debugging

**Detection**:
```go
// Check for cancellation signal
select {
case <-ctx.Done():
    return handleUserCancellation()
case result := <-signingComplete:
    return result
}
```

**Response**:
- Gracefully abort session
- Notify all participants
- Clean up all state
- No misbehavior penalties

## Coordinator Abort Procedures

### Basic Abort Flow

```go
func (c *coordinator) abortSession(sessionID string, reason string) error {
    // 1. Log the abort reason
    log.Warnf("Aborting session %s: %s", sessionID, reason)

    // 2. Notify all participants (if possible)
    for participantID := range c.participants {
        _ = c.notifyAbort(participantID, sessionID, reason)
    }

    // 3. Clean up session state
    if err := c.sessionManager.DeleteSession(sessionID); err != nil {
        log.Errorf("Failed to delete session: %v", err)
    }

    // 4. Clean up nonce tracking
    if c.nonceTracker != nil {
        if err := c.nonceTracker.ClearSession(ctx, sessionID); err != nil {
            log.Errorf("Failed to clear nonce tracking: %v", err)
        }
    }

    // 5. Record metrics
    metrics.RecordSessionAbort(sessionID, reason)

    return nil
}
```

### Abort with Participant Identification

```go
func (c *coordinator) abortWithMaliciousParticipant(
    sessionID string,
    maliciousID frost.Identifier,
    misbehaviorType security.MisbehaviorType,
    details string,
) error {
    // 1. Record misbehavior
    if c.reputationTracker != nil {
        c.reputationTracker.RecordMisbehavior(maliciousID, misbehaviorType, details)
    }

    // 2. Check if participant should be excluded
    if c.reputationTracker != nil {
        excluded, _ := c.reputationTracker.IsExcluded(maliciousID)
        if excluded {
            log.Warnf("Participant %d has been excluded due to repeated misbehavior", maliciousID)
        }
    }

    // 3. Abort session
    reason := fmt.Sprintf("Malicious participant %d: %s", maliciousID, details)
    return c.abortSession(sessionID, reason)
}
```

### Timeout Handling

```go
func (c *coordinator) RequestCommitmentsWithTimeout(
    participantIDs []frost.Identifier,
    msg []byte,
    timeout time.Duration,
) (frost.CommitmentList, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    commitments := make(frost.CommitmentList, 0, len(participantIDs))

    for _, id := range participantIDs {
        participant := c.participants[id]

        // Request commitment with timeout
        commitmentChan := make(chan frost.SigningCommitments, 1)
        errorChan := make(chan error, 1)

        go func(p Participant) {
            _, comm, err := p.RoundOne()
            if err != nil {
                errorChan <- err
                return
            }
            commitmentChan <- comm
        }(participant)

        // Wait for result or timeout
        select {
        case commitment := <-commitmentChan:
            commitments = append(commitments, commitment)

        case err := <-errorChan:
            // Record error and continue
            if c.reputationTracker != nil {
                c.reputationTracker.RecordMisbehavior(id,
                    security.MisbehaviorInvalidCommitment, err.Error())
            }
            return nil, fmt.Errorf("participant %d failed: %w", id, err)

        case <-ctx.Done():
            // Timeout occurred
            if c.reputationTracker != nil {
                c.reputationTracker.RecordMisbehavior(id,
                    security.MisbehaviorTimeout, "failed to provide commitment in time")
            }
            return nil, fmt.Errorf("participant %d timed out", id)
        }
    }

    return commitments, nil
}
```

## Participant Abort Procedures

### Detecting Coordinator Abort

```go
func (p *participant) WaitForCommitmentList(
    ctx context.Context,
    sessionID string,
) (frost.CommitmentList, error) {
    // Wait for commitment list from coordinator
    select {
    case commitmentList := <-p.commitmentListChannel:
        return commitmentList, nil

    case abortSignal := <-p.abortChannel:
        // Coordinator aborted the session
        return nil, fmt.Errorf("session aborted: %s", abortSignal.Reason)

    case <-ctx.Done():
        // Timeout waiting for coordinator
        return nil, fmt.Errorf("timeout waiting for commitment list")
    }
}
```

### Participant-Side Cleanup

```go
func (p *participant) cleanupSession(sessionID string) error {
    // 1. Clear cached nonces for this session
    p.mu.Lock()
    delete(p.sessionNonces, sessionID)
    p.mu.Unlock()

    // 2. Clear commitment cache
    delete(p.sessionCommitments, sessionID)

    // 3. Clear any session-specific state
    delete(p.activeSessions, sessionID)

    // 4. Log cleanup
    log.Debugf("Cleaned up session %s", sessionID)

    return nil
}
```

### Graceful Participant Withdrawal

```go
func (p *participant) WithdrawFromSession(sessionID string, reason string) error {
    // 1. Notify coordinator of withdrawal
    if err := p.notifyCoordinator(sessionID, WithdrawalNotice{
        ParticipantID: p.identifier,
        Reason: reason,
    }); err != nil {
        log.Warnf("Failed to notify coordinator: %v", err)
    }

    // 2. Clean up local state
    return p.cleanupSession(sessionID)
}
```

## Session Cleanup

### Session Manager Cleanup

```go
// Cancel a session and clean up all associated resources
func (m *sessionManagerImpl) CancelSession(sessionID string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    session, exists := m.sessions[sessionID]
    if !exists {
        return frost.NewParameterError("sessionID", "session not found", frost.ErrInvalidParameters)
    }

    // Mark session as canceled
    if err := session.Cancel(); err != nil {
        return err
    }

    // Delete the session
    delete(m.sessions, sessionID)

    return nil
}
```

### Automatic Session Expiration

```go
type sessionManagerImpl struct {
    // ... existing fields ...
    sessionTimeout time.Duration
    cleanupTicker  *time.Ticker
}

func (m *sessionManagerImpl) startCleanupRoutine() {
    m.cleanupTicker = time.NewTicker(5 * time.Minute)

    go func() {
        for range m.cleanupTicker.C {
            m.cleanupExpiredSessions()
        }
    }()
}

func (m *sessionManagerImpl) cleanupExpiredSessions() {
    m.mu.Lock()
    defer m.mu.Unlock()

    now := time.Now()

    for sessionID, session := range m.sessions {
        // Check if session is too old
        if now.Sub(session.createdAt) > m.sessionTimeout {
            log.Infof("Cleaning up expired session: %s", sessionID)

            // Cancel and delete
            session.Cancel()
            delete(m.sessions, sessionID)
        }
    }
}

func (m *sessionManagerImpl) Stop() {
    if m.cleanupTicker != nil {
        m.cleanupTicker.Stop()
    }
}
```

### Cleanup on Shutdown

```go
func (s *FrostService) Shutdown(ctx context.Context) error {
    // 1. Stop accepting new sessions
    s.mu.Lock()
    s.shuttingDown = true
    s.mu.Unlock()

    // 2. Cancel all active sessions
    sessionIDs := s.sessionManager.ListSessions()
    for _, sessionID := range sessionIDs {
        if err := s.sessionManager.CancelSession(sessionID); err != nil {
            log.Warnf("Failed to cancel session %s: %v", sessionID, err)
        }
    }

    // 3. Clean up all nonce tracking
    if s.nonceTracker != nil {
        // Clear all sessions (or use a shutdown-specific method)
        for _, sessionID := range sessionIDs {
            s.nonceTracker.ClearSession(ctx, sessionID)
        }
    }

    // 4. Stop session cleanup routine
    if sm, ok := s.sessionManager.(*sessionManagerImpl); ok {
        sm.Stop()
    }

    return nil
}
```

## Nonce Cleanup

### Cleanup After Successful Signing

```go
func (c *coordinator) Sign(participantIDs []frost.Identifier, msg []byte) (frost.Signature, error) {
    sessionID := generateSessionID()
    ctx := context.Background()

    defer func() {
        // Always clean up nonces after signing attempt
        if c.nonceTracker != nil {
            if err := c.nonceTracker.ClearSession(ctx, sessionID); err != nil {
                log.Warnf("Failed to clear nonces for session %s: %v", sessionID, err)
            }
        }
    }()

    // Record commitments for nonce tracking
    if c.nonceTracker != nil {
        for _, id := range participantIDs {
            commitment := commitments[id]
            if err := c.nonceTracker.RecordSigningCommitments(
                ctx, sessionID, id, commitment,
            ); err != nil {
                return frost.Signature{}, err
            }
        }
    }

    // ... continue with signing ...
}
```

### Cleanup After Abort

```go
func (c *coordinator) abortAndCleanup(sessionID string, reason string) error {
    ctx := context.Background()

    // 1. Clean up nonces FIRST (critical for security)
    if c.nonceTracker != nil {
        if err := c.nonceTracker.ClearSession(ctx, sessionID); err != nil {
            // Log but don't fail - nonces might already be cleared
            log.Warnf("Nonce cleanup warning for session %s: %v", sessionID, err)
        }
    }

    // 2. Clean up session state
    if err := c.sessionManager.DeleteSession(sessionID); err != nil {
        log.Errorf("Failed to delete session %s: %v", sessionID, err)
    }

    // 3. Log the abort
    log.Infof("Session %s aborted: %s", sessionID, reason)

    return nil
}
```

### Periodic Nonce Cleanup

```go
func (s *FrostService) startNonceCleanup() {
    ticker := time.NewTicker(1 * time.Hour)

    go func() {
        for range ticker.C {
            if s.nonceTracker != nil {
                // Clean up nonces older than 24 hours
                count, err := s.nonceTracker.ClearExpired(
                    context.Background(),
                    24*time.Hour,
                )
                if err != nil {
                    log.Errorf("Nonce cleanup failed: %v", err)
                } else {
                    log.Debugf("Cleaned up %d expired nonces", count)
                }
            }
        }
    }()
}
```

## Identifiable Abort

Identifiable abort allows the coordinator to detect which participant provided an invalid signature share, enabling accountability and exclusion of malicious actors.

### Enabling Identifiable Abort

```go
// Production coordinator with identifiable abort enabled
func NewProductionCoordinator(
    suite ciphersuite.Ciphersuite,
    participants map[frost.Identifier]signing.Participant,
    groupPublicKey group.Element,
) signing.Coordinator {
    // Create aggregator with identifiable abort support
    aggregator := signing.NewAggregator(suite, minSigners)

    // Create reputation tracker for misbehavior tracking
    reputationTracker := security.NewInMemoryReputationTracker(
        security.DefaultReputationConfig(),
    )

    // Create authenticator for participant authentication
    authenticator := security.NewEd25519Authenticator()

    // Create coordinator with full security features
    return signing.NewCoordinatorWithSecurity(
        suite,
        participants,
        aggregator,
        groupPublicKey,
        authenticator,
        reputationTracker,
    )
}
```

### Using Identifiable Abort in Aggregation

```go
func (c *coordinator) SignWithIdentifiableAbort(
    participantIDs []frost.Identifier,
    msg []byte,
) (frost.Signature, error) {
    // 1. Request commitments (Round 1)
    commitmentList, err := c.RequestCommitments(participantIDs, msg)
    if err != nil {
        return frost.Signature{}, err
    }

    // 2. Request signature shares (Round 2)
    signatureShares, err := c.RequestSignatureShares(commitmentList, msg)
    if err != nil {
        return frost.Signature{}, err
    }

    // 3. Get verification shares for identifiable abort
    verificationShares := make([]frost.VerificationShare, 0, len(participantIDs))
    for _, id := range participantIDs {
        participant := c.participants[id]
        keyPackage := participant.KeyPackage()

        // Extract verification share for this participant
        verificationShares = append(verificationShares, frost.VerificationShare{
            Identifier:      id,
            VerificationKey: keyPackage.VerificationKey,
        })
    }

    // 4. Aggregate with verification (identifiable abort)
    signature, err := c.aggregator.AggregateWithVerification(
        c.groupPublicKey,
        commitmentList,
        msg,
        signatureShares,
        verificationShares, // Enable identifiable abort
    )

    if err != nil {
        // Check if error identifies a malicious participant
        var participantErr *frost.ParticipantError
        if errors.As(err, &participantErr) {
            // Identifiable abort detected malicious participant
            c.handleMaliciousParticipant(
                participantErr.Identifier,
                security.MisbehaviorInvalidShare,
                participantErr.Reason,
            )
        }
        return frost.Signature{}, err
    }

    return signature, nil
}
```

### Manual Share Verification

```go
// Verify a single signature share (useful for debugging)
func VerifyShareManually(
    participant signing.Participant,
    share frost.SignatureShare,
    msg []byte,
    commitmentList frost.CommitmentList,
) error {
    err := participant.VerifySignatureShare(share, msg, commitmentList)
    if err != nil {
        log.Errorf("Share verification failed for participant %d: %v",
            share.Identifier, err)
        return err
    }
    return nil
}
```

### Handling Identifiable Abort Errors

```go
func (c *coordinator) handleMaliciousParticipant(
    participantID frost.Identifier,
    misbehaviorType security.MisbehaviorType,
    details string,
) {
    // 1. Record the misbehavior
    if c.reputationTracker != nil {
        err := c.reputationTracker.RecordMisbehavior(
            participantID,
            misbehaviorType,
            details,
        )
        if err != nil {
            log.Errorf("Failed to record misbehavior: %v", err)
        }
    }

    // 2. Check if participant should be excluded
    if c.reputationTracker != nil {
        excluded, err := c.reputationTracker.IsExcluded(participantID)
        if err != nil {
            log.Errorf("Failed to check exclusion status: %v", err)
        }

        if excluded {
            log.Warnf("Participant %d has been excluded from future signing operations", participantID)

            // 3. Remove from available participants
            delete(c.participants, participantID)

            // 4. Alert administrators
            c.alertSecurityTeam(participantID, misbehaviorType, details)
        }
    }
}

func (c *coordinator) alertSecurityTeam(
    participantID frost.Identifier,
    misbehaviorType security.MisbehaviorType,
    details string,
) {
    // Send alert to monitoring system
    alert := SecurityAlert{
        Timestamp:     time.Now(),
        ParticipantID: participantID,
        Type:          misbehaviorType,
        Details:       details,
        Severity:      "HIGH",
    }

    // Log structured alert
    log.WithFields(logrus.Fields{
        "participant_id": participantID,
        "type":          misbehaviorType,
        "details":       details,
    }).Error("Malicious participant detected")

    // Send to external monitoring (e.g., PagerDuty, Slack)
    // alertService.Send(alert)
}
```

## State Management

### Session State Machine

```
                    ┌─────────────┐
                    │   CREATED   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  COLLECTING │ ◄────────┐
                    │ COMMITMENTS │          │
                    └──────┬──────┘          │
                           │                 │
                    ┌──────▼──────┐          │
                    │  COLLECTING │   Retry  │
                    │   SHARES    │──────────┘
                    └──────┬──────┘
                           │
                  ┌────────┴────────┐
                  │                 │
           ┌──────▼──────┐   ┌─────▼──────┐
           │  COMPLETED  │   │   ABORTED  │
           └─────────────┘   └────────────┘
```

### State Transitions

```go
type SessionState int

const (
    StateCreated SessionState = iota
    StateCollectingCommitments
    StateCollectingShares
    StateCompleted
    StateAborted
    StateCanceled
)

type signingSession struct {
    // ... existing fields ...
    state      SessionState
    stateMu    sync.RWMutex
    createdAt  time.Time
    updatedAt  time.Time
}

func (s *signingSession) transitionTo(newState SessionState) error {
    s.stateMu.Lock()
    defer s.stateMu.Unlock()

    // Validate state transition
    if !s.isValidTransition(s.state, newState) {
        return fmt.Errorf("invalid state transition: %v -> %v", s.state, newState)
    }

    oldState := s.state
    s.state = newState
    s.updatedAt = time.Now()

    log.Debugf("Session %s: %v -> %v", s.id, oldState, newState)
    return nil
}

func (s *signingSession) isValidTransition(from, to SessionState) bool {
    validTransitions := map[SessionState][]SessionState{
        StateCreated:               {StateCollectingCommitments, StateAborted, StateCanceled},
        StateCollectingCommitments: {StateCollectingShares, StateAborted, StateCanceled},
        StateCollectingShares:      {StateCompleted, StateAborted, StateCanceled},
        StateCompleted:             {}, // Terminal state
        StateAborted:               {}, // Terminal state
        StateCanceled:              {}, // Terminal state
    }

    allowed := validTransitions[from]
    for _, allowedState := range allowed {
        if allowedState == to {
            return true
        }
    }
    return false
}
```

### Safe State Access

```go
func (s *signingSession) AddCommitment(commitment frost.SigningCommitments) error {
    s.stateMu.RLock()
    currentState := s.state
    s.stateMu.RUnlock()

    // Check state before adding commitment
    if currentState != StateCollectingCommitments {
        return fmt.Errorf("cannot add commitment in state %v", currentState)
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    // Double-check after acquiring lock
    if s.state != StateCollectingCommitments {
        return fmt.Errorf("state changed during operation")
    }

    // Add commitment...
    s.commitments[commitment.Identifier] = commitment

    return nil
}
```

## Code Examples

### Complete Abort Example with All Features

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
    "github.com/jeremyhahn/go-frost/pkg/frost/service"
    "github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

func main() {
    // 1. Setup
    suite := ristretto255_sha512.New()
    frostService := service.NewFrostService(suite)

    // 2. Generate keys
    config := frost.Configuration{
        MinSigners: 2,
        MaxSigners: 3,
        Group:      suite.Group(),
    }

    participantIDs := []frost.Identifier{1, 2, 3}
    keyPackages, groupPubKey, err := frostService.GenerateKeys(config, participantIDs)
    if err != nil {
        panic(err)
    }

    // 3. Create participants
    participants := make(map[frost.Identifier]signing.Participant)
    for _, pkg := range keyPackages {
        participants[pkg.Identifier] = signing.NewParticipant(pkg, suite)
    }

    // 4. Create security components
    nonceTracker := security.NewDefaultFrostNonceTracker()
    reputationTracker := security.NewInMemoryReputationTracker(
        security.DefaultReputationConfig(),
    )

    // 5. Create coordinator with security features
    aggregator := signing.NewAggregator(suite, config.MinSigners)
    coordinator := signing.NewCoordinatorWithSecurity(
        suite,
        participants,
        aggregator,
        groupPubKey,
        nil, // No authenticator in this example
        reputationTracker,
    )

    // 6. Attempt signing with comprehensive error handling
    message := []byte("Important message to sign")
    sessionID := "session-123"
    ctx := context.Background()

    signature, err := signWithAbortHandling(
        ctx,
        coordinator,
        nonceTracker,
        reputationTracker,
        sessionID,
        participantIDs[:2], // Use only 2 participants (threshold)
        message,
        groupPubKey,
    )

    if err != nil {
        fmt.Printf("Signing failed: %v\n", err)
        return
    }

    // 7. Verify signature
    err = aggregator.Verify(message, signature, groupPubKey)
    if err != nil {
        fmt.Printf("Signature verification failed: %v\n", err)
        return
    }

    fmt.Println("Signature created and verified successfully!")
}

func signWithAbortHandling(
    ctx context.Context,
    coordinator signing.Coordinator,
    nonceTracker *security.FrostNonceTracker,
    reputationTracker security.ReputationTracker,
    sessionID string,
    participantIDs []frost.Identifier,
    message []byte,
    groupPubKey group.Element,
) (frost.Signature, error) {

    // Ensure cleanup happens no matter what
    defer func() {
        // Clean up nonces
        if err := nonceTracker.ClearSession(ctx, sessionID); err != nil {
            fmt.Printf("Warning: Failed to clear nonces: %v\n", err)
        }
    }()

    // 1. Check for excluded participants
    for _, id := range participantIDs {
        excluded, err := reputationTracker.IsExcluded(id)
        if err != nil {
            return frost.Signature{}, fmt.Errorf("failed to check exclusion for %d: %w", id, err)
        }
        if excluded {
            return frost.Signature{}, fmt.Errorf("participant %d is excluded", id)
        }
    }

    // 2. Request commitments with timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    commitmentList, err := coordinator.RequestCommitments(participantIDs, message)
    if err != nil {
        return frost.Signature{}, fmt.Errorf("commitment collection failed: %w", err)
    }

    // 3. Record commitments for nonce tracking
    for _, commitment := range commitmentList {
        err := nonceTracker.RecordSigningCommitments(
            ctx,
            sessionID,
            commitment.Identifier,
            commitment,
        )
        if err != nil {
            // Nonce reuse detected!
            reputationTracker.RecordMisbehavior(
                commitment.Identifier,
                security.MisbehaviorNonceReuse,
                err.Error(),
            )
            return frost.Signature{}, fmt.Errorf("nonce reuse detected for participant %d: %w",
                commitment.Identifier, err)
        }
    }

    // 4. Request signature shares
    signatureShares, err := coordinator.RequestSignatureShares(commitmentList, message)
    if err != nil {
        return frost.Signature{}, fmt.Errorf("signature share collection failed: %w", err)
    }

    // 5. Aggregate with identifiable abort
    signature, err := coordinator.Sign(participantIDs, message)
    if err != nil {
        // Check if a specific participant was identified
        var participantErr *frost.ParticipantError
        if errors.As(err, &participantErr) {
            fmt.Printf("Malicious participant detected: %d - %s\n",
                participantErr.Identifier, participantErr.Reason)
        }
        return frost.Signature{}, fmt.Errorf("aggregation failed: %w", err)
    }

    return signature, nil
}
```

### Session Cleanup Example

```go
// Example: Proper session lifecycle management
func RunSigningSessionWithCleanup(
    service *FrostService,
    participantIDs []frost.Identifier,
    message []byte,
) (frost.Signature, error) {

    // 1. Create session
    session, err := service.SessionManager().CreateSession(participantIDs, message)
    if err != nil {
        return frost.Signature{}, err
    }

    sessionID := session.ID()

    // 2. Ensure cleanup on exit
    defer func() {
        // Always delete the session, even on panic
        if err := service.SessionManager().DeleteSession(sessionID); err != nil {
            log.Warnf("Failed to delete session %s: %v", sessionID, err)
        }
    }()

    // 3. Collect commitments
    for _, id := range participantIDs {
        commitment, err := service.RequestCommitment(id, message)
        if err != nil {
            // Abort: cleanup handled by defer
            return frost.Signature{}, err
        }

        if err := session.AddCommitment(commitment); err != nil {
            // Abort: cleanup handled by defer
            return frost.Signature{}, err
        }
    }

    // 4. Get commitment list
    commitmentList, err := session.GetCommitmentList()
    if err != nil {
        return frost.Signature{}, err
    }

    // 5. Collect signature shares
    for _, id := range participantIDs {
        share, err := service.RequestSignatureShare(id, message, commitmentList)
        if err != nil {
            return frost.Signature{}, err
        }

        if err := session.AddSignatureShare(share); err != nil {
            return frost.Signature{}, err
        }
    }

    // 6. Get final signature
    signature, err := session.GetSignature()
    if err != nil {
        return frost.Signature{}, err
    }

    return signature, nil
}
```

## Best Practices

### 1. Always Clean Up Nonces

```go
// ❌ BAD: No cleanup on error
func badSign() error {
    commitments := collectCommitments()
    nonceTracker.Record(sessionID, commitments)

    shares := collectShares() // If this fails, nonces are leaked
    return aggregate(shares)
}

// ✅ GOOD: Cleanup guaranteed
func goodSign() error {
    defer nonceTracker.ClearSession(ctx, sessionID)

    commitments := collectCommitments()
    nonceTracker.Record(sessionID, commitments)

    shares := collectShares()
    return aggregate(shares)
}
```

### 2. Use Identifiable Abort in Production

```go
// ❌ BAD: No participant identification
signature, err := aggregator.Aggregate(
    groupPubKey, commitmentList, msg, shares,
)

// ✅ GOOD: Identify malicious participants
signature, err := aggregator.AggregateWithVerification(
    groupPubKey, commitmentList, msg, shares, verificationShares,
)
```

### 3. Implement Timeouts

```go
// ❌ BAD: Unbounded wait
commitment, err := participant.RoundOne()

// ✅ GOOD: Bounded wait with timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

done := make(chan result)
go func() {
    commitment, err := participant.RoundOne()
    done <- result{commitment, err}
}()

select {
case res := <-done:
    // Process result
case <-ctx.Done():
    // Handle timeout
    return handleTimeout(participantID)
}
```

### 4. Separate Transient from Persistent Failures

```go
func handleParticipantError(id frost.Identifier, err error) {
    // Don't penalize for network issues
    if isNetworkError(err) {
        log.Warnf("Participant %d: transient network error: %v", id, err)
        return
    }

    // Do penalize for protocol violations
    if isProtocolViolation(err) {
        reputationTracker.RecordMisbehavior(
            id,
            security.MisbehaviorInvalidShare,
            err.Error(),
        )
    }
}
```

### 5. Log All Aborts

```go
func abortSession(sessionID string, reason string, cause error) error {
    // Structured logging for debugging
    log.WithFields(logrus.Fields{
        "session_id": sessionID,
        "reason":     reason,
        "error":      cause,
        "stack":      debug.Stack(),
    }).Warn("Session aborted")

    // Metrics for monitoring
    metrics.RecordAbort(sessionID, reason)

    // Cleanup
    return cleanup(sessionID)
}
```

### 6. Validate State Transitions

```go
// ❌ BAD: No state validation
func addCommitment(c Commitment) {
    session.commitments[c.ID] = c
}

// ✅ GOOD: Validate state before operations
func addCommitment(c Commitment) error {
    if session.state != StateCollectingCommitments {
        return fmt.Errorf("invalid state: %v", session.state)
    }

    session.commitments[c.ID] = c
    return nil
}
```

### 7. Use Defer for Cleanup

```go
func signWithCleanup() error {
    session := createSession()

    // Cleanup runs even on panic
    defer func() {
        session.Cancel()
        nonceTracker.ClearSession(ctx, session.ID())
    }()

    // Signing operations...
    return nil
}
```

### 8. Monitor Abort Metrics

```go
type AbortMetrics struct {
    TotalAborts          int64
    TimeoutAborts        int64
    MaliciousAborts      int64
    NetworkAborts        int64
    InsufficientAborts   int64
}

func recordAbort(reason AbortReason) {
    atomic.AddInt64(&metrics.TotalAborts, 1)

    switch reason {
    case AbortTimeout:
        atomic.AddInt64(&metrics.TimeoutAborts, 1)
    case AbortMalicious:
        atomic.AddInt64(&metrics.MaliciousAborts, 1)
    // ...
    }
}
```

### 9. Implement Retry with Backoff

```go
func signWithRetry(maxRetries int) (frost.Signature, error) {
    backoff := time.Second

    for attempt := 0; attempt < maxRetries; attempt++ {
        signature, err := attemptSign()
        if err == nil {
            return signature, nil
        }

        // Don't retry on malicious participant
        if isMaliciousError(err) {
            return frost.Signature{}, err
        }

        // Exponential backoff for transient errors
        if isTransientError(err) {
            time.Sleep(backoff)
            backoff *= 2
            continue
        }

        // Don't retry on permanent errors
        return frost.Signature{}, err
    }

    return frost.Signature{}, fmt.Errorf("max retries exceeded")
}
```

### 10. Document Abort Reasons

```go
type AbortReason int

const (
    // AbortTimeout indicates a participant failed to respond in time
    AbortTimeout AbortReason = iota

    // AbortMalicious indicates identifiable abort detected a malicious participant
    AbortMalicious

    // AbortNetwork indicates a network failure caused the abort
    AbortNetwork

    // AbortInsufficient indicates too few participants were available
    AbortInsufficient

    // AbortNonceReuse indicates critical nonce reuse was detected
    AbortNonceReuse

    // AbortUserCanceled indicates the user canceled the operation
    AbortUserCanceled
)

func (r AbortReason) String() string {
    names := [...]string{
        "timeout",
        "malicious_participant",
        "network_failure",
        "insufficient_participants",
        "nonce_reuse",
        "user_canceled",
    }
    if r < 0 || int(r) >= len(names) {
        return "unknown"
    }
    return names[r]
}
```

## Summary

The patterns above cover the main concerns for abort handling in FROST: nonce cleanup, identifiable abort, timeouts, misbehavior tracking, and graceful error recovery. Apply them as appropriate to your deployment.

For more information, see:
- [Misbehavior Tracking](MISBEHAVIOR_TRACKING.md)
- [Implementation Guide](IMPLEMENTATION_GUIDE.md)
- [RFC 9591 Section 7](../rfc9591.txt) - Security Considerations
