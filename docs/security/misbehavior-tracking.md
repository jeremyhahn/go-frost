# Misbehavior Tracking

> **Status: NORMATIVE** · Scope: go-frost `pkg/frost/security` · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

This document describes the misbehavior tracking and reputation system in go-frost, which implements DoS prevention through participant reputation tracking (RFC 9591 Section 7).

## Overview

The misbehavior tracking system monitors participant behavior during FROST signing operations and automatically excludes participants that exceed configurable thresholds for various types of misbehavior. This prevents repeated DoS attacks and improves overall system resilience.

## Features

- **Automatic Exclusion**: Participants are excluded once a violation counter reaches its threshold (`>=`)
- **Multiple Violation Types**: The tracker counts authentication failures, invalid shares, timeouts, nonce reuse, and invalid commitments
- **Configurable Thresholds**: Each violation type has an independent threshold; `0` disables automatic exclusion for that type
- **Manual Control**: Manual exclusion and reinstatement of participants
- **History Tracking**: Keeps a per-participant misbehavior history for auditing
- **Thread-Safe**: `InMemoryReputationTracker` is guarded by a mutex
- **Explicit Cleanup**: `CleanupOldRecords` removes old history records when the application calls it; nothing runs it automatically

What the coordinator records on its own (`pkg/frost/signing/coordinator.go`):
authentication failures (commitment and share), invalid shares, and
`RoundOne` failures (as invalid commitments). It checks `IsExcluded` in
`RequestCommitments`. **Timeouts and nonce reuse are never recorded by the
library**; the application must call `RecordMisbehavior` for them.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Coordinator                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Check ReputationTracker for excluded participants │  │
│  │  2. Request commitments/shares from participants      │  │
│  │  3. Record misbehavior on failures                    │  │
│  │  4. Automatic exclusion on threshold violation        │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │   ReputationTracker         │
         ├─────────────────────────────┤
         │ RecordMisbehavior()         │
         │ GetReputation()             │
         │ IsExcluded()                │
         │ ExcludeParticipant()        │
         │ ReinstateParticipant()      │
         │ GetMisbehaviorHistory()     │
         │ CleanupOldRecords()         │
         └─────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │ InMemoryReputationTracker   │
         ├─────────────────────────────┤
         │ - Violation counters        │
         │ - Exclusion status          │
         │ - Misbehavior history       │
         │ - Automatic threshold logic │
         └─────────────────────────────┘
```

## Violation Types

### 1. Authentication Failures

**Type**: `MisbehaviorAuthenticationFailure`

**Triggered when** (recorded by the coordinator when it has a tracker and an authenticator):
- Participant fails commitment authentication
- Participant fails signature share authentication
- Invalid or missing authentication proof

**Default Threshold**: 3 failures

**Severity**: HIGH - Indicates potential impersonation attempts

### 2. Invalid Signature Shares

**Type**: `MisbehaviorInvalidShare`

**Triggered when** (recorded by the coordinator during aggregation):
- Participant produces a signature share that fails verification

**Default Threshold**: 2 invalid shares

**Severity**: CRITICAL - Indicates malicious or faulty participant

### 3. Timeout Violations

**Type**: `MisbehaviorTimeout`

**Triggered when** (application-recorded; the library does not detect timeouts):
- Participant fails to respond within session timeout
- Participant causes protocol delays

**Default Threshold**: 5 timeouts

**Severity**: MEDIUM - May indicate network issues or DoS attempt

### 4. Nonce Reuse Attempts

**Type**: `MisbehaviorNonceReuse`

**Triggered when** (application-recorded, e.g. after `FrostNonceTracker` returns `ErrCommitmentReused`):
- Participant attempts to reuse a nonce commitment
- Critical security violation

**Default Threshold**: 1 attempt

**Severity**: CRITICAL - Immediate exclusion required

### 5. Invalid Commitments

**Type**: `MisbehaviorInvalidCommitment`

**Triggered when** (the coordinator records it when a participant's `RoundOne` returns an error):
- Participant produces a malformed commitment
- Commitment fails validation checks

**Default Threshold**: 3 invalid commitments

**Severity**: HIGH - Indicates protocol violation or attack

## Configuration

### Basic Configuration

```go
import "github.com/jeremyhahn/go-frost/pkg/frost/security"

// Use default configuration
config := security.DefaultReputationConfig()

// Create reputation tracker
tracker := security.NewInMemoryReputationTracker(config)
```

### Custom Configuration

```go
config := security.ReputationConfig{
    // Authentication failures threshold
    MaxAuthenticationFailures: 3,

    // Invalid shares threshold (keep low - critical violation)
    MaxInvalidShares: 2,

    // Timeout threshold (can be higher for network issues)
    MaxTimeouts: 5,

    // Nonce reuse threshold (should be 1)
    MaxNonceReuses: 1,

    // Invalid commitments threshold
    MaxInvalidCommitments: 3,

    // How long to keep records
    RecordRetention: 30 * 24 * time.Hour, // 30 days
}

tracker := security.NewInMemoryReputationTracker(config)
```

### Integration with Coordinator

```go
import (
    "github.com/jeremyhahn/go-frost/pkg/frost/signing"
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Create reputation tracker
reputationConfig := security.DefaultReputationConfig()
reputationTracker := security.NewInMemoryReputationTracker(reputationConfig)

// Create authenticator (optional but recommended); the map holds participant public keys
authenticator := security.NewEd25519Authenticator(participantPubKeys)

// Create coordinator with both security features
coordinator := signing.NewCoordinatorWithSecurity(
    suite,
    participants,
    aggregator,
    groupPublicKey,
    authenticator,
    reputationTracker,
)
```

## Usage Examples

### Checking Participant Reputation

```go
// Get detailed reputation for a participant
// Returns ErrParticipantNotFound for a participant with no recorded activity
rep, err := tracker.GetReputation(participantID)
if err != nil {
    log.Printf("Failed to get reputation: %v", err)
    return
}

fmt.Printf("Participant %d reputation:\n", participantID)
fmt.Printf("  Authentication Failures: %d\n", rep.AuthenticationFailures)
fmt.Printf("  Invalid Shares: %d\n", rep.InvalidShares)
fmt.Printf("  Timeouts: %d\n", rep.Timeouts)
fmt.Printf("  Total Violations: %d\n", rep.TotalViolations())
fmt.Printf("  Excluded: %v\n", rep.Excluded)
if rep.Excluded {
    fmt.Printf("  Exclusion Reason: %s\n", rep.ExclusionReason)
}
```

### Checking Exclusion Status

```go
excluded, err := tracker.IsExcluded(participantID)
if err != nil {
    log.Printf("Failed to check exclusion: %v", err)
    return
}

if excluded {
    log.Printf("Participant %d is excluded from signing", participantID)
    return
}

// Proceed with signing operation
```

### Manual Exclusion

```go
// Manually exclude a participant (administrative action)
err := tracker.ExcludeParticipant(participantID, "manual exclusion: operator decision")
if err != nil {
    log.Printf("Failed to exclude participant: %v", err)
    return
}

log.Printf("Participant %d manually excluded", participantID)
```

### Reinstatement

```go
// Reinstate a previously excluded participant (ErrParticipantNotFound if never tracked).
// This clears the exclusion only; violation counters are NOT reset, so with
// thresholds of >=, the next violation of the same type excludes the participant again.
err := tracker.ReinstateParticipant(participantID)
if err != nil {
    log.Printf("Failed to reinstate participant: %v", err)
    return
}

log.Printf("Participant %d reinstated", participantID)
```

### Viewing Misbehavior History

```go
// Get last 10 misbehavior records (limit 0 = all; ErrParticipantNotFound if none recorded)
history, err := tracker.GetMisbehaviorHistory(participantID, 10)
if err != nil {
    log.Printf("Failed to get history: %v", err)
    return
}

fmt.Printf("Recent misbehavior for participant %d:\n", participantID)
for _, record := range history {
    fmt.Printf("  %s: %s - %s\n",
        record.Timestamp.Format(time.RFC3339),
        record.Type,
        record.Details)
}
```

### Periodic Cleanup

`CleanupOldRecords` drops history records older than `maxAge` (it is a no-op for
`maxAge <= 0`). It does not touch the violation counters or exclusion status, and
the tracker never calls it by itself, nor does it read `RecordRetention`; pass that
value in yourself.

```go
// Run cleanup every 24 hours
ticker := time.NewTicker(24 * time.Hour)
defer ticker.Stop()

for range ticker.C {
    // Remove records older than 30 days
    removed, err := tracker.CleanupOldRecords(30 * 24 * time.Hour)
    if err != nil {
        log.Printf("Cleanup failed: %v", err)
        continue
    }
    log.Printf("Cleaned up %d old misbehavior records", removed)
}
```

## Automatic Behavior

### Exclusion Workflow

1. **Misbehavior Detection**: Coordinator detects violation during signing
2. **Record Violation**: `RecordMisbehavior()` is called with participant ID and type
3. **Increment Counter**: Appropriate violation counter is incremented
4. **Check Threshold**: If the counter has reached the configured threshold (and the threshold is > 0)
5. **Automatic Exclusion**: Participant is marked as excluded
6. **Future Rejections**: `RequestCommitments` fails with `ErrParticipantExcluded` (wrapped in a participant error) for an excluded participant

### Example: Invalid Share Flow

```
Participant sends invalid signature share
         │
         ▼
Coordinator detects verification failure
         │
         ▼
tracker.RecordMisbehavior(id, MisbehaviorInvalidShare, "verification failed")
         │
         ▼
Check: rep.InvalidShares >= config.MaxInvalidShares ?
         │
         ├─ NO: Continue (increment counter only)
         │
         └─ YES: Automatic exclusion
                  │
                  ▼
              rep.Excluded = true
              rep.ExclusionReason = "exceeded invalid share threshold"
              rep.ExcludedAt = time.Now()
```

## Integration Points

Simplified from `pkg/frost/signing/coordinator.go`; the real code wraps errors with
`frost.NewParticipantError` and ignores `RecordMisbehavior`'s return value (best effort).

### 1. Coordinator Request Commitments

```go
// Check for excluded participants before requesting commitments
if c.reputationTracker != nil {
    for _, id := range participantIDs {
        excluded, err := c.reputationTracker.IsExcluded(id)
        if excluded {
            return nil, ErrParticipantExcluded
        }
    }
}
```

### 2. Coordinator Request Signature Shares

```go
// Track invalid shares
if err != nil {
    if c.reputationTracker != nil {
        c.reputationTracker.RecordMisbehavior(
            participantID,
            MisbehaviorInvalidShare,
            err.Error())
    }
    return err
}
```

### 3. Authentication Layer

```go
// Track authentication failures
err := c.authenticator.AuthenticateCommitment(participantID, commitment, proof)
if err != nil {
    if c.reputationTracker != nil {
        c.reputationTracker.RecordMisbehavior(
            participantID,
            MisbehaviorAuthenticationFailure,
            "commitment authentication failed")
    }
    return err
}
```

## Production Deployment

### Recommended Configuration

```go
// Production configuration
config := security.ReputationConfig{
    MaxAuthenticationFailures: 3,    // Allow for occasional network issues
    MaxInvalidShares:          2,    // Low tolerance for invalid shares
    MaxTimeouts:               5,    // Higher tolerance for network delays
    MaxNonceReuses:            1,    // Zero tolerance for nonce reuse
    MaxInvalidCommitments:     3,    // Allow for some errors
    RecordRetention:           30 * 24 * time.Hour,
}
```

### Enable in SecurityConfig

```go
securityConfig := security.DefaultProductionConfig()
// ReputationTracker is already set (an in-memory tracker built from the defaults).
// Editing securityConfig.ReputationConfig afterwards does NOT change that tracker's
// thresholds; build a new tracker from the config you want and assign it:
repConfig := security.DefaultReputationConfig()
repConfig.MaxInvalidShares = 1 // Stricter
securityConfig.ReputationConfig = repConfig
securityConfig.ReputationTracker = security.NewInMemoryReputationTracker(repConfig)
```

### Monitoring

```go
// Periodically check for excluded participants
func monitorReputations(tracker security.ReputationTracker, participantIDs []frost.Identifier) {
    for _, id := range participantIDs {
        rep, err := tracker.GetReputation(id)
        if err != nil {
            continue
        }

        // Alert on high violation counts (before exclusion)
        if rep.TotalViolations() > 5 && !rep.Excluded {
            log.Printf("WARNING: Participant %d has %d violations",
                id, rep.TotalViolations())
        }

        // Alert on exclusions
        if rep.Excluded {
            log.Printf("ALERT: Participant %d excluded: %s",
                id, rep.ExclusionReason)
        }
    }
}
```

### Persistent Storage

For production deployments, implement a persistent `ReputationTracker`:

```go
type PersistentReputationTracker struct {
    db     *sql.DB  // Or your preferred database
    config ReputationConfig
}

// Implement ReputationTracker interface with database backing
func (t *PersistentReputationTracker) RecordMisbehavior(...) error {
    // Store in database
    _, err := t.db.Exec(
        "INSERT INTO misbehavior (participant_id, type, timestamp, details) VALUES (?, ?, ?, ?)",
        participantID, misbehaviorType, time.Now(), details)
    return err
}

// ... implement other methods ...
```

## Security Considerations

### 1. DoS Prevention

The reputation system prevents repeated DoS attacks by:
- Tracking misbehavior across sessions
- Automatically excluding persistent bad actors
- Reducing resource waste on known-bad participants

### 2. Threshold Tuning

- **Too Low**: Risk of excluding legitimate participants due to network issues
- **Too High**: Allows attackers more attempts before exclusion
- **Recommendation**: Start with defaults, adjust based on observed behavior

### 3. Reinstatement Policy

Establish clear policies for participant reinstatement:
- Manual review of exclusion reasons
- Verification of underlying issues resolved
- Logging of reinstatement decisions
- Possible probationary period with lower thresholds

### 4. Attack Scenarios

**Scenario 1: Malicious Participant**
- Sends invalid shares repeatedly
- After 2 invalid shares: Automatically excluded
- Future signing sessions reject this participant

**Scenario 2: Network Issues**
- Participant experiences intermittent connectivity
- Multiple timeouts (up to threshold)
- System allows for transient issues
- Manual investigation if threshold exceeded

**Scenario 3: Impersonation Attempt**
- Attacker tries to impersonate legitimate participant
- Authentication failures recorded
- After 3 failures: Automatically excluded
- Real participant may need investigation

## Testing

See `pkg/frost/security/reputation_test.go` for tests covering:

- Basic misbehavior recording
- Automatic exclusion for all violation types
- Manual exclusion and reinstatement
- Misbehavior history tracking
- Record cleanup
- Concurrent access
- Edge cases and boundary conditions

## Performance

- **Memory**: O(P × H) where P = participants, H = history length
- **Lookup**: O(1) for exclusion checks
- **Recording**: O(1) for misbehavior recording
- **Cleanup**: O(P × H) periodic cleanup operation

For large-scale deployments, implement periodic cleanup:

```go
go func() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()

    for range ticker.C {
        tracker.CleanupOldRecords(30 * 24 * time.Hour)
    }
}()
```

## API Reference

### ReputationTracker Interface

```go
type ReputationTracker interface {
    RecordMisbehavior(participantID frost.Identifier, misbehaviorType MisbehaviorType, details string) error
    GetReputation(participantID frost.Identifier) (ParticipantReputation, error)
    IsExcluded(participantID frost.Identifier) (bool, error)
    ExcludeParticipant(participantID frost.Identifier, reason string) error
    ReinstateParticipant(participantID frost.Identifier) error
    GetMisbehaviorHistory(participantID frost.Identifier, limit int) ([]MisbehaviorRecord, error)
    CleanupOldRecords(maxAge time.Duration) (int, error)
}
```

### ParticipantReputation Structure

```go
type ParticipantReputation struct {
    ParticipantID          frost.Identifier
    AuthenticationFailures int
    InvalidShares          int
    Timeouts               int
    NonceReuses            int
    InvalidCommitments     int
    FirstSeen              time.Time
    LastSeen               time.Time
    Excluded               bool
    ExcludedAt             time.Time
    ExclusionReason        string
}
```

## References

- RFC 9591 Section 7: Security Considerations
- [channel-security.md](channel-security.md): Participant authentication
- [rfc-compliance](../rfc-compliance/README.md): Overall RFC compliance status
