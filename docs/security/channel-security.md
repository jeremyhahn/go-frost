# Channel Security Guide

## Overview

RFC 9591 Section 7.2 requires that communication between participants and the coordinator occurs over **authenticated and confidential channels**. This guide provides concrete recommendations and implementation patterns for securing FROST protocol communication in production deployments.

### Threat Model

Without secure channels, FROST implementations are vulnerable to:

1. **Man-in-the-Middle (MITM) Attacks**
   - Attacker intercepts and modifies commitments or signature shares
   - Result: Invalid signatures or key recovery

2. **Replay Attacks**
   - Attacker replays old commitments from previous signing sessions
   - Result: Nonce reuse → private key recovery

3. **Impersonation Attacks**
   - Attacker impersonates a legitimate participant
   - Result: Malicious shares injected into signing protocol

4. **Eavesdropping**
   - Passive attacker observes protocol messages
   - Result: Potential information leakage about signing operations

---

## Requirements Summary

| Security Property | Implementation | RFC Requirement |
|-------------------|----------------|-----------------|
| **Confidentiality** | TLS 1.3+ | REQUIRED |
| **Integrity** | TLS + Message Authentication | REQUIRED |
| **Authentication** | Participant authenticators | REQUIRED |
| **Replay Protection** | Sequence numbers + Timestamps | RECOMMENDED |
| **Nonce Reuse Prevention** | Commitment tracking | REQUIRED |

---

## 1. Transport Security (TLS 1.3+)

### Minimum Requirements

All FROST protocol communication MUST use **TLS 1.3 or later**:

```yaml
TLS Configuration:
  Minimum Version: TLS 1.3
  Cipher Suites:
    - TLS_AES_256_GCM_SHA384          # Preferred
    - TLS_CHACHA20_POLY1305_SHA256    # Alternative for ARM
    - TLS_AES_128_GCM_SHA256          # Minimum acceptable

  Certificate Validation:
    - Verify full certificate chain
    - Check certificate expiration
    - Validate hostname matches
    - Enable OCSP stapling (recommended)
    - Pin certificates for high-security environments

  Session Resumption:
    - Disable TLS session tickets (prevents replay)
    - Use session IDs with server-side storage only
```

### Why TLS 1.3?

TLS 1.3 provides critical security improvements:

- **Forward Secrecy**: All cipher suites provide PFS (older TLS allows non-PFS)
- **Encrypted Handshake**: Protects participant identities
- **No Renegotiation**: Eliminates renegotiation attacks
- **Modern Crypto**: Removes MD5, SHA-1, RC4, CBC mode ciphers
- **Faster Handshake**: 1-RTT (vs 2-RTT in TLS 1.2)

### Go Implementation Example

```go
package transport

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
)

// NewProductionTLSConfig creates a TLS 1.3+ configuration for FROST communication
func NewProductionTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
    // Load server certificate and key
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load certificate: %w", err)
    }

    // Load CA certificate for client verification
    caCert, err := ioutil.ReadFile(caFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load CA certificate: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse CA certificate")
    }

    return &tls.Config{
        // Minimum TLS 1.3
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,

        // Server certificate
        Certificates: []tls.Certificate{cert},

        // Client authentication (mutual TLS)
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  caCertPool,

        // Prefer server cipher suite order
        PreferServerCipherSuites: true,

        // Explicitly set cipher suites (TLS 1.3 only)
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
        },

        // Disable session tickets (prevents replay attacks)
        SessionTicketsDisabled: true,

        // Enable client session cache for performance
        // (coordinator only, one session per participant)
        ClientSessionCache: nil, // Disable for maximum security

    }, nil
}

// Client-side configuration
func NewClientTLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load client certificate: %w", err)
    }

    caCert, err := ioutil.ReadFile(caFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load CA certificate: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse CA certificate")
    }

    return &tls.Config{
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        ServerName:   serverName,

        // Disable session resumption for maximum security
        SessionTicketsDisabled: true,
    }, nil
}
```

---

## 2. Participant Authentication

TLS provides transport-level authentication, but FROST requires **message-level authentication** to prevent impersonation within the protocol itself.

### Message Authentication Implementation

go-frost provides the `ParticipantAuthenticator` interface for message-level authentication:

```go
package security

import (
    "crypto/ed25519"
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Setup authenticator with participant public keys
func SetupAuthentication(participantPubKeys map[frost.Identifier]ed25519.PublicKey) *security.Ed25519Authenticator {
    auth := security.NewEd25519Authenticator()

    for id, pubKey := range participantPubKeys {
        auth.AddPublicKey(id, pubKey)
    }

    return auth
}

// Participant: Sign commitment before sending
func SignCommitment(
    participantID frost.Identifier,
    commitment frost.SigningCommitments,
    privateKey ed25519.PrivateKey,
) ([]byte, error) {
    return security.SignCommitment(participantID, commitment, privateKey)
}

// Coordinator: Verify received commitment
func VerifyCommitment(
    auth *security.Ed25519Authenticator,
    participantID frost.Identifier,
    commitment frost.SigningCommitments,
    signature []byte,
) error {
    return auth.AuthenticateCommitment(participantID, commitment, signature)
}
```

### Message Format

Authenticated messages use the following format:

```
Message = ParticipantID || ProtocolData
Signature = Ed25519.Sign(PrivateKey, Message)

Wire Format:
  [4 bytes: ParticipantID (little-endian)]
  [N bytes: ProtocolData (commitment or share)]
  [64 bytes: Ed25519 Signature]
```

---

## 3. Replay Attack Prevention

### Threat: Nonce Reuse via Replay

If an attacker can replay a participant's commitment from a previous signing session with a different message, the nonce will be reused:

```
Session 1: Sign message M1 with nonce k → commitment C
Session 2: Attacker replays C while participant signs M2 with nonce k'
Result: If C is accepted, nonce k is reused → private key recovery
```

### Defense 1: Message Sequence Numbers

Include monotonically increasing sequence numbers in protocol messages:

```go
package transport

import (
    "encoding/binary"
    "fmt"
    "sync"
)

// MessageEnvelope wraps FROST protocol messages with anti-replay metadata
type MessageEnvelope struct {
    SequenceNumber uint64                    // Monotonically increasing
    SessionID      [32]byte                  // Unique per signing session
    Timestamp      int64                     // Unix timestamp (nanoseconds)
    MessageType    string                    // "commitment" | "signature_share"
    ParticipantID  uint32                    // Sender identifier
    Payload        []byte                    // Actual protocol message
    Signature      [64]byte                  // Ed25519 signature over envelope
}

// SequenceTracker prevents replay attacks via sequence number validation
type SequenceTracker struct {
    mu              sync.RWMutex
    lastSequence    map[uint32]uint64         // ParticipantID -> last seen sequence
    sessionSequence map[[32]byte]uint64       // SessionID -> highest sequence seen
    maxClockSkew    int64                     // Maximum allowed time difference (ns)
}

func NewSequenceTracker(maxClockSkew int64) *SequenceTracker {
    return &SequenceTracker{
        lastSequence:    make(map[uint32]uint64),
        sessionSequence: make(map[[32]byte]uint64),
        maxClockSkew:    maxClockSkew,
    }
}

// ValidateEnvelope checks for replay attacks
func (st *SequenceTracker) ValidateEnvelope(env *MessageEnvelope) error {
    st.mu.Lock()
    defer st.mu.Unlock()

    // 1. Check timestamp freshness (prevents old message replay)
    now := time.Now().UnixNano()
    timeDiff := now - env.Timestamp
    if timeDiff < 0 {
        timeDiff = -timeDiff
    }
    if timeDiff > st.maxClockSkew {
        return fmt.Errorf("message timestamp outside acceptable window: diff=%d, max=%d",
            timeDiff, st.maxClockSkew)
    }

    // 2. Check sequence number monotonicity (per participant)
    lastSeq, exists := st.lastSequence[env.ParticipantID]
    if exists && env.SequenceNumber <= lastSeq {
        return fmt.Errorf("sequence number replay detected: participant=%d, seq=%d, last=%d",
            env.ParticipantID, env.SequenceNumber, lastSeq)
    }

    // 3. Check session-level sequence (prevents cross-session replay)
    lastSessionSeq, exists := st.sessionSequence[env.SessionID]
    if exists && env.SequenceNumber <= lastSessionSeq {
        return fmt.Errorf("session sequence replay detected: session=%x, seq=%d, last=%d",
            env.SessionID, env.SequenceNumber, lastSessionSeq)
    }

    // 4. Update sequence trackers
    st.lastSequence[env.ParticipantID] = env.SequenceNumber
    st.sessionSequence[env.SessionID] = env.SequenceNumber

    return nil
}
```

### Defense 2: Session Identifiers

Generate unique session IDs for each signing operation:

```go
package signing

import (
    "crypto/rand"
    "encoding/binary"
)

// Session represents a single FROST signing operation
type Session struct {
    ID             [32]byte              // Unique session identifier
    StartTime      int64                 // Session start timestamp
    ExpiryTime     int64                 // Session expiration
    Participants   []frost.Identifier    // Expected participants
    Message        []byte                // Message being signed
    Commitments    frost.CommitmentList  // Collected commitments
}

// NewSession creates a new signing session with a unique ID
func NewSession(participants []frost.Identifier, message []byte, ttl time.Duration) (*Session, error) {
    var sessionID [32]byte
    if _, err := rand.Read(sessionID[:]); err != nil {
        return nil, fmt.Errorf("failed to generate session ID: %w", err)
    }

    now := time.Now()
    return &Session{
        ID:           sessionID,
        StartTime:    now.UnixNano(),
        ExpiryTime:   now.Add(ttl).UnixNano(),
        Participants: participants,
        Message:      message,
    }, nil
}

// IsExpired checks if the session has exceeded its TTL
func (s *Session) IsExpired() bool {
    return time.Now().UnixNano() > s.ExpiryTime
}
```

### Defense 3: Commitment Tracking (Already Implemented)

go-frost implements `FrostNonceTracker` to prevent nonce reuse:

```go
package security

import (
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Production coordinator setup with nonce tracking
func NewSecureCoordinator(config security.SecurityConfig) *signing.Coordinator {
    // Nonce tracking is enabled by default in production config
    if config.NonceReuseProtection {
        nonceTracker := config.GetOrCreateNonceTracker()

        // The tracker automatically prevents commitment reuse
        // No additional action needed - integrated into participant.RoundOne()
    }

    return coordinator
}
```

**How it works:**
1. Participant generates commitment C = (hiding, binding)
2. Tracker stores hash(C) with timestamp
3. If C is seen again → ERROR: nonce reuse detected
4. Old commitments expire after configured TTL (default: 24 hours)

---

## 4. Production Deployment Example

### Complete Secure FROST Coordinator

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "time"

    "crypto/ed25519"
    "crypto/tls"
    "github.com/jeremyhahn/go-frost/pkg/frost"
    "github.com/jeremyhahn/go-frost/pkg/frost/security"
    "github.com/jeremyhahn/go-frost/pkg/frost/signing"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// ProductionCoordinator with full security hardening
type ProductionCoordinator struct {
    coordinator     signing.Coordinator
    authenticator   *security.Ed25519Authenticator
    sequenceTracker *SequenceTracker
    sessionManager  *SessionManager
    tlsConfig       *tls.Config
}

func NewProductionCoordinator(
    suite ciphersuite.Ciphersuite,
    participants map[frost.Identifier]signing.Participant,
    aggregator signing.Aggregator,
    groupPublicKey group.Element,
    participantPubKeys map[frost.Identifier]ed25519.PublicKey,
    certFile, keyFile, caFile string,
) (*ProductionCoordinator, error) {

    // 1. Setup TLS 1.3
    tlsConfig, err := NewProductionTLSConfig(certFile, keyFile, caFile)
    if err != nil {
        return nil, fmt.Errorf("TLS setup failed: %w", err)
    }

    // 2. Setup participant authentication
    authenticator := security.NewEd25519Authenticator()
    for id, pubKey := range participantPubKeys {
        authenticator.AddPublicKey(id, pubKey)
    }

    // 3. Setup sequence tracking (5 second max clock skew)
    sequenceTracker := NewSequenceTracker(5 * time.Second)

    // 4. Setup session management
    sessionManager := NewSessionManager(1 * time.Hour) // 1 hour session TTL

    // 5. Create coordinator with security config
    secConfig := security.DefaultProductionConfig()
    secConfig.ParticipantAuthenticator = authenticator

    coord := signing.NewCoordinatorWithAuthenticator(
        suite,
        participants,
        aggregator,
        groupPublicKey,
        authenticator,
    )

    return &ProductionCoordinator{
        coordinator:     coord,
        authenticator:   authenticator,
        sequenceTracker: sequenceTracker,
        sessionManager:  sessionManager,
        tlsConfig:       tlsConfig,
    }, nil
}

// HandleCommitment processes an incoming commitment with full security checks
func (pc *ProductionCoordinator) HandleCommitment(
    env *MessageEnvelope,
    commitment frost.SigningCommitments,
) error {

    // 1. Validate message envelope (anti-replay)
    if err := pc.sequenceTracker.ValidateEnvelope(env); err != nil {
        return fmt.Errorf("replay detection failed: %w", err)
    }

    // 2. Verify session is active
    session, err := pc.sessionManager.GetSession(env.SessionID)
    if err != nil {
        return fmt.Errorf("invalid session: %w", err)
    }
    if session.IsExpired() {
        return fmt.Errorf("session expired")
    }

    // 3. Authenticate participant (message-level auth)
    participantID := frost.Identifier(env.ParticipantID)
    if err := pc.coordinator.AuthenticateCommitment(participantID, commitment, env.Signature[:]); err != nil {
        return fmt.Errorf("authentication failed: %w", err)
    }

    // 4. Store commitment (coordinator logic)
    session.AddCommitment(participantID, commitment)

    return nil
}

// StartServer launches the gRPC server with TLS
func (pc *ProductionCoordinator) StartServer(port int) error {
    lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        return fmt.Errorf("failed to listen: %w", err)
    }

    // Create gRPC server with TLS credentials
    creds := credentials.NewTLS(pc.tlsConfig)
    grpcServer := grpc.NewServer(
        grpc.Creds(creds),
        grpc.MaxRecvMsgSize(1*1024*1024), // 1 MB max message size
    )

    // Register FROST service implementation
    // frost.RegisterCoordinatorServer(grpcServer, pc)

    log.Printf("Secure FROST coordinator listening on port %d (TLS 1.3)", port)
    return grpcServer.Serve(lis)
}
```

---

## 5. Configuration Checklist

### Pre-Production Security Checklist

- [ ] **TLS Configuration**
  - [ ] TLS 1.3 minimum version enforced
  - [ ] Strong cipher suites only (AES-256-GCM, ChaCha20-Poly1305)
  - [ ] Certificate validation enabled
  - [ ] Mutual TLS (mTLS) configured for all participants
  - [ ] Session tickets disabled
  - [ ] Certificate pinning implemented (high-security environments)

- [ ] **Participant Authentication**
  - [ ] Ed25519 authenticator configured with all participant public keys
  - [ ] Commitment signatures verified before processing
  - [ ] Signature share signatures verified before processing
  - [ ] Unknown participants rejected

- [ ] **Replay Protection**
  - [ ] Message sequence numbers implemented
  - [ ] Sequence number monotonicity enforced per participant
  - [ ] Session IDs unique per signing operation
  - [ ] Timestamp validation with bounded clock skew (≤5 seconds)
  - [ ] Commitment tracking enabled (nonce reuse prevention)

- [ ] **Session Management**
  - [ ] Session TTL configured (recommended: 1 hour)
  - [ ] Expired sessions automatically cleaned up
  - [ ] Session ID generation cryptographically secure
  - [ ] Maximum participants per session enforced

- [ ] **DoS Protection**
  - [ ] Message size limits enforced (1 MB recommended)
  - [ ] Rate limiting per participant
  - [ ] Connection timeouts configured
  - [ ] Maximum concurrent sessions limited

---

## 6. Security Best Practices

### Certificate Management

1. **Use Separate Certificates for Each Component**
   - Coordinator has unique certificate
   - Each participant has unique certificate
   - Do NOT share private keys

2. **Certificate Rotation**
   - Rotate certificates every 90 days minimum
   - Automate certificate renewal (Let's Encrypt, cert-manager)
   - Maintain certificate revocation lists (CRLs)

3. **Key Storage**
   - Store private keys in HSM or secure key vault
   - Never commit certificates/keys to source control
   - Use secrets management (HashiCorp Vault, AWS Secrets Manager)

### Network Security

1. **Firewall Configuration**
   - Allow only FROST coordinator port
   - Restrict source IPs to known participants
   - Use VPC/private networks when possible

2. **Intrusion Detection**
   - Monitor for repeated authentication failures
   - Alert on sequence number violations
   - Log all commitment/share submissions

3. **DDoS Mitigation**
   - Use rate limiting per IP/participant
   - Implement connection pooling limits
   - Deploy behind load balancer with DDoS protection

### Monitoring and Alerting

Monitor and alert on:

```yaml
Security Metrics:
  - Authentication failures per participant
  - Sequence number violations
  - Expired session attempts
  - TLS handshake failures
  - Certificate validation errors
  - Nonce reuse detection events
  - Abnormal signing session durations
  - Repeated malicious participant detection

Alert Thresholds:
  - Auth failures: > 3 in 5 minutes
  - Sequence violations: Any occurrence
  - Nonce reuse: Any occurrence (CRITICAL)
  - TLS errors: > 10 in 1 minute
```

---

## 7. Testing Channel Security

### TLS Validation Tests

```bash
# Test TLS version enforcement
openssl s_client -connect coordinator:8443 -tls1_2
# Expected: Connection refused (TLS 1.2 not supported)

openssl s_client -connect coordinator:8443 -tls1_3
# Expected: Connection successful

# Test cipher suites
nmap --script ssl-enum-ciphers -p 8443 coordinator
# Expected: Only TLS 1.3 ciphers listed

# Test certificate validation
openssl s_client -connect coordinator:8443 -CAfile ca.crt
# Expected: Verify return code: 0 (ok)
```

### Replay Attack Tests

```go
func TestReplayAttackPrevention(t *testing.T) {
    coordinator := setupSecureCoordinator(t)

    // Create and send valid commitment
    env1 := createMessageEnvelope(participantID, commitment, seqNum)
    err := coordinator.HandleCommitment(env1, commitment)
    require.NoError(t, err)

    // Attempt replay with same sequence number
    env2 := createMessageEnvelope(participantID, commitment, seqNum) // Same seqNum!
    err = coordinator.HandleCommitment(env2, commitment)
    require.Error(t, err)
    require.Contains(t, err.Error(), "sequence number replay detected")
}
```

---

## 8. Compliance Verification

### RFC 9591 Section 7.2 Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Authenticated channels | Ed25519 message signatures | ✅ |
| Confidential channels | TLS 1.3+ | ✅ |
| Prevent impersonation | ParticipantAuthenticator | ✅ |
| Prevent MITM | TLS certificate validation | ✅ |
| Prevent replay | Sequence numbers + timestamps | ✅ |
| Nonce reuse protection | CommitmentTracker | ✅ |

### Audit Evidence

For security audits, maintain:

1. **TLS Configuration Logs**
   - Cipher suite negotiation logs
   - Certificate validation logs
   - Handshake success/failure rates

2. **Authentication Logs**
   - All authentication attempts (success/failure)
   - Participant identity verification
   - Signature verification results

3. **Security Event Logs**
   - Replay attack detection events
   - Nonce reuse detection events
   - Session expiration events
   - Malicious participant identification

---

## References

- **RFC 9591**: The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol
  - Section 7.2: Authenticated and Confidential Channels
  - Section 7.3: Preventing Nonce Reuse

- **TLS 1.3 Specification**: RFC 8446
- **Ed25519 Signature Scheme**: RFC 8032
- **NIST Guidelines**: SP 800-52 Rev. 2 (TLS Guidelines)

---

## Support and Updates

For questions or security concerns:
- GitHub Issues: https://github.com/jeremyhahn/go-frost/issues
- Security Issues: See SECURITY.md for responsible disclosure

This document is maintained as part of the go-frost project and updated as security best practices evolve.
