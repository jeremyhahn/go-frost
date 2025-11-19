# Application-Level Message Validation

## Table of Contents

1. [Overview](#overview)
2. [Why Application Validation is Critical](#why-application-validation-is-critical)
3. [The MessageValidator Interface](#the-messagevalidator-interface)
4. [Common Validation Patterns](#common-validation-patterns)
5. [Signing Oracle Attack Prevention](#signing-oracle-attack-prevention)
6. [Use-Case Specific Examples](#use-case-specific-examples)
7. [Custom Validator Implementation](#custom-validator-implementation)
8. [Best Practices](#best-practices)
9. [Security Considerations](#security-considerations)
10. [Integration with FROST](#integration-with-frost)

## Overview

Application-level message validation is a **critical security layer** that sits above the FROST protocol itself. While FROST ensures cryptographic correctness of threshold signatures, it does not validate *what* is being signed. This is where application validation becomes essential.

**Key principle**: The FROST protocol will successfully sign any message you give it. It's your application's responsibility to ensure that only appropriate, safe messages are signed.

Without proper application-level validation, your FROST implementation could become a **signing oracle** that attackers can exploit to sign arbitrary malicious messages.

## Why Application Validation is Critical

### The Signing Oracle Problem

A signing oracle vulnerability occurs when an attacker can trick a signing system into signing messages they shouldn't. In the context of threshold signatures, this is particularly dangerous because:

1. **Distributed Trust**: Multiple parties participate in signing, making it harder to coordinate validation
2. **Automated Signing**: Systems may automatically sign messages without human review
3. **Message Ambiguity**: Without context, a message might appear legitimate but serve a malicious purpose
4. **Replay Attacks**: Previously signed legitimate messages could be reused in different contexts

### Real-World Attack Scenarios

#### Example 1: Financial Transaction Manipulation
```
Legitimate: "Transfer $100 from Alice to Bob"
Malicious:  "Transfer $100000 from Alice to Attacker"
```

Without validation, an attacker who can submit signing requests could drain accounts.

#### Example 2: Certificate Authority Compromise
```
Legitimate: Sign certificate for "example.com" (owned by requester)
Malicious:  Sign certificate for "bank.com" (not owned by requester)
```

An attacker could obtain valid certificates for domains they don't control.

#### Example 3: Smart Contract Exploitation
```
Legitimate: "Execute function transfer(recipient, 100)"
Malicious:  "Execute function changeOwner(attacker)"
```

Without validation, an attacker could manipulate smart contract state.

### The Cost of No Validation

Without application-level validation, you expose your system to:

- **Data exfiltration**: Signing messages that leak sensitive information
- **Unauthorized transactions**: Signing financial transfers or state changes
- **Reputation damage**: Signing messages that appear to come from your organization
- **Compliance violations**: Signing messages that violate policies or regulations
- **DoS attacks**: Processing extremely large or computationally expensive messages

## The MessageValidator Interface

The `MessageValidator` interface provides a structured approach to validating messages before they're signed:

```go
type MessageValidator interface {
    // ValidateStructure checks if the message has a valid structure.
    // This might include format validation, encoding checks, etc.
    ValidateStructure(msg []byte) error

    // ValidateSize checks if the message size is within acceptable limits.
    // This prevents DoS attacks via extremely large messages.
    ValidateSize(msg []byte) error

    // ValidatePolicy checks if the message complies with application policies.
    // This might include content filtering, allowlists/denylists, etc.
    ValidatePolicy(msg []byte) error

    // Validate performs all validation checks.
    // This is a convenience method that calls all other validation methods.
    Validate(msg []byte) error
}
```

### Built-in Validators

#### NoOpValidator

**WARNING**: Only use for testing or when validation is handled at a higher layer.

```go
validator := security.NewNoOpValidator()
// Allows ALL messages - use with extreme caution
```

#### SizeValidator

Protects against DoS attacks via oversized messages:

```go
// For general use: 1 MB limit
validator := security.NewSizeValidator(1024 * 1024)

// For high-security environments: 100 KB limit
validator := security.NewSizeValidator(100 * 1024)

// For large document signing: 10 MB limit
validator := security.NewSizeValidator(10 * 1024 * 1024)
```

#### CompositeValidator

Combines multiple validators for layered validation:

```go
validator := security.NewCompositeValidator(
    security.NewSizeValidator(1024 * 1024),
    NewJSONValidator(),
    NewFinancialTransactionValidator(),
)
```

## Common Validation Patterns

### 1. Structure Validation

Ensure messages conform to expected formats:

```go
type JSONValidator struct {
    maxSize int
}

func (v *JSONValidator) ValidateStructure(msg []byte) error {
    var js json.RawMessage
    if err := json.Unmarshal(msg, &js); err != nil {
        return fmt.Errorf("invalid JSON structure: %w", err)
    }
    return nil
}

func (v *JSONValidator) ValidateSize(msg []byte) error {
    if len(msg) > v.maxSize {
        return security.ErrMessageTooLarge
    }
    return nil
}

func (v *JSONValidator) ValidatePolicy(msg []byte) error {
    return nil // No policy validation
}

func (v *JSONValidator) Validate(msg []byte) error {
    if err := v.ValidateStructure(msg); err != nil {
        return err
    }
    return v.ValidateSize(msg)
}
```

### 2. Schema Validation

Validate against a predefined schema:

```go
type SchemaValidator struct {
    schema *jsonschema.Schema
}

func (v *SchemaValidator) ValidateStructure(msg []byte) error {
    var data interface{}
    if err := json.Unmarshal(msg, &data); err != nil {
        return fmt.Errorf("invalid JSON: %w", err)
    }

    if err := v.schema.Validate(data); err != nil {
        return fmt.Errorf("schema validation failed: %w", err)
    }
    return nil
}
```

### 3. Content Filtering

Prevent signing of blacklisted content:

```go
type ContentFilterValidator struct {
    forbiddenPatterns []*regexp.Regexp
}

func (v *ContentFilterValidator) ValidatePolicy(msg []byte) error {
    msgStr := string(msg)
    for _, pattern := range v.forbiddenPatterns {
        if pattern.MatchString(msgStr) {
            return fmt.Errorf("message contains forbidden content: %w",
                security.ErrMessageValidationFailed)
        }
    }
    return nil
}
```

### 4. Allowlist Validation

Only allow messages from approved sources or types:

```go
type AllowlistValidator struct {
    allowedMessageTypes map[string]bool
}

func (v *AllowlistValidator) ValidatePolicy(msg []byte) error {
    var msgType struct {
        Type string `json:"type"`
    }

    if err := json.Unmarshal(msg, &msgType); err != nil {
        return fmt.Errorf("failed to parse message type: %w", err)
    }

    if !v.allowedMessageTypes[msgType.Type] {
        return fmt.Errorf("message type not allowed: %s", msgType.Type)
    }
    return nil
}
```

## Signing Oracle Attack Prevention

### Understanding Signing Oracles

A signing oracle is any system that signs messages without proper validation. Attackers exploit this by:

1. **Message Confusion**: Crafting messages that appear legitimate but serve malicious purposes
2. **Context Manipulation**: Using signed messages in unintended contexts
3. **Format Exploitation**: Leveraging ambiguous message formats
4. **Timestamp Manipulation**: Reusing old signatures or predating new ones

### Prevention Strategies

#### 1. Message Context Binding

Always include context in the message being signed:

```go
type ContextualMessage struct {
    Domain      string    `json:"domain"`       // "financial.transfer"
    Timestamp   time.Time `json:"timestamp"`    // Current time
    Nonce       string    `json:"nonce"`        // Unique per message
    SessionID   string    `json:"session_id"`   // Current session
    Purpose     string    `json:"purpose"`      // Intended use
    Payload     []byte    `json:"payload"`      // Actual message
}

type ContextValidator struct {
    expectedDomain string
    maxAge         time.Duration
    nonceTracker   NonceTracker
}

func (v *ContextValidator) ValidatePolicy(msg []byte) error {
    var ctxMsg ContextualMessage
    if err := json.Unmarshal(msg, &ctxMsg); err != nil {
        return err
    }

    // Validate domain matches expected
    if ctxMsg.Domain != v.expectedDomain {
        return fmt.Errorf("invalid domain: expected %s, got %s",
            v.expectedDomain, ctxMsg.Domain)
    }

    // Validate timestamp is recent
    age := time.Since(ctxMsg.Timestamp)
    if age > v.maxAge || age < 0 {
        return fmt.Errorf("invalid timestamp: message too old or in future")
    }

    // Validate nonce hasn't been seen before
    if v.nonceTracker.HasSeen(ctxMsg.Nonce) {
        return fmt.Errorf("nonce reuse detected")
    }

    return nil
}
```

#### 2. Domain Separation

Use different signing keys or add domain tags for different purposes:

```go
type DomainSeparatedValidator struct {
    domain string
}

func (v *DomainSeparatedValidator) ValidateStructure(msg []byte) error {
    // Ensure message includes domain prefix
    expectedPrefix := []byte(v.domain + ":")
    if !bytes.HasPrefix(msg, expectedPrefix) {
        return fmt.Errorf("message missing domain prefix")
    }
    return nil
}

// Usage:
// Financial: "financial.transfer:..."
// Certificate: "pki.certificate:..."
// Smart Contract: "blockchain.tx:..."
```

#### 3. Replay Attack Prevention

Prevent reuse of signed messages:

```go
type ReplayPreventionValidator struct {
    seenMessages sync.Map // map[string]time.Time
    windowSize   time.Duration
}

func (v *ReplayPreventionValidator) ValidatePolicy(msg []byte) error {
    // Hash the message
    hash := sha256.Sum256(msg)
    hashStr := hex.EncodeToString(hash[:])

    // Check if we've seen this message
    if timestamp, seen := v.seenMessages.Load(hashStr); seen {
        return fmt.Errorf("replay detected: message seen at %v", timestamp)
    }

    // Record this message
    v.seenMessages.Store(hashStr, time.Now())

    // Cleanup old entries (run periodically)
    v.cleanup()

    return nil
}
```

#### 4. Rate Limiting

Prevent DoS via excessive signing requests:

```go
type RateLimitValidator struct {
    limiter *rate.Limiter
}

func NewRateLimitValidator(reqPerSecond float64, burst int) *RateLimitValidator {
    return &RateLimitValidator{
        limiter: rate.NewLimiter(rate.Limit(reqPerSecond), burst),
    }
}

func (v *RateLimitValidator) ValidatePolicy(msg []byte) error {
    if !v.limiter.Allow() {
        return fmt.Errorf("rate limit exceeded: %w",
            security.ErrMessageValidationFailed)
    }
    return nil
}
```

## Use-Case Specific Examples

### Financial Transactions

```go
type FinancialTransactionValidator struct {
    maxAmount        decimal.Decimal
    allowedCurrencies map[string]bool
    accountValidator  AccountValidator
}

type Transaction struct {
    From      string          `json:"from"`
    To        string          `json:"to"`
    Amount    decimal.Decimal `json:"amount"`
    Currency  string          `json:"currency"`
    Reference string          `json:"reference"`
    Timestamp time.Time       `json:"timestamp"`
}

func (v *FinancialTransactionValidator) ValidateStructure(msg []byte) error {
    var tx Transaction
    if err := json.Unmarshal(msg, &tx); err != nil {
        return fmt.Errorf("invalid transaction structure: %w", err)
    }

    // Validate required fields
    if tx.From == "" || tx.To == "" {
        return fmt.Errorf("missing required fields")
    }

    // Validate amount is positive
    if tx.Amount.LessThanOrEqual(decimal.Zero) {
        return fmt.Errorf("amount must be positive")
    }

    return nil
}

func (v *FinancialTransactionValidator) ValidatePolicy(msg []byte) error {
    var tx Transaction
    json.Unmarshal(msg, &tx)

    // Enforce maximum transaction amount
    if tx.Amount.GreaterThan(v.maxAmount) {
        return fmt.Errorf("amount exceeds maximum allowed")
    }

    // Validate currency is allowed
    if !v.allowedCurrencies[tx.Currency] {
        return fmt.Errorf("currency not allowed: %s", tx.Currency)
    }

    // Validate accounts exist and have sufficient balance
    if err := v.accountValidator.Validate(tx.From, tx.Amount); err != nil {
        return fmt.Errorf("account validation failed: %w", err)
    }

    // Prevent self-transfers
    if tx.From == tx.To {
        return fmt.Errorf("self-transfers not allowed")
    }

    return nil
}

func (v *FinancialTransactionValidator) ValidateSize(msg []byte) error {
    if len(msg) > 10*1024 { // 10 KB max
        return security.ErrMessageTooLarge
    }
    return nil
}

func (v *FinancialTransactionValidator) Validate(msg []byte) error {
    if err := v.ValidateSize(msg); err != nil {
        return err
    }
    if err := v.ValidateStructure(msg); err != nil {
        return err
    }
    return v.ValidatePolicy(msg)
}
```

### Certificate Signing

```go
type CertificateValidator struct {
    allowedDomains     []string
    domainVerifier     DomainOwnershipVerifier
    maxValidityPeriod  time.Duration
}

type CertificateRequest struct {
    Domain       string    `json:"domain"`
    PublicKey    []byte    `json:"public_key"`
    ValidFrom    time.Time `json:"valid_from"`
    ValidUntil   time.Time `json:"valid_until"`
    Organization string    `json:"organization"`
}

func (v *CertificateValidator) ValidateStructure(msg []byte) error {
    var req CertificateRequest
    if err := json.Unmarshal(msg, &req); err != nil {
        return fmt.Errorf("invalid certificate request: %w", err)
    }

    // Validate domain format
    if !isValidDomain(req.Domain) {
        return fmt.Errorf("invalid domain format")
    }

    // Validate public key
    if len(req.PublicKey) == 0 {
        return fmt.Errorf("missing public key")
    }

    return nil
}

func (v *CertificateValidator) ValidatePolicy(msg []byte) error {
    var req CertificateRequest
    json.Unmarshal(msg, &req)

    // Verify domain ownership
    if err := v.domainVerifier.Verify(req.Domain); err != nil {
        return fmt.Errorf("domain ownership verification failed: %w", err)
    }

    // Validate validity period
    validityPeriod := req.ValidUntil.Sub(req.ValidFrom)
    if validityPeriod > v.maxValidityPeriod {
        return fmt.Errorf("validity period exceeds maximum allowed")
    }

    // Ensure ValidFrom is not in the past
    if req.ValidFrom.Before(time.Now().Add(-1 * time.Hour)) {
        return fmt.Errorf("certificate backdating not allowed")
    }

    // Check domain allowlist
    allowed := false
    for _, domain := range v.allowedDomains {
        if matchesDomain(req.Domain, domain) {
            allowed = true
            break
        }
    }
    if !allowed {
        return fmt.Errorf("domain not in allowlist")
    }

    return nil
}
```

### Smart Contract Operations

```go
type SmartContractValidator struct {
    allowedContracts   map[string]bool
    allowedFunctions   map[string]map[string]bool // contract -> function -> allowed
    gasLimitMax        uint64
}

type ContractCall struct {
    Contract string   `json:"contract"`
    Function string   `json:"function"`
    Args     []string `json:"args"`
    GasLimit uint64   `json:"gas_limit"`
    Value    string   `json:"value"`
}

func (v *SmartContractValidator) ValidatePolicy(msg []byte) error {
    var call ContractCall
    if err := json.Unmarshal(msg, &call); err != nil {
        return err
    }

    // Validate contract is allowed
    if !v.allowedContracts[call.Contract] {
        return fmt.Errorf("contract not allowed: %s", call.Contract)
    }

    // Validate function is allowed for this contract
    allowedFuncs, ok := v.allowedFunctions[call.Contract]
    if !ok || !allowedFuncs[call.Function] {
        return fmt.Errorf("function not allowed: %s.%s",
            call.Contract, call.Function)
    }

    // Validate gas limit
    if call.GasLimit > v.gasLimitMax {
        return fmt.Errorf("gas limit exceeds maximum")
    }

    // Prevent dangerous functions
    dangerousFunctions := []string{
        "selfdestruct", "delegatecall", "changeOwner", "transferOwnership",
    }
    for _, dangerous := range dangerousFunctions {
        if strings.Contains(strings.ToLower(call.Function), dangerous) {
            return fmt.Errorf("dangerous function call blocked: %s", call.Function)
        }
    }

    return nil
}
```

### Document Signing

```go
type DocumentValidator struct {
    allowedFormats    map[string]bool // pdf, docx, etc.
    maxSize           int
    virusScanner      VirusScanner
    metadataValidator MetadataValidator
}

type DocumentSigningRequest struct {
    DocumentHash  string            `json:"document_hash"`
    DocumentType  string            `json:"document_type"`
    Metadata      map[string]string `json:"metadata"`
    SignerRole    string            `json:"signer_role"`
}

func (v *DocumentValidator) ValidateStructure(msg []byte) error {
    var req DocumentSigningRequest
    if err := json.Unmarshal(msg, &req); err != nil {
        return fmt.Errorf("invalid document request: %w", err)
    }

    // Validate hash format
    if len(req.DocumentHash) != 64 { // SHA-256 hex
        return fmt.Errorf("invalid document hash format")
    }

    return nil
}

func (v *DocumentValidator) ValidatePolicy(msg []byte) error {
    var req DocumentSigningRequest
    json.Unmarshal(msg, &req)

    // Validate document type is allowed
    if !v.allowedFormats[req.DocumentType] {
        return fmt.Errorf("document type not allowed: %s", req.DocumentType)
    }

    // Validate metadata
    if err := v.metadataValidator.Validate(req.Metadata); err != nil {
        return fmt.Errorf("metadata validation failed: %w", err)
    }

    // Validate signer has appropriate role
    if !isValidSignerRole(req.SignerRole) {
        return fmt.Errorf("invalid signer role: %s", req.SignerRole)
    }

    return nil
}
```

## Custom Validator Implementation

### Step-by-Step Guide

#### Step 1: Define Your Message Structure

```go
// Define what you're signing
type MyMessage struct {
    Type      string    `json:"type"`
    Payload   string    `json:"payload"`
    Timestamp time.Time `json:"timestamp"`
}
```

#### Step 2: Create Validator Struct

```go
type MyCustomValidator struct {
    maxSize         int
    allowedTypes    map[string]bool
    maxMessageAge   time.Duration
}

func NewMyCustomValidator(maxSize int, allowedTypes []string, maxAge time.Duration) *MyCustomValidator {
    typeMap := make(map[string]bool)
    for _, t := range allowedTypes {
        typeMap[t] = true
    }

    return &MyCustomValidator{
        maxSize:       maxSize,
        allowedTypes:  typeMap,
        maxMessageAge: maxAge,
    }
}
```

#### Step 3: Implement ValidateStructure

```go
func (v *MyCustomValidator) ValidateStructure(msg []byte) error {
    var myMsg MyMessage
    if err := json.Unmarshal(msg, &myMsg); err != nil {
        return fmt.Errorf("invalid JSON structure: %w", err)
    }

    // Validate required fields are present
    if myMsg.Type == "" {
        return fmt.Errorf("missing required field: type")
    }

    if myMsg.Payload == "" {
        return fmt.Errorf("missing required field: payload")
    }

    if myMsg.Timestamp.IsZero() {
        return fmt.Errorf("missing required field: timestamp")
    }

    return nil
}
```

#### Step 4: Implement ValidateSize

```go
func (v *MyCustomValidator) ValidateSize(msg []byte) error {
    if len(msg) > v.maxSize {
        return fmt.Errorf("message size %d exceeds maximum %d: %w",
            len(msg), v.maxSize, security.ErrMessageTooLarge)
    }
    return nil
}
```

#### Step 5: Implement ValidatePolicy

```go
func (v *MyCustomValidator) ValidatePolicy(msg []byte) error {
    var myMsg MyMessage
    json.Unmarshal(msg, &myMsg) // Already validated in ValidateStructure

    // Check type is allowed
    if !v.allowedTypes[myMsg.Type] {
        return fmt.Errorf("message type not allowed: %s", myMsg.Type)
    }

    // Check timestamp is recent
    age := time.Since(myMsg.Timestamp)
    if age > v.maxMessageAge {
        return fmt.Errorf("message too old: %v", age)
    }

    if age < 0 {
        return fmt.Errorf("message timestamp in future")
    }

    return nil
}
```

#### Step 6: Implement Validate

```go
func (v *MyCustomValidator) Validate(msg []byte) error {
    if err := v.ValidateSize(msg); err != nil {
        return err
    }

    if err := v.ValidateStructure(msg); err != nil {
        return err
    }

    return v.ValidatePolicy(msg)
}
```

#### Step 7: Use Your Validator

```go
validator := NewMyCustomValidator(
    1024*1024,                    // 1 MB max
    []string{"order", "invoice"}, // allowed types
    5*time.Minute,                // max age
)

// Validate a message
msg := []byte(`{
    "type": "order",
    "payload": "Customer order #12345",
    "timestamp": "2025-11-18T10:30:00Z"
}`)

if err := validator.Validate(msg); err != nil {
    log.Fatalf("Validation failed: %v", err)
}
```

## Best Practices

### 1. Defense in Depth

Use multiple validators in layers:

```go
validator := security.NewCompositeValidator(
    security.NewSizeValidator(1024*1024),  // Size check
    NewJSONValidator(),                     // Format check
    NewSchemaValidator(mySchema),           // Schema check
    NewBusinessRuleValidator(),             // Business logic
    NewRateLimitValidator(10, 100),        // Rate limiting
)
```

### 2. Fail Securely

Default to rejection when in doubt:

```go
func (v *MyValidator) ValidatePolicy(msg []byte) error {
    // If ANY validation fails, reject the message
    if !v.isAllowed(msg) {
        return security.ErrMessageValidationFailed
    }

    // Explicit allowlist approach
    if !v.allowlist.Contains(msg) {
        return fmt.Errorf("message not in allowlist")
    }

    return nil
}
```

### 3. Use Typed Errors

Return specific errors for different failures:

```go
var (
    ErrInvalidFormat     = errors.New("invalid message format")
    ErrUnauthorized      = errors.New("unauthorized message type")
    ErrExpired           = errors.New("message expired")
    ErrRateLimitExceeded = errors.New("rate limit exceeded")
)
```

### 4. Log Validation Failures

Always log failed validations for security monitoring:

```go
func (v *MyValidator) Validate(msg []byte) error {
    if err := v.validateInternal(msg); err != nil {
        log.WithFields(log.Fields{
            "error":       err,
            "message_len": len(msg),
            "timestamp":   time.Now(),
        }).Warn("Message validation failed")
        return err
    }
    return nil
}
```

### 5. Test Thoroughly

Write comprehensive tests including:
- Valid messages
- Invalid formats
- Edge cases
- Malicious inputs
- Performance tests

```go
func TestMyValidator_MaliciousInputs(t *testing.T) {
    validator := NewMyValidator()

    maliciousInputs := [][]byte{
        []byte(`{"type": "../../../etc/passwd"}`),
        []byte(`{"type": "'; DROP TABLE users;--"}`),
        []byte(`{"type": "<script>alert('xss')</script>"}`),
        make([]byte, 1024*1024*100), // 100 MB
    }

    for i, input := range maliciousInputs {
        err := validator.Validate(input)
        if err == nil {
            t.Errorf("case %d: malicious input was not rejected", i)
        }
    }
}
```

## Security Considerations

### What NOT to Sign

Never sign messages containing:

1. **User-controlled input without sanitization**
   ```go
   // BAD: Direct user input
   userInput := req.GetParameter("message")
   signature := frost.Sign([]byte(userInput))

   // GOOD: Validated and sanitized
   if err := validator.Validate([]byte(userInput)); err != nil {
       return err
   }
   signature := frost.Sign([]byte(userInput))
   ```

2. **Executable code or scripts**
   ```go
   // Never sign JavaScript, shell scripts, SQL queries, etc.
   dangerousPatterns := []string{
       "<script>", "javascript:", "eval(",
       "system(", "exec(", "DROP TABLE",
   }
   ```

3. **Ambiguous or multi-purpose messages**
   ```go
   // BAD: Could be interpreted multiple ways
   msg := "Transfer 100"

   // GOOD: Explicit and unambiguous
   msg := `{
       "action": "transfer",
       "amount": 100,
       "currency": "USD",
       "from": "account123",
       "to": "account456"
   }`
   ```

4. **Messages without context binding**
   ```go
   // BAD: No context
   msg := "Approve"

   // GOOD: Context bound
   msg := `{
       "action": "approve",
       "request_id": "req-12345",
       "timestamp": "2025-11-18T10:30:00Z",
       "domain": "approval.system"
   }`
   ```

### Timing Attacks

Be aware of timing side-channels in validation:

```go
// Use constant-time comparison for secrets
func (v *SecretValidator) validateSecret(provided, expected string) bool {
    return subtle.ConstantTimeCompare(
        []byte(provided),
        []byte(expected),
    ) == 1
}
```

### Resource Exhaustion

Protect against resource exhaustion attacks:

```go
type ResourceLimitValidator struct {
    maxConcurrent int32
    current       atomic.Int32
}

func (v *ResourceLimitValidator) Validate(msg []byte) error {
    // Limit concurrent validations
    if v.current.Add(1) > v.maxConcurrent {
        v.current.Add(-1)
        return fmt.Errorf("too many concurrent validations")
    }
    defer v.current.Add(-1)

    // Validation with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    return v.validateWithContext(ctx, msg)
}
```

## Integration with FROST

### Using Validators in FROST Service

```go
// Create FROST service with validation
suite := ristretto255_sha512.New()
frostService := service.NewFrostService(suite)

// Create validator
validator := security.NewCompositeValidator(
    security.NewSizeValidator(1024*1024),
    NewFinancialTransactionValidator(),
)

// Validate before signing
func signTransaction(tx Transaction) error {
    msgBytes, err := json.Marshal(tx)
    if err != nil {
        return err
    }

    // CRITICAL: Validate before signing
    if err := validator.Validate(msgBytes); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    // Now safe to sign
    signature, err := frostService.Sign(signingPackages, msgBytes)
    if err != nil {
        return err
    }

    return nil
}
```

### Validator in Signing Sessions

```go
type ValidatedSigningSession struct {
    session   *service.SigningSession
    validator security.MessageValidator
}

func (s *ValidatedSigningSession) Sign(msg []byte) error {
    // Validate first
    if err := s.validator.Validate(msg); err != nil {
        log.WithError(err).Error("Message validation failed")
        return err
    }

    // Proceed with signing
    return s.session.Sign(msg)
}
```

### Participant-Side Validation

Each participant should also validate:

```go
type ValidatingParticipant struct {
    participant signing.Participant
    validator   security.MessageValidator
}

func (p *ValidatingParticipant) SignRound1(msg []byte) error {
    // Each participant validates independently
    if err := p.validator.Validate(msg); err != nil {
        return fmt.Errorf("participant validation failed: %w", err)
    }

    return p.participant.SignRound1(msg)
}
```

## Conclusion

Application-level message validation is not optional - it's a critical security requirement for any FROST implementation. By following the patterns and best practices outlined in this guide, you can:

- Prevent signing oracle attacks
- Enforce business policies
- Protect against DoS attacks
- Maintain audit trails
- Ensure regulatory compliance

Remember: **The FROST protocol will sign anything you ask it to. It's your responsibility to only ask it to sign appropriate messages.**

For more information, see:
- [Security Guide](CHANNEL_SECURITY.md)
- [Misbehavior Tracking](MISBEHAVIOR_TRACKING.md)
- [RFC 9591 Section 7: Security Considerations](../rfc0001.txt)
