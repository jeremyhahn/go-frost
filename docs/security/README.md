# Security Documentation

Comprehensive security guidance for deploying go-frost in production environments.

## Security Audit

- All 5 ciphersuites constant-time compliant
- RFC 9591 fully compliant

## Critical Security Considerations

### Essential Reading

1. **[error-sanitization.md](error-sanitization.md)** - Signing oracle prevention
   - **CRITICAL**: Required reading before production deployment
   - Prevents signing oracle attacks through message validation

2. **[channel-security.md](channel-security.md)** - Network security
   - TLS configuration
   - Participant authentication
   - Secure channel establishment

3. **[misbehavior-tracking.md](misbehavior-tracking.md)** - Participant reputation
   - Detecting malicious participants
   - Reputation systems and banning
   - Recovery from failures

4. **[side-channel-protection.md](side-channel-protection.md)** - Timing attacks
   - Constant-time operations
   - Memory safety
   - All ciphersuites verified secure

5. **[testing.md](testing.md)** - Security testing
   - Side-channel testing
   - Security test coverage
   - Fuzzing procedures

## Security Principles

This implementation follows cryptographic best practices:

- **Constant-time operations** where applicable to prevent timing attacks
- **Secure random number generation** using crypto/rand
- **Nonce reuse prevention** with comprehensive tracking
- **Input validation** at all API boundaries
- **Typed errors** for proper error handling without information leakage
- **No unsafe operations** - pure Go implementation without pointer magic

## Production Deployment Checklist

Before deploying to production, ensure you have:

- [ ] Read and implemented [error-sanitization.md](error-sanitization.md) guidance
- [ ] Configured TLS as described in [channel-security.md](channel-security.md)
- [ ] Implemented participant authentication
- [ ] Set up misbehavior tracking per [misbehavior-tracking.md](misbehavior-tracking.md)
- [ ] Reviewed and tested against [side-channel-protection.md](side-channel-protection.md)
- [ ] Run security tests from [testing.md](testing.md)
- [ ] Established key backup and recovery procedures
- [ ] Set up monitoring and alerting for security events

## Threat Model

### In-Scope Threats

- **Signing Oracle Attacks**: Application must validate messages before signing
- **Nonce Reuse**: Implementation prevents reuse through tracking
- **Network Attacks**: Requires TLS and authentication
- **Malicious Participants**: Tracked and identifiable abort protocol
- **Side-Channel Attacks**: Mitigated through constant-time operations

### Out-of-Scope Threats

- **Physical Access**: Key material must be protected by the application
- **Memory Extraction**: Use secure enclaves if required
- **DDoS**: Requires application-level rate limiting
- **Social Engineering**: Operational security is application responsibility

## Additional Resources

- [RFC 9591 Section 7: Security Considerations](../rfc-compliance/README.md)
- [Architecture Overview](../architecture/README.md)
- [Implementation Guide](../guides/implementation.md)
