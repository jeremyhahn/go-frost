# Security Documentation

Security guidance for go-frost deployments.

## Security Audit

- All 5 ciphersuites constant-time compliant
- RFC 9591 fully compliant

## Critical Security Considerations

### Essential Reading

1. [error-sanitization.md](error-sanitization.md) - Signing oracle prevention through message validation. Required reading before production deployment.
2. [channel-security.md](channel-security.md) - TLS configuration, participant authentication, and secure channel establishment.
3. [misbehavior-tracking.md](misbehavior-tracking.md) - Detecting malicious participants, reputation systems, banning, and recovery from failures.
4. [side-channel-protection.md](side-channel-protection.md) - Constant-time operations, memory safety, and ciphersuite verification.
5. [testing.md](testing.md) - Side-channel testing, security test coverage, and fuzzing procedures.

## Security Principles

This implementation follows cryptographic best practices:

- **Constant-time operations** where applicable to prevent timing attacks
- **Secure random number generation** using crypto/rand
- **Nonce reuse prevention** with comprehensive tracking
- **Input validation** at all API boundaries
- **Typed errors** for proper error handling without information leakage
- **Audited unsafe usage** limited to secure memory zeroing (secmem package)
- **Secure memory management** via memguard in the `pkg/secmem` package: mlock'd memory protected from swap, encrypted-at-rest storage via Enclave (XSalsa20-Poly1305), guard pages for sensitive byte slices, constant-time zeroing of byte slices and string backing memory, and automatic cleanup on process termination signals

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
- **Memory Extraction**: The memguard-based secmem package provides mlock and encrypted-at-rest protection, but physical memory access remains out of scope
- **DDoS**: Requires application-level rate limiting
- **Social Engineering**: Operational security is application responsibility

## Additional Resources

- [RFC 9591 Section 7: Security Considerations](../rfc-compliance/README.md)
- [Architecture Overview](../architecture/README.md)
- [Implementation Guide](../guides/implementation.md)
