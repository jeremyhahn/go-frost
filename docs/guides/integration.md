# FROST Protocol

This document explains how the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme works.

## Table of Contents

- [Overview](#overview)
- [Threshold Signatures](#threshold-signatures)
- [Key Generation](#key-generation)
- [Two-Round Signing Protocol](#two-round-signing-protocol)
- [Signature Verification](#signature-verification)
- [Security Properties](#security-properties)
- [Comparison with Other Schemes](#comparison-with-other-schemes)

## Overview

FROST is a threshold signature scheme based on Schnorr signatures. It enables a threshold number of participants to cooperatively generate a signature that appears identical to a standard Schnorr signature, with the following key properties:

- **Threshold signing**: Only t-of-n participants are needed to sign
- **Flexibility**: Any threshold subset can create valid signatures
- **Two-round protocol**: Efficient signing with just two rounds
- **Standard verification**: Signatures verify like regular Schnorr signatures
- **Security**: Proven secure under the discrete logarithm assumption

## Threshold Signatures

### What is a Threshold Signature?

In a traditional signature scheme, a single private key signs messages. In a threshold signature scheme:

- The private key is split into **n** shares
- Any **t** of these shares can reconstruct a signature
- Fewer than **t** shares reveal no information about the key
- The resulting signature is indistinguishable from a single-party signature

### Parameters

- **n** (MaxSigners): Total number of participants in the group
- **t** (MinSigners): Threshold - minimum number needed to sign
- Common configurations:
  - **2-of-2**: Both parties must sign (multisig)
  - **2-of-3**: Any 2 of 3 can sign (typical threshold)
  - **5-of-9**: Any 5 of 9 can sign (high availability)

### Use Cases

1. **Multi-party custody**: Cryptocurrency wallets, key management
2. **Distributed trust**: No single point of failure
3. **Access control**: Require approval from multiple parties
4. **Disaster recovery**: Continue operations if some keys are lost
5. **Geographic distribution**: Keys in different locations

## Key Generation

FROST supports two key generation methods. This implementation uses the Trusted Dealer approach.

### Trusted Dealer (Implemented)

A trusted dealer generates all key material and distributes shares to participants.

#### Process

1. **Generate secret**: Dealer creates random group secret `s`
   ```
   s ← random scalar
   ```

2. **Create polynomial**: Dealer creates polynomial of degree t-1
   ```
   f(x) = s + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹
   where s is the constant term and a₁,...,aₜ₋₁ are random
   ```

3. **Evaluate shares**: For each participant i
   ```
   sᵢ = f(i)
   ```

4. **Create verification shares**: For each coefficient aⱼ
   ```
   Aⱼ = aⱼ * G  (scalar multiplication with generator G)
   ```

5. **Compute group public key**:
   ```
   Y = s * G
   ```

6. **Distribute key packages**: Each participant receives:
   - Their secret share: `sᵢ`
   - Group public key: `Y`
   - Verification shares: `{A₀, A₁, ..., Aₜ₋₁}`

#### Verification

Each participant can verify their share:
```
sᵢ * G = Σⱼ (iʲ * Aⱼ)  for j = 0 to t-1
```

### Distributed Key Generation (DKG)

Not yet implemented. In DKG, participants collectively generate the secret without a trusted dealer.

**Advantages of DKG:**
- No trusted dealer needed
- Secret never exists in one place
- More suitable for decentralized scenarios

**Advantages of Trusted Dealer:**
- Simpler implementation
- Faster key generation
- Suitable when dealer trust is acceptable

## Two-Round Signing Protocol

FROST uses a two-round signing protocol that is efficient and secure.

### Participants

- **Signers**: The t participants creating the signature
- **Aggregator/Coordinator**: Collects commitments and shares, creates final signature

### Round One: Commitment Phase

Each signer generates and broadcasts nonce commitments.

#### Steps for each signer i

1. **Generate nonces**: Create two random nonces
   ```
   dᵢ ← random scalar  (hiding nonce)
   eᵢ ← random scalar  (binding nonce)
   ```

2. **Compute commitments**: Create public commitments
   ```
   Dᵢ = dᵢ * G  (hiding nonce commitment)
   Eᵢ = eᵢ * G  (binding nonce commitment)
   ```

3. **Broadcast commitments**: Send `(Dᵢ, Eᵢ)` to coordinator

**Important**: Nonces must be:
- Cryptographically random
- Never reused (critical for security)
- Kept secret until round two

### Preprocessing

After collecting all commitments, the coordinator computes binding factors.

#### Binding Factor Computation

For each participant i in the signing set:

1. **Encode commitment list**: Create sorted list of all commitments
   ```
   B = encode([(i₁, Dᵢ₁, Eᵢ₁), (i₂, Dᵢ₂, Eᵢ₂), ...])
   ```

2. **Compute binding factor**: Using ciphersuite hash function H1
   ```
   ρᵢ = H1(iᵢ, msg, B)
   ```

Binding factors prevent rogue-key attacks and ensure each signature is unique.

#### Group Commitment

Compute the group commitment from all individual commitments:
```
R = Σᵢ (Dᵢ + ρᵢ * Eᵢ)
```

This combines hiding and binding commitments weighted by binding factors.

### Round Two: Signature Share Generation

Each signer computes their signature share.

#### Steps for each signer i

1. **Receive group commitment**: Get `R` and binding factor `ρᵢ` from coordinator

2. **Compute challenge**: Using ciphersuite hash function H2
   ```
   c = H2(R, Y, msg)
   ```
   where Y is the group public key

3. **Compute Lagrange coefficient**: For the signing set {i₁, i₂, ..., iₜ}
   ```
   λᵢ = Πⱼ≠ᵢ (j / (j - i))
   ```

   This coefficient allows any t shares to reconstruct the signature

4. **Compute signature share**:
   ```
   zᵢ = dᵢ + (eᵢ * ρᵢ) + (λᵢ * sᵢ * c)
   ```

   Breaking this down:
   - `dᵢ`: hiding nonce (randomness)
   - `eᵢ * ρᵢ`: binding nonce weighted by binding factor
   - `λᵢ * sᵢ * c`: secret share weighted by Lagrange coefficient and challenge

5. **Send share**: Broadcast `zᵢ` to coordinator

### Aggregation

The coordinator aggregates signature shares into the final signature.

#### Steps

1. **Aggregate shares**: Sum all signature shares
   ```
   z = Σᵢ zᵢ
   ```

2. **Create signature**: Output signature `(R, z)`

The signature is now a valid Schnorr signature!

### Why Two Rounds?

- **Round 1**: Establish commitments before seeing the message
  - Prevents adaptive attacks
  - Binds signers to their nonces

- **Round 2**: Compute shares using the message and commitments
  - Incorporates message into signature
  - Combines shares with Lagrange interpolation

## Signature Verification

FROST signatures are verified exactly like standard Schnorr signatures.

### Verification Equation

Given signature `(R, z)`, message `msg`, and public key `Y`:

```
z * G = R + c * Y
```

where `c = H2(R, Y, msg)`

### Why This Works

The verification equation holds because:

```
z * G = (Σᵢ zᵢ) * G
     = Σᵢ (dᵢ + eᵢ*ρᵢ + λᵢ*sᵢ*c) * G
     = Σᵢ (Dᵢ + ρᵢ*Eᵢ + λᵢ*sᵢ*c*G)
     = R + c * Σᵢ (λᵢ*sᵢ*G)
     = R + c * Y
```

The Lagrange coefficients ensure that `Σᵢ λᵢ*sᵢ = s` (the original secret).

### Compatibility

FROST signatures are:
- **Indistinguishable** from single-signer Schnorr signatures
- **Verifiable** with standard Schnorr verification
- **Compatible** with existing Schnorr infrastructure

## Security Properties

### Cryptographic Assumptions

FROST security relies on:
- **Discrete Logarithm Problem**: Computing `log_G(Y)` is hard
- **Random Oracle Model**: Hash functions behave as random oracles

### Security Guarantees

1. **Unforgeability**:
   - Cannot create valid signatures without t participants
   - Attackers with t-1 shares cannot forge signatures

2. **Binding**:
   - Commitments bind signers to their nonces
   - Prevents adaptive attacks after seeing commitments

3. **Hiding**:
   - Commitments reveal nothing about nonces
   - Nonces remain secret until shares are revealed

4. **Robustness**:
   - Identify and exclude malicious participants
   - Continue protocol with honest participants

5. **Privacy**:
   - Shares reveal no information about the secret
   - Signatures reveal no information about which participants signed

### Attacks and Mitigations

#### Nonce Reuse Attack

**Attack**: If a participant reuses nonces, their secret share can be recovered.

**Mitigation**:
- Use cryptographically secure randomness
- Never reuse nonces (implementation ensures this)
- Deterministic nonce generation (optional)

#### Rogue Key Attack

**Attack**: Malicious participant chooses their key based on others' keys.

**Mitigation**:
- Binding factors in FROST prevent this
- Each signature is bound to specific participant set

#### Denial of Service

**Attack**: Malicious participant doesn't complete signing rounds.

**Mitigation**:
- Use timeouts
- Exclude unresponsive participants
- Retry with different participant set

## Comparison with Other Schemes

### vs. Multi-Signatures

**Multi-signatures** (e.g., MuSig):
- Require ALL n participants
- No threshold capability
- Simpler protocol

**FROST**:
- Only need t of n participants
- Threshold capability
- More complex but more flexible

### vs. Traditional Threshold Schemes

**Traditional schemes** (e.g., threshold DSA):
- Often require 3+ rounds
- Group-specific protocols
- Less efficient

**FROST**:
- Only 2 rounds
- Works with any Schnorr-compatible group
- More efficient

### vs. Multi-Party Computation (MPC)

**MPC approaches**:
- Generic threshold signing
- Higher communication overhead
- More complex setup

**FROST**:
- Specialized for Schnorr signatures
- Optimized for efficiency
- Simpler implementation

## Protocol Flow Diagram

```
Trusted Dealer Key Generation:
┌─────────────────┐
│  Trusted Dealer │
│  1. Generate s  │
│  2. Create f(x) │
│  3. Compute Y   │
└────────┬────────┘
         │
    Distribute
         │
   ┌─────┴──────┐
   │            │
   ▼            ▼
┌──────┐    ┌──────┐
│  P₁  │... │  Pₙ  │
│ (s₁) │    │ (sₙ) │
└──────┘    └──────┘


Two-Round Signing:
Round 1:
┌──────┐         ┌────────────┐         ┌──────┐
│  P₁  │────────▶│ Aggregator │◀────────│  Pₜ  │
│(D₁,E₁)         │            │      (Dₜ,Eₜ)   │
└──────┘         └─────┬──────┘         └──────┘
                       │
                  Compute R, ρᵢ, c
                       │
Round 2:               │
┌──────┐         ┌────┴───────┐         ┌──────┐
│  P₁  │◀────────│ Aggregator │────────▶│  Pₜ  │
│      │   ───▶  │            │  ◀───   │      │
│ (z₁) │   z₁    │ Aggregate  │   zₜ    │ (zₜ) │
└──────┘         └─────┬──────┘         └──────┘
                       │
                  Signature (R, z)
```

## Implementation Notes

### Serialization

- All group elements and scalars are serialized according to the group specification
- Commitment lists are sorted by participant identifier
- Consistent serialization is critical for binding factors

### Randomness

- Use cryptographically secure random number generator
- Consider deterministic nonces (RFC 6979 style) for some use cases
- Never reuse nonces across signing sessions

### State Management

- Track signing rounds and participant states
- Implement timeouts for rounds
- Handle participant failures gracefully

### Network Considerations

FROST is network-agnostic but requires:
- Reliable broadcast for commitments
- Point-to-point communication for shares (optional)
- Consideration for network latency and failures

## References

1. [RFC 9591: The FROST Protocol](https://www.rfc-editor.org/rfc/rfc9591.html)
2. [FROST20: Original Paper](https://eprint.iacr.org/2020/852)
3. [Schnorr Signatures](https://en.wikipedia.org/wiki/Schnorr_signature)
4. [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
