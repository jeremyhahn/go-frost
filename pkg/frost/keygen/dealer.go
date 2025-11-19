// Package keygen implements key generation for FROST.
//
// This package implements the trusted dealer key generation approach using
// Verifiable Secret Sharing (VSS) as specified in RFC 9591 Appendix C.
package keygen

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Dealer generates secret shares for FROST participants using a trusted dealer.
type Dealer interface {
	// GenerateShares creates secret shares for participants using Verifiable Secret Sharing.
	//
	// Inputs:
	// - secret: The group secret key (optional, generated if nil)
	// - minSigners: Minimum number of participants required to sign (threshold t)
	// - maxSigners: Total number of participants (n)
	// - participantIDs: List of participant identifiers (must be unique and non-zero)
	//
	// Outputs:
	// - keyPackages: Key packages for each participant
	// - groupPublicKey: The group's public key
	//
	// The dealer:
	// 1. Generates or uses provided secret
	// 2. Creates polynomial of degree (minSigners - 1) with secret as constant term
	// 3. Evaluates polynomial at each participant's identifier to get secret shares
	// 4. Computes verification shares (public commitments to polynomial coefficients)
	// 5. Creates key packages with secret shares and verification data
	//
	// Errors:
	// - Returns error if minSigners > maxSigners
	// - Returns error if participantIDs contains duplicates or zeros
	// - Returns error if minSigners < 2
	GenerateShares(secret group.Scalar, minSigners, maxSigners uint32, participantIDs []frost.Identifier) ([]frost.KeyPackage, group.Element, error)

	// VerifyShare verifies a secret share against verification shares.
	//
	// Inputs:
	// - identifier: The participant's identifier
	// - secretShare: The secret share to verify
	// - verificationShares: List of verification shares (polynomial commitments)
	//
	// Outputs:
	// - valid: True if the share is valid
	//
	// Verification checks:
	// ScalarBaseMult(secret_share) == product_{j=0}^{t} (verification_share_j^{identifier^j})
	VerifyShare(identifier frost.Identifier, secretShare group.Scalar, verificationShares []frost.VerificationShare) error

	// RecoverSecret recovers the group secret from threshold shares.
	// This should only be used for testing or key recovery scenarios.
	//
	// Inputs:
	// - shares: Map of participant identifiers to their secret shares (must have >= minSigners)
	//
	// Outputs:
	// - secret: The recovered group secret
	//
	// Uses Lagrange interpolation to reconstruct the polynomial's constant term.
	RecoverSecret(shares map[frost.Identifier]group.Scalar) (group.Scalar, error)
}

// NewDealer creates a new trusted dealer for key generation.
func NewDealer(suite ciphersuite.Ciphersuite) Dealer {
	return &dealer{
		suite: suite,
	}
}

type dealer struct {
	suite ciphersuite.Ciphersuite
}

// GenerateShares implements Dealer.GenerateShares
func (d *dealer) GenerateShares(secret group.Scalar, minSigners, maxSigners uint32, participantIDs []frost.Identifier) ([]frost.KeyPackage, group.Element, error) {
	// 1. Validate parameters
	if minSigners < 2 {
		return nil, nil, frost.NewParameterError("minSigners", "must be at least 2", frost.ErrInvalidThreshold)
	}

	if minSigners > maxSigners {
		return nil, nil, frost.NewParameterError("minSigners", "cannot exceed maxSigners", frost.ErrInvalidThreshold)
	}

	if uint32(len(participantIDs)) != maxSigners {
		return nil, nil, frost.NewParameterError("participantIDs", "length must equal maxSigners", frost.ErrInvalidParameters)
	}

	// Check for duplicate and zero participant IDs
	seen := make(map[frost.Identifier]bool)
	for _, id := range participantIDs {
		if id == 0 {
			return nil, nil, frost.NewParameterError("participantIDs", "cannot contain zero", frost.ErrInvalidParticipant)
		}
		if seen[id] {
			return nil, nil, frost.NewParameterError("participantIDs", "contains duplicate", frost.ErrDuplicateParticipant)
		}
		seen[id] = true
	}

	// 2. Generate secret if not provided
	grp := d.suite.Group()
	if secret == nil {
		var err error
		secret, err = grp.RandomScalar()
		if err != nil {
			return nil, nil, frost.NewParameterError("secret", "failed to generate random secret", err)
		}
	}

	// 3. Create polynomial of degree (minSigners - 1)
	polyHelper := helpers.NewPolynomialHelper(grp)
	polynomial, err := polyHelper.Generate(secret, minSigners-1)
	if err != nil {
		return nil, nil, err
	}

	// 4. Compute verification shares (commitments to polynomial coefficients)
	vss := NewVSS(grp)
	verificationShares, err := vss.CreateCommitments(polynomial)
	if err != nil {
		return nil, nil, err
	}

	// 5. Compute group public key = ScalarBaseMult(secret)
	groupPublicKey := grp.ScalarBaseMult(secret)

	// 6. For each participant, evaluate polynomial and create key package
	keyPackages := make([]frost.KeyPackage, maxSigners)

	for i, participantID := range participantIDs {
		// Convert participant ID to scalar for polynomial evaluation
		idBytes := make([]byte, grp.ScalarLength())
		idValue := uint32(participantID)
		// Encode as little-endian to match ristretto255 native format
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idValue >> (8 * j))
		}

		idScalar, err := grp.DeserializeScalar(idBytes)
		if err != nil {
			return nil, nil, frost.NewParameterError("participantID", "failed to convert to scalar", err)
		}

		// Evaluate polynomial at participant ID to get secret share
		secretShare := polyHelper.Evaluate(polynomial, idScalar)

		// Create key package
		keyPackages[i] = frost.KeyPackage{
			Identifier:         participantID,
			SecretShare:        secretShare,
			GroupPublicKey:     groupPublicKey,
			VerificationShares: verificationShares,
		}
	}

	return keyPackages, groupPublicKey, nil
}

// VerifyShare implements Dealer.VerifyShare
func (d *dealer) VerifyShare(identifier frost.Identifier, secretShare group.Scalar, verificationShares []frost.VerificationShare) error {
	// Delegate to VSS implementation
	vss := NewVSS(d.suite.Group())
	return vss.VerifyShare(identifier, secretShare, verificationShares)
}

// RecoverSecret implements Dealer.RecoverSecret
func (d *dealer) RecoverSecret(shares map[frost.Identifier]group.Scalar) (group.Scalar, error) {
	if shares == nil {
		return nil, frost.NewParameterError("shares", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(shares) == 0 {
		return nil, frost.NewParameterError("shares", "cannot be empty", frost.ErrInsufficientParticipants)
	}

	grp := d.suite.Group()
	polyHelper := helpers.NewPolynomialHelper(grp)

	// 1. Extract participant IDs and convert to scalars
	xCoords := make([]group.Scalar, 0, len(shares))
	identifiers := make([]frost.Identifier, 0, len(shares))

	for id := range shares {
		identifiers = append(identifiers, id)

		// Convert ID to scalar
		idBytes := make([]byte, grp.ScalarLength())
		idValue := uint32(id)
		// Encode as little-endian to match ristretto255 native format
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(idValue >> (8 * j))
		}

		idScalar, err := grp.DeserializeScalar(idBytes)
		if err != nil {
			return nil, frost.NewParameterError("identifier", "failed to convert to scalar", err)
		}
		xCoords = append(xCoords, idScalar)
	}

	// 2. Use Lagrange interpolation to recover secret at x=0
	// secret = sum(share_i * lambda_i) where lambda_i is the Lagrange coefficient
	secret := grp.NewScalar()

	for i, id := range identifiers {
		// Compute Lagrange coefficient for this participant
		lambda, err := polyHelper.DeriveInterpolatingValue(xCoords, xCoords[i])
		if err != nil {
			return nil, err
		}

		// Multiply share by Lagrange coefficient
		term := shares[id].Mul(lambda)

		// Add to accumulator
		secret = secret.Add(term)
	}

	return secret, nil
}
