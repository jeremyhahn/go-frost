// Package keygen implements key generation for FROST.
//
// This package provides trusted dealer key generation using
// Verifiable Secret Sharing (VSS) as specified in RFC 9591 Appendix C.
package keygen

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// PublicKeyPackage contains the group public key and all verification shares.
// This is the public output from key generation that can be shared openly.
type PublicKeyPackage struct {
	// GroupPublicKey is the group's aggregated public key used for verification
	GroupPublicKey group.Element

	// VerificationShares contains public verification keys for each participant
	VerificationShares []frost.VerificationShare
}

// TrustedDealerKeygen generates key packages for all participants using a trusted dealer.
//
// This is a convenience function that creates a dealer and generates shares.
//
// Inputs:
//   - maxSigners: Total number of participants
//   - minSigners: Minimum threshold required for signing
//   - identifiers: Participant identifiers (must be unique and non-zero)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - keyPackages: Key packages for each participant (contains secret share)
//   - publicKeyPackage: Public key package (contains group key and verification shares)
//
// Errors:
//   - Returns error if minSigners > maxSigners
//   - Returns error if minSigners < 2
//   - Returns error if identifiers contains duplicates or zeros
func TrustedDealerKeygen(
	maxSigners, minSigners uint32,
	identifiers []frost.Identifier,
	suite ciphersuite.Ciphersuite,
) ([]*frost.KeyPackage, *PublicKeyPackage, error) {
	dealer := NewDealer(suite)
	grp := suite.Group()

	keyPackageValues, groupPublicKey, err := dealer.GenerateShares(nil, minSigners, maxSigners, identifiers)
	if err != nil {
		return nil, nil, err
	}

	// Convert to pointer slice and create per-participant verification shares
	keyPackages := make([]*frost.KeyPackage, len(keyPackageValues))
	verificationShares := make([]frost.VerificationShare, len(keyPackageValues))

	for i := range keyPackageValues {
		kp := keyPackageValues[i]
		keyPackages[i] = &kp

		// Compute per-participant verification key: g^secret_share
		verificationKey := grp.ScalarBaseMult(kp.SecretShare)
		verificationShares[i] = frost.VerificationShare{
			Identifier:      kp.Identifier,
			VerificationKey: verificationKey,
		}
	}

	// Also update the key packages with the per-participant verification shares
	for i := range keyPackages {
		keyPackages[i].VerificationShares = verificationShares
	}

	publicKeyPackage := &PublicKeyPackage{
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
	}

	return keyPackages, publicKeyPackage, nil
}

// ShareInput represents a share to be used for secret reconstruction
type ShareInput struct {
	Identifier frost.Identifier
	Share      group.Scalar
}
