// Package keygen implements trusted dealer key generation with VSS per RFC 9591 Appendix C.
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

// TrustedDealerKeygen creates a dealer and returns key packages and the public key package for unique non-zero identifiers, with 2 <= minSigners <= maxSigners.
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
