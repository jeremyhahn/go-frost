// Package signing implements FROST signing: Participant, Aggregator, Coordinator and convenience functions.
package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// NoncePackage contains the nonces and commitments generated during Round 1.
type NoncePackage struct {
	Nonces      frost.SigningNonces
	Commitments *frost.SigningCommitments
}

// SignatureShare wraps frost.SignatureShare for convenience.
type SignatureShare = frost.SignatureShare

// GenerateNonces runs round 1 for a participant; keep the nonces secret and share the commitments.
func GenerateNonces(
	identifier frost.Identifier,
	secretShare group.Scalar,
	suite ciphersuite.Ciphersuite,
) (*NoncePackage, error) {
	keyPackage := frost.KeyPackage{
		Identifier:  identifier,
		SecretShare: secretShare,
	}

	participant := NewParticipant(keyPackage, suite)
	nonces, commitments, err := participant.RoundOne()
	if err != nil {
		return nil, err
	}

	return &NoncePackage{
		Nonces:      nonces,
		Commitments: &commitments,
	}, nil
}

// Sign returns the participant's round 2 signature share.
func Sign(
	message []byte,
	keyPackage *frost.KeyPackage,
	noncePackage *NoncePackage,
	allCommitments map[frost.Identifier]*frost.SigningCommitments,
	suite ciphersuite.Ciphersuite,
) (*SignatureShare, error) {
	participant := NewParticipant(*keyPackage, suite)

	// Build commitment list
	commitmentList := make(frost.CommitmentList, 0, len(allCommitments))
	for _, c := range allCommitments {
		commitmentList = append(commitmentList, *c)
	}

	// Sort commitment list by identifier for deterministic behavior
	sortCommitmentList(commitmentList)

	share, err := participant.RoundTwo(noncePackage.Nonces, message, commitmentList)
	if err != nil {
		return nil, err
	}

	return &share, nil
}

// Aggregate combines the signature shares into the FROST signature.
func Aggregate(
	message []byte,
	commitments map[frost.Identifier]*frost.SigningCommitments,
	signatureShares map[frost.Identifier]*SignatureShare,
	verificationShares map[frost.Identifier]frost.VerificationShare,
	groupPublicKey group.Element,
	suite ciphersuite.Ciphersuite,
) (frost.Signature, error) {
	// Build commitment list
	commitmentList := make(frost.CommitmentList, 0, len(commitments))
	for _, c := range commitments {
		commitmentList = append(commitmentList, *c)
	}
	sortCommitmentList(commitmentList)

	// Build signature share slice
	shareSlice := make([]frost.SignatureShare, 0, len(signatureShares))
	for _, s := range signatureShares {
		shareSlice = append(shareSlice, *s)
	}

	// Build verification share slice
	verificationSlice := make([]frost.VerificationShare, 0, len(verificationShares))
	for _, vs := range verificationShares {
		verificationSlice = append(verificationSlice, vs)
	}

	aggregator := NewAggregator(suite, uint32(len(signatureShares)))
	return aggregator.AggregateWithVerification(
		groupPublicKey,
		commitmentList,
		message,
		shareSlice,
		verificationSlice,
	)
}

// VerifySignature returns nil if signature is valid for message and groupPublicKey.
func VerifySignature(
	message []byte,
	signature frost.Signature,
	groupPublicKey group.Element,
	suite ciphersuite.Ciphersuite,
) error {
	aggregator := NewAggregator(suite, 2) // minSigners doesn't matter for verification
	return aggregator.Verify(message, signature, groupPublicKey)
}

// sortCommitmentList sorts the commitment list by identifier for deterministic behavior.
func sortCommitmentList(list frost.CommitmentList) {
	// Simple bubble sort (usually small lists)
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			//nolint:gosec // i and j are bounds-checked by loop conditions
			if list[i].Identifier > list[j].Identifier {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
}
