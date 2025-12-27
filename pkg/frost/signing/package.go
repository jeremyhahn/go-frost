package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// SigningPackage bundles the data needed for round 2 of the signing protocol.
// It combines the message with the commitment list, making it convenient to
// pass signing context between participants.
type SigningPackage struct {
	// Message is the message being signed
	Message []byte

	// CommitmentList is the sorted list of participant commitments from round 1
	CommitmentList frost.CommitmentList

	// GroupPublicKey is the group's public key (optional, used for binding factor computation)
	GroupPublicKey group.Element
}

// NewSigningPackage creates a new SigningPackage.
//
// Inputs:
//   - message: The message to be signed
//   - commitmentList: Sorted list of participant commitments
//   - groupPublicKey: The group's public key (can be nil)
//
// Errors:
//   - Returns error if commitment list is empty
//   - Returns error if commitment list is not sorted
func NewSigningPackage(
	message []byte,
	commitmentList frost.CommitmentList,
	groupPublicKey group.Element,
) (*SigningPackage, error) {
	if len(commitmentList) == 0 {
		return nil, frost.ErrEmptyCommitmentList
	}

	// Verify commitment list is sorted (bounds checked above: len > 0, loop starts at 1)
	for i := 1; i < len(commitmentList); i++ {
		if commitmentList[i].Identifier <= commitmentList[i-1].Identifier { //nolint:gosec // bounds checked
			return nil, frost.ErrUnsortedCommitments
		}
	}

	return &SigningPackage{
		Message:        message,
		CommitmentList: commitmentList,
		GroupPublicKey: groupPublicKey,
	}, nil
}

// GetCommitment returns the commitment for a specific participant.
// Returns nil if the participant is not found.
func (sp *SigningPackage) GetCommitment(identifier frost.Identifier) *frost.SigningCommitments {
	for i := range sp.CommitmentList {
		if sp.CommitmentList[i].Identifier == identifier {
			return &sp.CommitmentList[i]
		}
	}
	return nil
}

// GetParticipants returns the list of participant identifiers in the signing package.
func (sp *SigningPackage) GetParticipants() []frost.Identifier {
	participants := make([]frost.Identifier, len(sp.CommitmentList))
	for i, c := range sp.CommitmentList {
		participants[i] = c.Identifier
	}
	return participants
}

// ContainsParticipant returns true if the signing package contains a commitment
// from the specified participant.
func (sp *SigningPackage) ContainsParticipant(identifier frost.Identifier) bool {
	return sp.GetCommitment(identifier) != nil
}

// Len returns the number of commitments in the signing package.
func (sp *SigningPackage) Len() int {
	return len(sp.CommitmentList)
}

// SigningPackageBuilder provides a fluent interface for building SigningPackages.
type SigningPackageBuilder struct {
	message        []byte
	commitments    []frost.SigningCommitments
	groupPublicKey group.Element
}

// NewSigningPackageBuilder creates a new builder for constructing SigningPackages.
func NewSigningPackageBuilder() *SigningPackageBuilder {
	return &SigningPackageBuilder{
		commitments: make([]frost.SigningCommitments, 0),
	}
}

// WithMessage sets the message to be signed.
func (b *SigningPackageBuilder) WithMessage(message []byte) *SigningPackageBuilder {
	b.message = message
	return b
}

// WithGroupPublicKey sets the group public key.
func (b *SigningPackageBuilder) WithGroupPublicKey(publicKey group.Element) *SigningPackageBuilder {
	b.groupPublicKey = publicKey
	return b
}

// AddCommitment adds a participant's commitment to the package.
func (b *SigningPackageBuilder) AddCommitment(commitment frost.SigningCommitments) *SigningPackageBuilder {
	b.commitments = append(b.commitments, commitment)
	return b
}

// AddCommitments adds multiple participant commitments to the package.
func (b *SigningPackageBuilder) AddCommitments(commitments []frost.SigningCommitments) *SigningPackageBuilder {
	b.commitments = append(b.commitments, commitments...)
	return b
}

// Build creates the SigningPackage, sorting the commitment list by identifier.
//
// Errors:
//   - Returns error if no commitments have been added
//   - Returns error if duplicate identifiers are found
func (b *SigningPackageBuilder) Build() (*SigningPackage, error) {
	if len(b.commitments) == 0 {
		return nil, frost.ErrEmptyCommitmentList
	}

	// Sort commitments by identifier
	sortedCommitments := make(frost.CommitmentList, len(b.commitments))
	copy(sortedCommitments, b.commitments)

	// Simple insertion sort (commitment lists are typically small)
	for i := 1; i < len(sortedCommitments); i++ {
		key := sortedCommitments[i]
		j := i - 1
		for j >= 0 && sortedCommitments[j].Identifier > key.Identifier {
			sortedCommitments[j+1] = sortedCommitments[j]
			j--
		}
		sortedCommitments[j+1] = key
	}

	// Check for duplicates
	for i := 1; i < len(sortedCommitments); i++ {
		if sortedCommitments[i].Identifier == sortedCommitments[i-1].Identifier {
			return nil, frost.ErrDuplicateParticipant
		}
	}

	return &SigningPackage{
		Message:        b.message,
		CommitmentList: sortedCommitments,
		GroupPublicKey: b.groupPublicKey,
	}, nil
}
