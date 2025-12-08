package signing

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// PreprocessedNonces contains multiple nonces and commitments generated in advance.
// This enables 1-round signing by pre-generating nonces before the message is known.
type PreprocessedNonces struct {
	// Nonces contains the secret nonces (must be kept private)
	Nonces []frost.SigningNonces

	// Commitments contains the corresponding public commitments
	Commitments []frost.SigningCommitments
}

// Zeroize securely erases all nonces from memory.
// This should be called when the preprocessed nonces are no longer needed.
func (p *PreprocessedNonces) Zeroize() {
	for i := range p.Nonces {
		p.Nonces[i].Zeroize()
	}
}

// Len returns the number of remaining nonces available.
func (p *PreprocessedNonces) Len() int {
	return len(p.Nonces)
}

// Next returns and removes the next nonce and commitment pair.
// Returns empty structs and false if no nonces remain.
func (p *PreprocessedNonces) Next() (frost.SigningNonces, frost.SigningCommitments, bool) {
	if len(p.Nonces) == 0 {
		return frost.SigningNonces{}, frost.SigningCommitments{}, false
	}

	nonces := p.Nonces[0]
	commitments := p.Commitments[0]

	// Remove the used nonce and commitment
	p.Nonces = p.Nonces[1:]
	p.Commitments = p.Commitments[1:]

	return nonces, commitments, true
}

// Preprocess generates multiple nonces and commitments for future signing operations.
// This enables 1-round FROST by allowing nonces to be generated before the message is known.
//
// Security Note: Each nonce MUST only be used once. Reusing a nonce will compromise
// the participant's secret key. The PreprocessedNonces.Next() method ensures each
// nonce is only returned once.
//
// Inputs:
//   - count: Number of nonces to generate
//   - identifier: The participant's identifier
//   - secretShare: The participant's secret share (used for deterministic nonce generation)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - preprocessed: The generated nonces and commitments
//
// Errors:
//   - Returns error if count is 0
//   - Returns error if random generation fails
func Preprocess(
	count int,
	identifier frost.Identifier,
	secretShare group.Scalar,
	suite ciphersuite.Ciphersuite,
) (*PreprocessedNonces, error) {
	if count <= 0 {
		return nil, frost.NewParameterError("count", "must be positive", frost.ErrInvalidParameters)
	}

	if identifier == 0 {
		return nil, frost.NewParameterError("identifier", "cannot be zero", frost.ErrInvalidParticipant)
	}

	if secretShare == nil {
		return nil, frost.NewParameterError("secretShare", "cannot be nil", frost.ErrInvalidParameters)
	}

	grp := suite.Group()

	nonces := make([]frost.SigningNonces, count)
	commitments := make([]frost.SigningCommitments, count)

	for i := 0; i < count; i++ {
		// Generate random hiding nonce
		hidingNonce, err := grp.RandomScalar()
		if err != nil {
			// Zeroize any already-generated nonces on error
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("hidingNonce", "failed to generate", err)
		}

		// Generate random binding nonce
		bindingNonce, err := grp.RandomScalar()
		if err != nil {
			// Zeroize any already-generated nonces on error
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("bindingNonce", "failed to generate", err)
		}

		// Compute commitments
		hidingCommitment := grp.ScalarBaseMult(hidingNonce)
		bindingCommitment := grp.ScalarBaseMult(bindingNonce)

		// Security check: commitments must not be identity
		if hidingCommitment.IsIdentity() {
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("hidingCommitment", "commitment is identity", frost.ErrIdentityElement)
		}
		if bindingCommitment.IsIdentity() {
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("bindingCommitment", "commitment is identity", frost.ErrIdentityElement)
		}

		commitments[i] = frost.SigningCommitments{
			Identifier:             identifier,
			HidingNonceCommitment:  hidingCommitment,
			BindingNonceCommitment: bindingCommitment,
		}

		nonces[i] = frost.SigningNonces{
			HidingNonce:  hidingNonce,
			BindingNonce: bindingNonce,
			Commitments:  commitments[i],
		}
	}

	return &PreprocessedNonces{
		Nonces:      nonces,
		Commitments: commitments,
	}, nil
}

// PreprocessDeterministic generates nonces deterministically from a seed.
// This is useful for applications that need reproducible nonce generation
// or want to derive nonces from a master secret.
//
// WARNING: Using the same seed twice will result in nonce reuse, which
// compromises the secret key. Only use this if you have a secure way
// to ensure unique seeds.
//
// Inputs:
//   - count: Number of nonces to generate
//   - identifier: The participant's identifier
//   - seed: Seed for deterministic generation (must be unique per signing session)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - preprocessed: The generated nonces and commitments
func PreprocessDeterministic(
	count int,
	identifier frost.Identifier,
	seed []byte,
	suite ciphersuite.Ciphersuite,
) (*PreprocessedNonces, error) {
	if count <= 0 {
		return nil, frost.NewParameterError("count", "must be positive", frost.ErrInvalidParameters)
	}

	if identifier == 0 {
		return nil, frost.NewParameterError("identifier", "cannot be zero", frost.ErrInvalidParticipant)
	}

	if len(seed) == 0 {
		return nil, frost.NewParameterError("seed", "cannot be empty", frost.ErrInvalidParameters)
	}

	grp := suite.Group()

	nonces := make([]frost.SigningNonces, count)
	commitments := make([]frost.SigningCommitments, count)

	for i := 0; i < count; i++ {
		// Generate hiding nonce: H3(seed || i || "hiding")
		hidingInput := make([]byte, len(seed)+8+6)
		copy(hidingInput, seed)
		hidingInput[len(seed)] = byte(i)
		hidingInput[len(seed)+1] = byte(i >> 8)
		hidingInput[len(seed)+2] = byte(i >> 16)
		hidingInput[len(seed)+3] = byte(i >> 24)
		copy(hidingInput[len(seed)+4:], "hiding")
		hidingNonce := suite.H3(hidingInput)

		// Generate binding nonce: H3(seed || i || "binding")
		bindingInput := make([]byte, len(seed)+8+7)
		copy(bindingInput, seed)
		bindingInput[len(seed)] = byte(i)
		bindingInput[len(seed)+1] = byte(i >> 8)
		bindingInput[len(seed)+2] = byte(i >> 16)
		bindingInput[len(seed)+3] = byte(i >> 24)
		copy(bindingInput[len(seed)+4:], "binding")
		bindingNonce := suite.H3(bindingInput)

		// Compute commitments
		hidingCommitment := grp.ScalarBaseMult(hidingNonce)
		bindingCommitment := grp.ScalarBaseMult(bindingNonce)

		// Security check: commitments must not be identity
		if hidingCommitment.IsIdentity() {
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("hidingCommitment", "commitment is identity", frost.ErrIdentityElement)
		}
		if bindingCommitment.IsIdentity() {
			for j := 0; j < i; j++ {
				nonces[j].Zeroize()
			}
			return nil, frost.NewParameterError("bindingCommitment", "commitment is identity", frost.ErrIdentityElement)
		}

		commitments[i] = frost.SigningCommitments{
			Identifier:             identifier,
			HidingNonceCommitment:  hidingCommitment,
			BindingNonceCommitment: bindingCommitment,
		}

		nonces[i] = frost.SigningNonces{
			HidingNonce:  hidingNonce,
			BindingNonce: bindingNonce,
			Commitments:  commitments[i],
		}
	}

	return &PreprocessedNonces{
		Nonces:      nonces,
		Commitments: commitments,
	}, nil
}
