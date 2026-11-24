package signing

import (
	"bytes"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// BatchItem represents a single signature verification item in a batch.
type BatchItem struct {
	// VerifyingKey is the public key for this signature
	VerifyingKey group.Element

	// Signature is the FROST signature to verify
	Signature frost.Signature

	// Challenge is the pre-computed Schnorr challenge
	Challenge group.Scalar
}

// BatchVerifier verifies many signatures with one randomized multi-scalar check: -sum(b_i z_i) G + sum(b_i R_i) + sum(b_i c_i VK_i) == 0.
type BatchVerifier struct {
	items []BatchItem
	suite ciphersuite.Ciphersuite
}

// NewBatchVerifier creates a new batch verifier for the given ciphersuite.
func NewBatchVerifier(suite ciphersuite.Ciphersuite) *BatchVerifier {
	return &BatchVerifier{
		items: make([]BatchItem, 0),
		suite: suite,
	}
}

// Add queues a signature; errors on a nil or identity key or invalid signature components.
func (bv *BatchVerifier) Add(
	verifyingKey group.Element,
	signature frost.Signature,
	message []byte,
) error {
	if verifyingKey == nil {
		return frost.NewParameterError("verifyingKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	if verifyingKey.IsIdentity() {
		return frost.NewParameterError("verifyingKey", "cannot be identity", frost.ErrIdentityElement)
	}

	if signature.R == nil || signature.Z == nil {
		return frost.NewParameterError("signature", "invalid signature components", frost.ErrInvalidSignature)
	}

	// Security check: R must not be the identity element
	if signature.R.IsIdentity() {
		return frost.NewParameterError("signature.R", "R is identity element", frost.ErrIdentityElement)
	}

	// Pre-compute the challenge: c = H2(R || VK || message)
	var challengeInput bytes.Buffer
	challengeInput.Write(signature.R.Bytes())
	challengeInput.Write(verifyingKey.Bytes())
	challengeInput.Write(message)

	challenge := bv.suite.H2(challengeInput.Bytes())

	bv.items = append(bv.items, BatchItem{
		VerifyingKey: verifyingKey,
		Signature:    signature,
		Challenge:    challenge,
	})

	return nil
}

// Verify checks every queued signature at once; on failure verify individually to find the invalid one.
func (bv *BatchVerifier) Verify() error {
	if len(bv.items) == 0 {
		return frost.NewParameterError("items", "batch is empty", frost.ErrInvalidParameters)
	}

	// For a single item, just do regular verification
	if len(bv.items) == 1 {
		return bv.verifySingle(bv.items[0])
	}

	grp := bv.suite.Group()

	// Accumulate terms for the batch equation:
	// -sum(blind_i * z_i) * G + sum(blind_i * R_i) + sum(blind_i * c_i * VK_i) == 0

	// Accumulator for the G coefficient: -sum(blind_i * z_i)
	gCoeff := grp.NewScalar()

	// Accumulated R and VK terms as group elements
	accumR := grp.Identity()
	accumVK := grp.Identity()

	for _, item := range bv.items {
		// Generate random blind
		blind, err := grp.RandomScalar()
		if err != nil {
			return frost.NewParameterError("blind", "failed to generate random blind", err)
		}

		// G coefficient contribution: blind * z
		blindZ := blind.Mul(item.Signature.Z)
		gCoeff = gCoeff.Sub(blindZ) // Negate because we want -sum(...)

		// R contribution: blind * R
		blindR := grp.ScalarMult(item.Signature.R, blind)
		accumR = accumR.Add(blindR)

		// VK contribution: blind * c * VK
		blindC := blind.Mul(item.Challenge)
		blindCVK := grp.ScalarMult(item.VerifyingKey, blindC)
		accumVK = accumVK.Add(blindCVK)
	}

	// Compute final check: gCoeff * G + accumR + accumVK
	gTerm := grp.ScalarBaseMult(gCoeff)
	check := gTerm.Add(accumR).Add(accumVK)

	// Verify that check equals identity
	if !check.IsIdentity() {
		return frost.NewVerificationError("batch", "batch verification failed", frost.ErrInvalidSignature)
	}

	return nil
}

// verifySingle performs single signature verification.
// Verification equation: z * G == R + c * VK
func (bv *BatchVerifier) verifySingle(item BatchItem) error {
	grp := bv.suite.Group()

	// Left side: z * G
	left := grp.ScalarBaseMult(item.Signature.Z)

	// Right side: R + c * VK
	cVK := grp.ScalarMult(item.VerifyingKey, item.Challenge)
	right := item.Signature.R.Add(cVK)

	if !left.Equal(right) {
		return frost.NewVerificationError("signature", "signature verification failed", frost.ErrInvalidSignature)
	}

	return nil
}

// Size returns the number of signatures in the batch.
func (bv *BatchVerifier) Size() int {
	return len(bv.items)
}

// Clear removes all items from the batch.
func (bv *BatchVerifier) Clear() {
	bv.items = make([]BatchItem, 0)
}

// VerifyAll batch-verifies the given (verifyingKey, signature, message) tuples.
func VerifyAll(
	verifyingKeys []group.Element,
	signatures []frost.Signature,
	messages [][]byte,
	suite ciphersuite.Ciphersuite,
) error {
	if len(verifyingKeys) != len(signatures) || len(signatures) != len(messages) {
		return frost.NewParameterError("inputs", "mismatched input lengths", frost.ErrInvalidParameters)
	}

	if len(signatures) == 0 {
		return frost.NewParameterError("signatures", "no signatures to verify", frost.ErrInvalidParameters)
	}

	bv := NewBatchVerifier(suite)

	for i := range signatures {
		if err := bv.Add(verifyingKeys[i], signatures[i], messages[i]); err != nil {
			return err
		}
	}

	return bv.Verify()
}
