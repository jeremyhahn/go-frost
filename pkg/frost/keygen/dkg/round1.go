package dkg

import (
	"bytes"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers"
)

// Part1 executes round 1 of the DKG protocol.
//
// Each participant generates a random secret polynomial, computes commitments
// to its coefficients, and creates a Schnorr proof of knowledge of the
// constant term (their contribution to the group secret).
//
// Inputs:
//   - identifier: This participant's unique identifier (must be non-zero)
//   - maxSigners: Total number of participants (n)
//   - minSigners: Threshold required to sign (t)
//   - suite: The ciphersuite to use
//
// Outputs:
//   - secretPackage: Secret data to keep for round 2 (MUST NOT be shared)
//   - package_: Public data to broadcast to all participants
//
// Errors:
//   - Returns error if parameters are invalid
//   - Returns error if random number generation fails
func Part1(
	identifier frost.Identifier,
	maxSigners, minSigners uint32,
	suite ciphersuite.Ciphersuite,
) (*Round1SecretPackage, *Round1Package, error) {
	// Validate parameters
	if err := validateDKGParameters(minSigners, maxSigners); err != nil {
		return nil, nil, err
	}

	if identifier == 0 {
		return nil, nil, frost.NewParameterError("identifier", "cannot be zero", frost.ErrInvalidParticipant)
	}

	grp := suite.Group()

	// Generate random coefficients for the polynomial
	// Polynomial: f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_(t-1)*x^(t-1)
	coefficients := make([]group.Scalar, minSigners)
	for i := uint32(0); i < minSigners; i++ {
		scalar, err := grp.RandomScalar()
		if err != nil {
			return nil, nil, frost.NewParameterError("coefficients", "failed to generate random coefficient", err)
		}
		coefficients[i] = scalar
	}

	// Compute commitments: C_i = [g^a_0, g^a_1, ..., g^a_(t-1)]
	commitment := make([]group.Element, minSigners)
	for i, coeff := range coefficients {
		commitment[i] = grp.ScalarBaseMult(coeff)
	}

	// Compute proof of knowledge for a_0
	proof, err := computeProofOfKnowledge(identifier, coefficients[0], commitment[0], suite)
	if err != nil {
		return nil, nil, err
	}

	// Create packages
	secretPackage := &Round1SecretPackage{
		Identifier:   identifier,
		Coefficients: coefficients,
		Commitment:   commitment,
		MinSigners:   minSigners,
		MaxSigners:   maxSigners,
	}

	publicPackage := &Round1Package{
		Commitment:       commitment,
		ProofOfKnowledge: *proof,
	}

	return secretPackage, publicPackage, nil
}

// computeProofOfKnowledge creates a Schnorr signature proving knowledge of the secret.
//
// The proof is: sigma = (R, z) where:
//   - k is a random nonce
//   - R = g^k
//   - c = HDKG(identifier || commitment || R)
//   - z = k + secret * c
func computeProofOfKnowledge(
	identifier frost.Identifier,
	secret group.Scalar,
	commitment group.Element,
	suite ciphersuite.Ciphersuite,
) (*Signature, error) {
	grp := suite.Group()

	// Generate random nonce k
	k, err := grp.RandomScalar()
	if err != nil {
		return nil, frost.NewParameterError("nonce", "failed to generate random nonce", err)
	}

	// Compute R = g^k
	R := grp.ScalarBaseMult(k)

	// Compute challenge: c = HDKG(identifier || commitment || R)
	challenge := computeChallenge(identifier, commitment, R, suite)

	// Compute response: z = k + secret * c
	secretTimesChallenge := secret.Mul(challenge)
	z := k.Add(secretTimesChallenge)

	return &Signature{R: R, Z: z}, nil
}

// computeChallenge computes the DKG challenge hash.
// challenge = HDKG(identifier || commitment || R)
func computeChallenge(
	identifier frost.Identifier,
	commitment group.Element,
	R group.Element,
	suite ciphersuite.Ciphersuite,
) group.Scalar {
	grp := suite.Group()

	// Build challenge input
	var buf bytes.Buffer

	// Serialize identifier using group's byte order
	idBytes := make([]byte, grp.ScalarLength())
	id := uint32(identifier)
	if grp.ByteOrder() == group.BigEndian {
		idBytes[len(idBytes)-1] = byte(id)
		idBytes[len(idBytes)-2] = byte(id >> 8)
		idBytes[len(idBytes)-3] = byte(id >> 16)
		idBytes[len(idBytes)-4] = byte(id >> 24)
	} else {
		for j := 0; j < 4 && j < len(idBytes); j++ {
			idBytes[j] = byte(id >> (8 * j))
		}
	}
	buf.Write(idBytes)

	// Serialize commitment (g^a_0)
	buf.Write(commitment.Bytes())

	// Serialize R
	buf.Write(R.Bytes())

	// Hash to scalar using HDKG
	return suite.HDKG(buf.Bytes())
}

// VerifyProofOfKnowledge verifies a participant's proof of knowledge.
//
// Verification equation: g^z == R + commitment^c
// where c = HDKG(identifier || commitment || R)
//
// Inputs:
//   - identifier: The participant's identifier
//   - package_: The round 1 package containing commitment and proof
//   - suite: The ciphersuite to use
//
// Returns:
//   - nil if proof is valid
//   - error if proof is invalid
func VerifyProofOfKnowledge(
	identifier frost.Identifier,
	package_ *Round1Package,
	suite ciphersuite.Ciphersuite,
) error {
	if package_ == nil {
		return frost.NewParameterError("package", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(package_.Commitment) == 0 {
		return frost.NewParameterError("commitment", "cannot be empty", frost.ErrInvalidCommitment)
	}

	grp := suite.Group()

	// Extract proof components
	R := package_.ProofOfKnowledge.R
	z := package_.ProofOfKnowledge.Z

	if R == nil || z == nil {
		return frost.NewVerificationError("proof", "missing R or z component", frost.ErrInvalidParameters)
	}

	// Get the commitment to a_0 (first coefficient)
	commitment := package_.Commitment[0]

	// Recompute challenge: c = HDKG(identifier || commitment || R)
	challenge := computeChallenge(identifier, commitment, R, suite)

	// Verify: g^z == R + commitment^c
	// Left side: g^z
	left := grp.ScalarBaseMult(z)

	// Right side: R + commitment^c
	commitmentTimesChallenge := grp.ScalarMult(commitment, challenge)
	right := R.Add(commitmentTimesChallenge)

	// Check equality
	if !left.Equal(right) {
		return frost.NewProofOfKnowledgeError(identifier, "verification failed: g^z != R + commitment^c", frost.ErrInvalidSignature)
	}

	return nil
}

// validateDKGParameters checks that the DKG parameters are valid.
func validateDKGParameters(minSigners, maxSigners uint32) error {
	if minSigners < 2 {
		return frost.NewParameterError("minSigners", "must be at least 2", frost.ErrInvalidThreshold)
	}

	if maxSigners < 2 {
		return frost.NewParameterError("maxSigners", "must be at least 2", frost.ErrInvalidThreshold)
	}

	if minSigners > maxSigners {
		return frost.NewParameterError("minSigners", "cannot exceed maxSigners", frost.ErrInvalidThreshold)
	}

	return nil
}

// evaluatePolynomial evaluates a polynomial at a given point using Horner's method.
func evaluatePolynomial(coefficients []group.Scalar, x group.Scalar, grp group.Group) group.Scalar {
	polyHelper := helpers.NewPolynomialHelper(grp)
	poly := frost.Polynomial{Coefficients: coefficients}
	return polyHelper.Evaluate(poly, x)
}
