package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// PolynomialHelper provides operations on polynomials over scalars.
type PolynomialHelper interface {
	// Evaluate evaluates a polynomial at a given x-coordinate.
	//
	// Inputs:
	// - poly: The polynomial to evaluate
	// - x: The x-coordinate at which to evaluate
	//
	// Outputs:
	// - y: The result of evaluating the polynomial at x
	Evaluate(poly frost.Polynomial, x group.Scalar) group.Scalar

	// DeriveInterpolatingValue computes the Lagrange interpolation coefficient
	// for a given x-coordinate within a set of x-coordinates.
	//
	// Inputs:
	// - xCoords: List of x-coordinates (must not contain duplicates or zero)
	// - xi: The x-coordinate for which to compute the coefficient (must be in xCoords)
	//
	// Outputs:
	// - value: The interpolating coefficient
	//
	// Errors:
	// - Returns error if xi is not in xCoords
	// - Returns error if xCoords contains duplicates
	DeriveInterpolatingValue(xCoords []group.Scalar, xi group.Scalar) (group.Scalar, error)

	// Generate creates a random polynomial of degree t with the given constant term.
	//
	// Inputs:
	// - constantTerm: The constant coefficient (polynomial[0])
	// - degree: The maximum degree of the polynomial
	//
	// Outputs:
	// - poly: A random polynomial with the specified constant term
	Generate(constantTerm group.Scalar, degree uint32) (frost.Polynomial, error)
}

// NewPolynomialHelper creates a new polynomial helper.
func NewPolynomialHelper(grp group.Group) PolynomialHelper {
	return &polynomialHelper{group: grp}
}

type polynomialHelper struct {
	group group.Group
}

// Evaluate implements PolynomialHelper.Evaluate
//
// Evaluates a polynomial at a given x-coordinate using Horner's method.
// This is an efficient algorithm with O(n) complexity for degree n polynomial.
//
// Algorithm:
// result = coefficients[degree]
// for i from degree-1 down to 0:
//
//	result = result * x + coefficients[i]
func (p *polynomialHelper) Evaluate(poly frost.Polynomial, x group.Scalar) group.Scalar {
	if len(poly.Coefficients) == 0 {
		return p.group.NewScalar()
	}

	// Start with the highest degree coefficient
	result := poly.Coefficients[len(poly.Coefficients)-1].Copy()

	// Apply Horner's method: work backwards through coefficients
	for i := len(poly.Coefficients) - 2; i >= 0; i-- {
		// result = result * x + coefficients[i]
		result = result.Mul(x).Add(poly.Coefficients[i])
	}

	return result
}

// DeriveInterpolatingValue implements PolynomialHelper.DeriveInterpolatingValue
//
// Computes the Lagrange interpolation coefficient for xi within the set of x-coordinates.
//
// The Lagrange coefficient L_i is computed as:
// L_i = product(xj / (xj - xi)) for all j != i
//
// This can be rewritten as:
// numerator = product(xj) for all j != i
// denominator = product(xj - xi) for all j != i
// L_i = numerator / denominator
func (p *polynomialHelper) DeriveInterpolatingValue(xCoords []group.Scalar, xi group.Scalar) (group.Scalar, error) {
	if len(xCoords) == 0 {
		return nil, frost.NewParameterError("xCoords", "cannot be empty", frost.ErrInvalidParameters)
	}

	if xi == nil {
		return nil, frost.NewParameterError("xi", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Step 1: Verify xi is in xCoords
	found := false
	for _, x := range xCoords {
		if x.Equal(xi) {
			found = true
			break
		}
	}
	if !found {
		return nil, frost.NewParameterError("xi", "not found in x-coordinates", frost.ErrInvalidParameters)
	}

	// Step 2: Check for duplicate x-coordinates
	for i := 0; i < len(xCoords); i++ {
		for j := i + 1; j < len(xCoords); j++ {
			if xCoords[i].Equal(xCoords[j]) {
				return nil, frost.NewParameterError("xCoords", "contains duplicate coordinates", frost.ErrInvalidParameters)
			}
		}
	}

	// Step 3: Compute Lagrange coefficient
	// Special case: if only one coordinate, coefficient is 1 (mathematically correct).
	// NOTE: In FROST, this case should never occur because threshold >= 2 is enforced
	// during key generation (see dealer.go:82-84). This check exists for mathematical
	// completeness and defense-in-depth.
	if len(xCoords) == 1 {
		one := scalarOne(p.group)
		return one, nil
	}

	// Initialize numerator = 1 and denominator = 1
	numerator := scalarOne(p.group)
	denominator := scalarOne(p.group)

	// Compute product terms
	for _, xj := range xCoords {
		if xj.Equal(xi) {
			continue // Skip xi itself
		}

		// numerator *= xj
		numerator = numerator.Mul(xj)

		// denominator *= (xj - xi)
		diff := xj.Sub(xi)
		denominator = denominator.Mul(diff)
	}

	// Return numerator / denominator
	denominatorInv, err := denominator.Inv()
	if err != nil {
		return nil, frost.NewParameterError("denominator", "cannot invert (division by zero)", err)
	}

	result := numerator.Mul(denominatorInv)
	return result, nil
}

// Generate implements PolynomialHelper.Generate
func (p *polynomialHelper) Generate(constantTerm group.Scalar, degree uint32) (frost.Polynomial, error) {
	if constantTerm == nil {
		return frost.Polynomial{}, frost.NewParameterError("constantTerm", "cannot be nil", frost.ErrInvalidParameters)
	}

	// Create polynomial with degree+1 coefficients
	coefficients := make([]group.Scalar, degree+1)

	// Set the constant term (coefficient 0)
	coefficients[0] = constantTerm.Copy()

	// Generate random coefficients for degrees 1 through degree
	for i := uint32(1); i <= degree; i++ {
		randomCoeff, err := p.group.RandomScalar()
		if err != nil {
			return frost.Polynomial{}, frost.NewParameterError("coefficients", "failed to generate random scalar", err)
		}
		coefficients[i] = randomCoeff
	}

	return frost.Polynomial{Coefficients: coefficients}, nil
}

// scalarOne returns the scalar value 1 encoded in the group's native byte order.
func scalarOne(grp group.Group) group.Scalar {
	oneBytes := make([]byte, grp.ScalarLength())
	if grp.ByteOrder() == group.BigEndian {
		oneBytes[len(oneBytes)-1] = 1
	} else {
		oneBytes[0] = 1
	}
	one, _ := grp.DeserializeScalar(oneBytes)
	secmem.ZeroBytes(oneBytes)
	return one
}
