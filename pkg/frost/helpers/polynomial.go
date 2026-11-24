package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// PolynomialHelper provides operations on polynomials over scalars.
type PolynomialHelper interface {
	// Evaluate returns the polynomial's value at x.
	Evaluate(poly frost.Polynomial, x group.Scalar) group.Scalar

	// DeriveInterpolatingValue returns the Lagrange coefficient for xi in xCoords; errors if xi is absent or xCoords has duplicates.
	DeriveInterpolatingValue(xCoords []group.Scalar, xi group.Scalar) (group.Scalar, error)

	// Generate returns a random polynomial of the given degree with the given constant term.
	Generate(constantTerm group.Scalar, degree uint32) (frost.Polynomial, error)
}

// NewPolynomialHelper creates a new polynomial helper.
func NewPolynomialHelper(grp group.Group) PolynomialHelper {
	return &polynomialHelper{group: grp}
}

type polynomialHelper struct {
	group group.Group
}

// Evaluate implements PolynomialHelper.Evaluate with Horner's method.
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

// DeriveInterpolatingValue implements PolynomialHelper.DeriveInterpolatingValue: L_i = product(xj) / product(xj - xi) for j != i.
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

	// Step 3: compute the coefficient; a single coordinate gives 1 (keygen enforces threshold >= 2).
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
