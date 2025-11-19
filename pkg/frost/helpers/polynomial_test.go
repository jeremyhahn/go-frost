package helpers

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/frost/helpers/testutil"
)

func TestPolynomialHelper_Evaluate_Success(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create a simple polynomial: f(x) = 5 + 3x + 2x^2
	coeffs := make([]group.Scalar, 3)

	// Create scalars for coefficients
	coeffs[0] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[0].(*testutil.MockScalar).SetBytes([]byte{5})

	coeffs[1] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[1].(*testutil.MockScalar).SetBytes([]byte{3})

	coeffs[2] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[2].(*testutil.MockScalar).SetBytes([]byte{2})

	poly := frost.Polynomial{Coefficients: coeffs}

	// Evaluate at x = 2: f(2) = 5 + 3*2 + 2*4 = 5 + 6 + 8 = 19
	x := grp.NewScalar().(*testutil.MockScalar)
	x.SetBytes([]byte{2})

	result := helper.Evaluate(poly, x)
	if result == nil {
		t.Fatal("Evaluate() returned nil")
	}

	// Expected: 19
	expected := grp.NewScalar().(*testutil.MockScalar)
	expected.SetBytes([]byte{19})

	if !result.Equal(expected) {
		t.Errorf("Evaluate() = %v, want %v", result.Bytes(), expected.Bytes())
	}
}

func TestPolynomialHelper_Evaluate_AtZero(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create polynomial: f(x) = 10 + 5x + 3x^2
	coeffs := make([]group.Scalar, 3)
	coeffs[0] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[0].(*testutil.MockScalar).SetBytes([]byte{10})
	coeffs[1] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[1].(*testutil.MockScalar).SetBytes([]byte{5})
	coeffs[2] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[2].(*testutil.MockScalar).SetBytes([]byte{3})

	poly := frost.Polynomial{Coefficients: coeffs}

	// Evaluate at x = 0: f(0) = 10
	x := grp.NewScalar()
	result := helper.Evaluate(poly, x)

	expected := grp.NewScalar().(*testutil.MockScalar)
	expected.SetBytes([]byte{10})

	if !result.Equal(expected) {
		t.Errorf("Evaluate(0) = %v, want %v", result.Bytes(), expected.Bytes())
	}
}

func TestPolynomialHelper_Evaluate_ConstantPolynomial(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create constant polynomial: f(x) = 42
	coeffs := make([]group.Scalar, 1)
	coeffs[0] = grp.NewScalar().(*testutil.MockScalar)
	coeffs[0].(*testutil.MockScalar).SetBytes([]byte{42})

	poly := frost.Polynomial{Coefficients: coeffs}

	// Evaluate at x = 7: f(7) = 42
	x := grp.NewScalar().(*testutil.MockScalar)
	x.SetBytes([]byte{7})

	result := helper.Evaluate(poly, x)

	expected := grp.NewScalar().(*testutil.MockScalar)
	expected.SetBytes([]byte{42})

	if !result.Equal(expected) {
		t.Errorf("Evaluate() = %v, want %v", result.Bytes(), expected.Bytes())
	}
}

func TestPolynomialHelper_DeriveInterpolatingValue_Success(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create x-coordinates: [1, 2, 3]
	xCoords := make([]group.Scalar, 3)
	for i := 0; i < 3; i++ {
		xCoords[i] = grp.NewScalar().(*testutil.MockScalar)
		xCoords[i].(*testutil.MockScalar).SetBytes([]byte{byte(i + 1)})
	}

	// Compute interpolating value for xi = 1
	xi := xCoords[0]

	value, err := helper.DeriveInterpolatingValue(xCoords, xi)
	if err != nil {
		t.Fatalf("DeriveInterpolatingValue() error = %v", err)
	}

	if value == nil {
		t.Fatal("DeriveInterpolatingValue() returned nil")
	}

	// The Lagrange coefficient for x_0 = 1 over [1, 2, 3] is:
	// L_0 = (x_1 * x_2) / ((x_1 - x_0) * (x_2 - x_0))
	//     = (2 * 3) / ((2 - 1) * (3 - 1))
	//     = 6 / (1 * 2)
	//     = 3
	expected := grp.NewScalar().(*testutil.MockScalar)
	expected.SetBytes([]byte{3})

	if !value.Equal(expected) {
		t.Errorf("DeriveInterpolatingValue() = %v, want %v", value.Bytes(), expected.Bytes())
	}
}

func TestPolynomialHelper_DeriveInterpolatingValue_NotInList(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create x-coordinates: [1, 2, 3]
	xCoords := make([]group.Scalar, 3)
	for i := 0; i < 3; i++ {
		xCoords[i] = grp.NewScalar().(*testutil.MockScalar)
		xCoords[i].(*testutil.MockScalar).SetBytes([]byte{byte(i + 1)})
	}

	// Try to compute for xi = 4 (not in list)
	xi := grp.NewScalar().(*testutil.MockScalar)
	xi.SetBytes([]byte{4})

	_, err := helper.DeriveInterpolatingValue(xCoords, xi)
	if err == nil {
		t.Fatal("DeriveInterpolatingValue() expected error for xi not in list")
	}
}

func TestPolynomialHelper_DeriveInterpolatingValue_DuplicateCoords(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create x-coordinates with duplicate: [1, 2, 2]
	xCoords := make([]group.Scalar, 3)
	xCoords[0] = grp.NewScalar().(*testutil.MockScalar)
	xCoords[0].(*testutil.MockScalar).SetBytes([]byte{1})
	xCoords[1] = grp.NewScalar().(*testutil.MockScalar)
	xCoords[1].(*testutil.MockScalar).SetBytes([]byte{2})
	xCoords[2] = grp.NewScalar().(*testutil.MockScalar)
	xCoords[2].(*testutil.MockScalar).SetBytes([]byte{2})

	xi := xCoords[0]

	_, err := helper.DeriveInterpolatingValue(xCoords, xi)
	if err == nil {
		t.Fatal("DeriveInterpolatingValue() expected error for duplicate x-coordinates")
	}
}

func TestPolynomialHelper_DeriveInterpolatingValue_SinglePoint(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Single point: [1]
	xCoords := make([]group.Scalar, 1)
	xCoords[0] = grp.NewScalar().(*testutil.MockScalar)
	xCoords[0].(*testutil.MockScalar).SetBytes([]byte{1})

	xi := xCoords[0]

	value, err := helper.DeriveInterpolatingValue(xCoords, xi)
	if err != nil {
		t.Fatalf("DeriveInterpolatingValue() error = %v", err)
	}

	// For a single point, the Lagrange coefficient should be 1
	// Create a properly sized byte slice for the scalar
	oneBytes := make([]byte, 32) // Standard scalar size
	oneBytes[0] = 1 // Little-endian encoding

	one := grp.NewScalar().(*testutil.MockScalar)
	one.SetBytes(oneBytes)

	if !value.Equal(one) {
		t.Errorf("DeriveInterpolatingValue() = %v, want 1", value.Bytes())
	}
}

func TestPolynomialHelper_Generate_Success(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create constant term
	constantTerm := grp.NewScalar().(*testutil.MockScalar)
	constantTerm.SetBytes([]byte{42})

	// Generate polynomial of degree 2
	poly, err := helper.Generate(constantTerm, 2)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify polynomial has correct number of coefficients (degree + 1)
	if len(poly.Coefficients) != 3 {
		t.Errorf("Generate() polynomial length = %d, want 3", len(poly.Coefficients))
	}

	// Verify constant term is correct
	if !poly.Coefficients[0].Equal(constantTerm) {
		t.Errorf("Generate() constant term = %v, want %v",
			poly.Coefficients[0].Bytes(), constantTerm.Bytes())
	}

	// Verify other coefficients are non-nil
	for i := 1; i < len(poly.Coefficients); i++ {
		if poly.Coefficients[i] == nil {
			t.Errorf("Generate() coefficient[%d] is nil", i)
		}
	}
}

func TestPolynomialHelper_Generate_DegreeZero(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	constantTerm := grp.NewScalar().(*testutil.MockScalar)
	constantTerm.SetBytes([]byte{7})

	// Generate polynomial of degree 0 (constant)
	poly, err := helper.Generate(constantTerm, 0)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(poly.Coefficients) != 1 {
		t.Errorf("Generate() polynomial length = %d, want 1", len(poly.Coefficients))
	}

	if !poly.Coefficients[0].Equal(constantTerm) {
		t.Errorf("Generate() constant = %v, want %v",
			poly.Coefficients[0].Bytes(), constantTerm.Bytes())
	}
}

func TestPolynomialHelper_Generate_Randomness(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	constantTerm := grp.NewScalar().(*testutil.MockScalar)
	constantTerm.SetBytes([]byte{5})

	// Generate two polynomials with same constant term
	poly1, err := helper.Generate(constantTerm, 3)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	poly2, err := helper.Generate(constantTerm, 3)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Constant terms should be equal
	if !poly1.Coefficients[0].Equal(poly2.Coefficients[0]) {
		t.Error("Generate() constant terms differ")
	}

	// At least one higher coefficient should differ (with overwhelming probability)
	allEqual := true
	for i := 1; i < len(poly1.Coefficients); i++ {
		if !poly1.Coefficients[i].Equal(poly2.Coefficients[i]) {
			allEqual = false
			break
		}
	}

	if allEqual {
		t.Error("Generate() produced identical polynomials (should be random)")
	}
}

func TestPolynomialHelper_Generate_NilConstant(t *testing.T) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Should handle nil constant term gracefully
	_, err := helper.Generate(nil, 2)
	if err == nil {
		t.Error("Generate() expected error with nil constant term")
	}
}

// BenchmarkPolynomialEvaluate benchmarks polynomial evaluation
func BenchmarkPolynomialEvaluate(b *testing.B) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create polynomial of degree 10
	coeffs := make([]group.Scalar, 11)
	for i := 0; i < 11; i++ {
		coeffs[i] = grp.NewScalar().(*testutil.MockScalar)
		coeffs[i].(*testutil.MockScalar).SetBytes([]byte{byte(i + 1)})
	}
	poly := frost.Polynomial{Coefficients: coeffs}

	x := grp.NewScalar().(*testutil.MockScalar)
	x.SetBytes([]byte{7})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.Evaluate(poly, x)
	}
}

// BenchmarkDeriveInterpolatingValue benchmarks Lagrange coefficient computation
func BenchmarkDeriveInterpolatingValue(b *testing.B) {
	grp := testutil.NewMockGroup()
	helper := NewPolynomialHelper(grp)

	// Create x-coordinates for 5 participants
	xCoords := make([]group.Scalar, 5)
	for i := 0; i < 5; i++ {
		xCoords[i] = grp.NewScalar().(*testutil.MockScalar)
		xCoords[i].(*testutil.MockScalar).SetBytes([]byte{byte(i + 1)})
	}

	xi := xCoords[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DeriveInterpolatingValue(xCoords, xi)
	}
}
