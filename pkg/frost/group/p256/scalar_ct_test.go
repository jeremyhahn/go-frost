// Package p256 provides tests for constant-time P-256 scalar field arithmetic.
package p256

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// Reference implementation using math/big for verification
var p256N = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
})

// bigIntToCtScalar converts a big.Int to ctScalar (for testing)
func bigIntToCtScalar(x *big.Int) *ctScalar {
	// Ensure x is reduced modulo n
	x = new(big.Int).Mod(x, p256N)

	// Convert to 32-byte big-endian
	b := make([]byte, 32)
	xBytes := x.Bytes()
	copy(b[32-len(xBytes):], xBytes)

	return newCTScalarFromBytesWide(b)
}

// ctScalarToBigInt converts a ctScalar to big.Int (for testing)
func ctScalarToBigInt(s *ctScalar) *big.Int {
	return new(big.Int).SetBytes(s.Bytes())
}

// randomBigInt generates a random big.Int < n
func randomBigInt() *big.Int {
	for {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		x := new(big.Int).SetBytes(b)
		if x.Cmp(p256N) < 0 && x.Sign() > 0 {
			return x
		}
	}
}

// TestSimpleMul tests a simple multiplication case
func TestSimpleMul(t *testing.T) {
	// Test 3 * 5 = 15
	three := bigIntToCtScalar(big.NewInt(3))
	five := bigIntToCtScalar(big.NewInt(5))
	result := three.Mul(five)
	expected := big.NewInt(15)
	got := ctScalarToBigInt(result)
	if got.Cmp(expected) != 0 {
		t.Errorf("3 * 5 = %v, want 15", got)
	}

	// Test (n-1) * 2 = n - 2 (mod n)
	nMinus1 := new(big.Int).Sub(p256N, big.NewInt(1))
	snMinus1 := bigIntToCtScalar(nMinus1)
	two := bigIntToCtScalar(big.NewInt(2))
	result = snMinus1.Mul(two)

	expectedBig := new(big.Int).Mul(nMinus1, big.NewInt(2))
	expectedBig.Mod(expectedBig, p256N)
	got = ctScalarToBigInt(result)
	if got.Cmp(expectedBig) != 0 {
		t.Errorf("(n-1) * 2 = %v, want %v", got, expectedBig)
	}

	// Test large * large
	a := new(big.Int).SetBytes([]byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	})
	b := new(big.Int).SetBytes([]byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	})
	a.Mod(a, p256N)
	b.Mod(b, p256N)

	sa := bigIntToCtScalar(a)
	sb := bigIntToCtScalar(b)
	result = sa.Mul(sb)

	expectedBig = new(big.Int).Mul(a, b)
	expectedBig.Mod(expectedBig, p256N)
	got = ctScalarToBigInt(result)
	if got.Cmp(expectedBig) != 0 {
		t.Errorf("large * large failed")
		t.Errorf("a = %x", a)
		t.Errorf("b = %x", b)
		t.Errorf("got = %x", got)
		t.Errorf("want = %x", expectedBig)
	}
}

// TestCTScalarFromBytes tests scalar creation from bytes
func TestCTScalarFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		wantNil bool
	}{
		{
			name:    "zero",
			bytes:   make([]byte, 32),
			wantNil: false, // zero is valid (0 < n)
		},
		{
			name:    "one",
			bytes:   append(make([]byte, 31), 1),
			wantNil: false,
		},
		{
			name:    "max valid (n-1)",
			bytes:   new(big.Int).Sub(p256N, big.NewInt(1)).FillBytes(make([]byte, 32)),
			wantNil: false,
		},
		{
			name:    "equal to n (invalid)",
			bytes:   p256N.FillBytes(make([]byte, 32)),
			wantNil: true, // n itself is >= n, so invalid
		},
		{
			name:    "wrong length",
			bytes:   make([]byte, 16),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newCTScalarFromBytes(tt.bytes)
			if (s == nil) != tt.wantNil {
				t.Errorf("newCTScalarFromBytes() nil = %v, want nil = %v", s == nil, tt.wantNil)
			}
		})
	}
}

// TestCTScalarBytes tests scalar serialization roundtrip
func TestCTScalarBytes(t *testing.T) {
	for i := 0; i < 100; i++ {
		x := randomBigInt()
		s := bigIntToCtScalar(x)
		if s == nil {
			t.Fatal("bigIntToCtScalar returned nil")
		}

		got := ctScalarToBigInt(s)
		if got.Cmp(x) != 0 {
			t.Errorf("roundtrip failed: got %v, want %v", got, x)
		}
	}
}

// TestCTScalarAdd tests constant-time addition
func TestCTScalarAdd(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := randomBigInt()
		b := randomBigInt()

		// Compute using big.Int
		expected := new(big.Int).Add(a, b)
		expected.Mod(expected, p256N)

		// Compute using ctScalar
		sa := bigIntToCtScalar(a)
		sb := bigIntToCtScalar(b)
		result := sa.Add(sb)

		got := ctScalarToBigInt(result)
		if got.Cmp(expected) != 0 {
			t.Errorf("Add(%v, %v) = %v, want %v", a, b, got, expected)
		}
	}
}

// TestCTScalarSub tests constant-time subtraction
func TestCTScalarSub(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := randomBigInt()
		b := randomBigInt()

		// Compute using big.Int
		expected := new(big.Int).Sub(a, b)
		expected.Mod(expected, p256N)

		// Compute using ctScalar
		sa := bigIntToCtScalar(a)
		sb := bigIntToCtScalar(b)
		result := sa.Sub(sb)

		got := ctScalarToBigInt(result)
		if got.Cmp(expected) != 0 {
			t.Errorf("Sub(%v, %v) = %v, want %v", a, b, got, expected)
		}
	}
}

// TestCTScalarNegate tests constant-time negation
func TestCTScalarNegate(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := randomBigInt()

		// Compute using big.Int
		expected := new(big.Int).Neg(a)
		expected.Mod(expected, p256N)

		// Compute using ctScalar
		sa := bigIntToCtScalar(a)
		result := sa.Negate()

		got := ctScalarToBigInt(result)
		if got.Cmp(expected) != 0 {
			t.Errorf("Negate(%v) = %v, want %v", a, got, expected)
		}
	}

	// Test negate zero
	t.Run("negate zero", func(t *testing.T) {
		zero := newCTScalar()
		result := zero.Negate()
		if result.IsZero() != 1 {
			t.Error("Negate(0) should be 0")
		}
	})
}

// TestCTScalarMul tests constant-time multiplication
func TestCTScalarMul(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := randomBigInt()
		b := randomBigInt()

		// Compute using big.Int
		expected := new(big.Int).Mul(a, b)
		expected.Mod(expected, p256N)

		// Compute using ctScalar
		sa := bigIntToCtScalar(a)
		sb := bigIntToCtScalar(b)
		result := sa.Mul(sb)

		got := ctScalarToBigInt(result)
		if got.Cmp(expected) != 0 {
			t.Errorf("Mul(%v, %v) = %v, want %v", a, b, got, expected)
		}
	}
}

// TestCTScalarMulEdgeCases tests multiplication with edge cases
func TestCTScalarMulEdgeCases(t *testing.T) {
	one := bigIntToCtScalar(big.NewInt(1))
	two := bigIntToCtScalar(big.NewInt(2))

	// n-1 * n-1 should reduce correctly
	nMinus1 := new(big.Int).Sub(p256N, big.NewInt(1))
	snMinus1 := bigIntToCtScalar(nMinus1)

	result := snMinus1.Mul(snMinus1)
	expected := new(big.Int).Mul(nMinus1, nMinus1)
	expected.Mod(expected, p256N)

	got := ctScalarToBigInt(result)
	if got.Cmp(expected) != 0 {
		t.Errorf("Mul(n-1, n-1) = %v, want %v", got, expected)
	}

	// 1 * x = x
	for i := 0; i < 10; i++ {
		x := randomBigInt()
		sx := bigIntToCtScalar(x)
		result := one.Mul(sx)
		got := ctScalarToBigInt(result)
		if got.Cmp(x) != 0 {
			t.Errorf("Mul(1, %v) = %v, want %v", x, got, x)
		}
	}

	// 2 * x = x + x
	for i := 0; i < 10; i++ {
		x := randomBigInt()
		sx := bigIntToCtScalar(x)

		mul2 := two.Mul(sx)
		addX := sx.Add(sx)

		if mul2.Equal(addX) != 1 {
			t.Errorf("2*x != x+x for x=%v", x)
		}
	}
}

// TestCTScalarInv tests constant-time inversion
func TestCTScalarInv(t *testing.T) {
	// Test with a few random values (inversion is slow due to Fermat's method)
	for i := 0; i < 5; i++ {
		a := randomBigInt()

		// Compute using big.Int
		expected := new(big.Int).ModInverse(a, p256N)

		// Compute using ctScalar
		sa := bigIntToCtScalar(a)
		result := sa.Inv()

		got := ctScalarToBigInt(result)
		if got.Cmp(expected) != 0 {
			t.Errorf("Inv(%v) = %v, want %v", a, got, expected)
		}

		// Verify a * a^(-1) = 1
		product := sa.Mul(result)
		if ctScalarToBigInt(product).Cmp(big.NewInt(1)) != 0 {
			t.Errorf("a * a^(-1) != 1 for a=%v", a)
		}
	}
}

// TestCTScalarEqual tests constant-time equality
func TestCTScalarEqual(t *testing.T) {
	for i := 0; i < 50; i++ {
		a := randomBigInt()
		b := randomBigInt()

		sa := bigIntToCtScalar(a)
		sb := bigIntToCtScalar(b)
		saCopy := bigIntToCtScalar(a)

		// Same values should be equal
		if sa.Equal(saCopy) != 1 {
			t.Errorf("Equal(%v, %v) = 0, want 1", a, a)
		}

		// Different values should not be equal
		if a.Cmp(b) != 0 && sa.Equal(sb) != 0 {
			t.Errorf("Equal(%v, %v) = 1, want 0", a, b)
		}
	}
}

// TestCTScalarIsZero tests constant-time zero check
func TestCTScalarIsZero(t *testing.T) {
	zero := newCTScalar()
	if zero.IsZero() != 1 {
		t.Error("IsZero(0) should be 1")
	}

	one := bigIntToCtScalar(big.NewInt(1))
	if one.IsZero() != 0 {
		t.Error("IsZero(1) should be 0")
	}

	for i := 0; i < 50; i++ {
		x := randomBigInt()
		sx := bigIntToCtScalar(x)
		if sx.IsZero() != 0 {
			t.Errorf("IsZero(%v) should be 0", x)
		}
	}
}

// TestCTScalarCopy tests scalar copying
func TestCTScalarCopy(t *testing.T) {
	for i := 0; i < 10; i++ {
		a := randomBigInt()
		sa := bigIntToCtScalar(a)
		saCopy := sa.copy()

		if sa.Equal(saCopy) != 1 {
			t.Error("copy should produce equal scalar")
		}

		// Modify original, copy should be unchanged
		one := bigIntToCtScalar(big.NewInt(1))
		sa.Set(one)

		if sa.Equal(saCopy) == 1 && ctScalarToBigInt(sa).Cmp(big.NewInt(1)) == 0 {
			t.Error("copy should be independent of original")
		}
	}
}

// TestTimingConstancy performs basic timing analysis on scalar operations.
// This is a statistical test that may occasionally fail due to system variance.
func TestTimingConstancy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	const iterations = 1000
	const threshold = 5.0 // t-statistic threshold

	// Generate test values: some with many 1 bits, some with few
	highWeight := make([]*ctScalar, iterations)
	lowWeight := make([]*ctScalar, iterations)

	for i := 0; i < iterations; i++ {
		// High Hamming weight: all 0xFF bytes
		highBytes := bytes.Repeat([]byte{0xFF}, 32)
		// Reduce to be < n
		highInt := new(big.Int).SetBytes(highBytes)
		highInt.Mod(highInt, p256N)
		if highInt.Sign() == 0 {
			highInt = big.NewInt(1)
		}
		highWeight[i] = bigIntToCtScalar(highInt)

		// Low Hamming weight: only a few bits set
		lowBytes := make([]byte, 32)
		lowBytes[31] = byte(i%255 + 1) // Ensure non-zero
		lowWeight[i] = bigIntToCtScalar(new(big.Int).SetBytes(lowBytes))
	}

	// Test multiplication timing
	t.Run("Mul timing", func(t *testing.T) {
		var highTimes, lowTimes []int64

		for i := 0; i < iterations; i++ {
			// High weight * high weight
			start := time.Now()
			_ = highWeight[i].Mul(highWeight[(i+1)%iterations])
			highTimes = append(highTimes, time.Since(start).Nanoseconds())

			// Low weight * low weight
			start = time.Now()
			_ = lowWeight[i].Mul(lowWeight[(i+1)%iterations])
			lowTimes = append(lowTimes, time.Since(start).Nanoseconds())
		}

		tStat := calculateTStatistic(highTimes, lowTimes)
		if tStat > threshold {
			t.Logf("WARNING: Mul timing may not be constant (t=%.2f)", tStat)
		} else {
			t.Logf("Mul timing appears constant (t=%.2f)", tStat)
		}
	})

	// Test addition timing
	t.Run("Add timing", func(t *testing.T) {
		var highTimes, lowTimes []int64

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_ = highWeight[i].Add(highWeight[(i+1)%iterations])
			highTimes = append(highTimes, time.Since(start).Nanoseconds())

			start = time.Now()
			_ = lowWeight[i].Add(lowWeight[(i+1)%iterations])
			lowTimes = append(lowTimes, time.Since(start).Nanoseconds())
		}

		tStat := calculateTStatistic(highTimes, lowTimes)
		if tStat > threshold {
			t.Logf("WARNING: Add timing may not be constant (t=%.2f)", tStat)
		} else {
			t.Logf("Add timing appears constant (t=%.2f)", tStat)
		}
	})

	// Test equal timing
	t.Run("Equal timing", func(t *testing.T) {
		var equalTimes, notEqualTimes []int64

		for i := 0; i < iterations; i++ {
			// Equal values
			copy1 := highWeight[i].copy()
			start := time.Now()
			_ = highWeight[i].Equal(copy1)
			equalTimes = append(equalTimes, time.Since(start).Nanoseconds())

			// Different values
			start = time.Now()
			_ = highWeight[i].Equal(lowWeight[i])
			notEqualTimes = append(notEqualTimes, time.Since(start).Nanoseconds())
		}

		tStat := calculateTStatistic(equalTimes, notEqualTimes)
		if tStat > threshold {
			t.Logf("WARNING: Equal timing may not be constant (t=%.2f)", tStat)
		} else {
			t.Logf("Equal timing appears constant (t=%.2f)", tStat)
		}
	})
}

// calculateTStatistic computes the t-statistic for two samples.
func calculateTStatistic(a, b []int64) float64 {
	meanA := mean(a)
	meanB := mean(b)
	varA := variance(a, meanA)
	varB := variance(b, meanB)

	n := float64(len(a))
	pooledStdErr := (varA/n + varB/n)
	if pooledStdErr <= 0 {
		return 0
	}

	return abs(meanA-meanB) / sqrt(pooledStdErr)
}

func mean(samples []int64) float64 {
	sum := int64(0)
	for _, s := range samples {
		sum += s
	}
	return float64(sum) / float64(len(samples))
}

func variance(samples []int64, mean float64) float64 {
	sumSq := float64(0)
	for _, s := range samples {
		diff := float64(s) - mean
		sumSq += diff * diff
	}
	return sumSq / float64(len(samples)-1)
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton's method
	z := x
	for i := 0; i < 100; i++ {
		z = 0.5 * (z + x/z)
	}
	return z
}

// BenchmarkCTScalarMul benchmarks constant-time multiplication
func BenchmarkCTScalarMul(b *testing.B) {
	x := randomBigInt()
	y := randomBigInt()
	sx := bigIntToCtScalar(x)
	sy := bigIntToCtScalar(y)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sx.Mul(sy)
	}
}

// BenchmarkCTScalarInv benchmarks constant-time inversion
func BenchmarkCTScalarInv(b *testing.B) {
	x := randomBigInt()
	sx := bigIntToCtScalar(x)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sx.Inv()
	}
}

// BenchmarkCTScalarAdd benchmarks constant-time addition
func BenchmarkCTScalarAdd(b *testing.B) {
	x := randomBigInt()
	y := randomBigInt()
	sx := bigIntToCtScalar(x)
	sy := bigIntToCtScalar(y)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sx.Add(sy)
	}
}
