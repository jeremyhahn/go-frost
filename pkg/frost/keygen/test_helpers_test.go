package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMockScalar_Inv tests the Inv method of mockScalar
func TestMockScalar_Inv(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       int64
		expectError bool
		description string
	}{
		{
			name:        "invert non-zero scalar",
			value:       5,
			expectError: false,
			description: "non-zero scalar should have an inverse",
		},
		{
			name:        "invert zero scalar",
			value:       0,
			expectError: true,
			description: "zero scalar should return error",
		},
		{
			name:        "invert one",
			value:       1,
			expectError: false,
			description: "inverse of 1 should be 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMockScalar(tt.value, grp.order)
			inv, err := s.Inv()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, inv)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, inv)

				// Verify s * s^-1 = 1
				product := s.Mul(inv)
				assert.True(t, product.Equal(newMockScalar(1, grp.order)))
			}
		})
	}
}

// TestMockScalar_Negate tests the Negate method of mockScalar
func TestMockScalar_Negate(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       int64
		description string
	}{
		{
			name:        "negate positive scalar",
			value:       5,
			description: "negation of positive scalar should be negative modulo order",
		},
		{
			name:        "negate zero",
			value:       0,
			description: "negation of zero should be zero",
		},
		{
			name:        "negate negative scalar",
			value:       -3,
			description: "negation of negative scalar should be positive modulo order",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMockScalar(tt.value, grp.order)
			negated := s.Negate()

			// Verify s + (-s) = 0
			sum := s.Add(negated)
			assert.True(t, sum.IsZero())
		})
	}
}

// TestMockScalar_Bytes tests the Bytes method of mockScalar
func TestMockScalar_Bytes(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       int64
		description string
	}{
		{
			name:        "zero scalar bytes",
			value:       0,
			description: "zero scalar should produce 32 zero bytes",
		},
		{
			name:        "small positive scalar bytes",
			value:       42,
			description: "small scalar should be encoded in 32 bytes",
		},
		{
			name:        "large scalar bytes",
			value:       12345,
			description: "larger scalar should be encoded in 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMockScalar(tt.value, grp.order)
			bytes := s.Bytes()

			assert.Equal(t, 32, len(bytes))

			// Verify bytes can round-trip
			deserialized, err := grp.DeserializeScalar(bytes)
			assert.NoError(t, err)
			assert.True(t, s.Equal(deserialized))
		})
	}
}

// TestMockScalar_Compare tests the Compare method of mockScalar
func TestMockScalar_Compare(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value1      int64
		value2      int64
		expected    int
		description string
	}{
		{
			name:        "equal scalars",
			value1:      5,
			value2:      5,
			expected:    0,
			description: "equal scalars should compare equal",
		},
		{
			name:        "first scalar greater",
			value1:      10,
			value2:      5,
			expected:    1,
			description: "greater scalar should compare as 1",
		},
		{
			name:        "first scalar less",
			value1:      3,
			value2:      7,
			expected:    -1,
			description: "lesser scalar should compare as -1",
		},
		{
			name:        "zero vs non-zero",
			value1:      0,
			value2:      1,
			expected:    -1,
			description: "zero should be less than non-zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := newMockScalar(tt.value1, grp.order)
			s2 := newMockScalar(tt.value2, grp.order)

			result := s1.Compare(s2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMockElement_Negate tests the Negate method of mockElement
func TestMockElement_Negate(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		x           int64
		y           int64
		description string
	}{
		{
			name:        "negate non-identity element",
			x:           3,
			y:           5,
			description: "negation should flip both coordinates",
		},
		{
			name:        "negate identity element",
			x:           0,
			y:           0,
			description: "negation of identity should be identity",
		},
		{
			name:        "negate element with negative coordinates",
			x:           -2,
			y:           -4,
			description: "negation should handle negative coordinates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newMockElement(tt.x, tt.y, grp.order)
			negated := e.Negate()

			// Verify e + (-e) = identity
			sum := e.Add(negated)
			assert.True(t, sum.IsIdentity())
		})
	}
}

// TestMockElement_Bytes tests the Bytes method of mockElement
func TestMockElement_Bytes(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		x           int64
		y           int64
		description string
	}{
		{
			name:        "identity element bytes",
			x:           0,
			y:           0,
			description: "identity element should produce 64 zero bytes",
		},
		{
			name:        "non-identity element bytes",
			x:           3,
			y:           5,
			description: "non-identity element should be encoded in 64 bytes",
		},
		{
			name:        "element with large coordinates",
			x:           123,
			y:           456,
			description: "element with larger coordinates should be encoded in 64 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newMockElement(tt.x, tt.y, grp.order)
			bytes := e.Bytes()

			assert.Equal(t, 64, len(bytes))

			// For non-identity elements, verify round-trip
			if !e.IsIdentity() {
				deserialized, err := grp.DeserializeElement(bytes)
				assert.NoError(t, err)
				assert.True(t, e.Equal(deserialized))
			}
		})
	}
}

// TestMockGroup_Order tests the Order method of mockGroup
func TestMockGroup_Order(t *testing.T) {
	grp := newMockGroup()

	orderBytes := grp.Order()
	assert.NotNil(t, orderBytes)
	assert.Greater(t, len(orderBytes), 0)

	// Verify the order matches the expected value
	orderInt := new(big.Int).SetBytes(orderBytes)
	assert.Equal(t, grp.order.Int64(), orderInt.Int64())
}

// TestMockGroup_Generator tests the Generator method of mockGroup
func TestMockGroup_Generator(t *testing.T) {
	grp := newMockGroup()

	gen := grp.Generator()
	assert.NotNil(t, gen)
	assert.False(t, gen.IsIdentity())

	// Verify generator is a copy, not the same object
	gen2 := grp.Generator()
	assert.True(t, gen.Equal(gen2))
	assert.NotSame(t, gen, gen2)
}

// TestMockGroup_NewElement tests the NewElement method of mockGroup
func TestMockGroup_NewElement(t *testing.T) {
	grp := newMockGroup()

	elem := grp.NewElement()
	assert.NotNil(t, elem)
	assert.True(t, elem.IsIdentity())
}

// TestMockGroup_RandomScalar tests the RandomScalar method of mockGroup
func TestMockGroup_RandomScalar(t *testing.T) {
	grp := newMockGroup()

	// Test multiple random scalars
	for i := 0; i < 10; i++ {
		scalar, err := grp.RandomScalar()
		assert.NoError(t, err)
		assert.NotNil(t, scalar)
		assert.False(t, scalar.IsZero())

		// Verify scalar is within valid range
		scalarCopy := scalar.(*mockScalar)
		assert.True(t, scalarCopy.value.Cmp(big.NewInt(0)) > 0)
		assert.True(t, scalarCopy.value.Cmp(grp.order) < 0)
	}

	// Test randomness - collect several scalars and verify they're not all the same
	scalars := make([]int64, 20)
	for i := 0; i < 20; i++ {
		scalar, err := grp.RandomScalar()
		assert.NoError(t, err)
		scalars[i] = scalar.(*mockScalar).value.Int64()
	}

	// Check that we got at least 2 different values (probabilistically)
	unique := make(map[int64]bool)
	for _, s := range scalars {
		unique[s] = true
	}
	assert.Greater(t, len(unique), 1, "random scalars should produce different values")
}

// TestMockGroup_SerializeElement tests the SerializeElement method of mockGroup
func TestMockGroup_SerializeElement(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		x           int64
		y           int64
		expectError bool
		description string
	}{
		{
			name:        "serialize non-identity element",
			x:           3,
			y:           5,
			expectError: false,
			description: "non-identity element should serialize successfully",
		},
		{
			name:        "serialize identity element",
			x:           0,
			y:           0,
			expectError: true,
			description: "identity element should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elem := newMockElement(tt.x, tt.y, grp.order)
			bytes, err := grp.SerializeElement(elem)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, bytes)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 64, len(bytes))
			}
		})
	}
}

// TestMockGroup_DeserializeElement tests the DeserializeElement method of mockGroup
func TestMockGroup_DeserializeElement(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		setupBytes  func() []byte
		expectError bool
		description string
	}{
		{
			name: "deserialize valid non-identity element",
			setupBytes: func() []byte {
				elem := newMockElement(3, 5, grp.order)
				return elem.Bytes()
			},
			expectError: false,
			description: "valid non-identity element bytes should deserialize successfully",
		},
		{
			name: "deserialize identity element",
			setupBytes: func() []byte {
				return make([]byte, 64)
			},
			expectError: true,
			description: "identity element bytes should return error",
		},
		{
			name: "deserialize invalid length",
			setupBytes: func() []byte {
				return make([]byte, 32)
			},
			expectError: true,
			description: "invalid length should return error",
		},
		{
			name: "deserialize too long",
			setupBytes: func() []byte {
				return make([]byte, 128)
			},
			expectError: true,
			description: "too long bytes should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := tt.setupBytes()
			elem, err := grp.DeserializeElement(bytes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, elem)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, elem)
				assert.False(t, elem.IsIdentity())
			}
		})
	}
}

// TestMockGroup_SerializeScalar tests the SerializeScalar method of mockGroup
func TestMockGroup_SerializeScalar(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       int64
		description string
	}{
		{
			name:        "serialize zero scalar",
			value:       0,
			description: "zero scalar should serialize to 32 bytes",
		},
		{
			name:        "serialize non-zero scalar",
			value:       42,
			description: "non-zero scalar should serialize to 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scalar := newMockScalar(tt.value, grp.order)
			bytes := grp.SerializeScalar(scalar)

			assert.Equal(t, 32, len(bytes))
		})
	}
}

// TestMockGroup_DeserializeScalar tests the DeserializeScalar method of mockGroup
func TestMockGroup_DeserializeScalar(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		setupBytes  func() []byte
		expectError bool
		description string
	}{
		{
			name: "deserialize valid scalar",
			setupBytes: func() []byte {
				scalar := newMockScalar(42, grp.order)
				return scalar.Bytes()
			},
			expectError: false,
			description: "valid scalar bytes should deserialize successfully",
		},
		{
			name: "deserialize zero scalar",
			setupBytes: func() []byte {
				return make([]byte, 32)
			},
			expectError: false,
			description: "zero scalar bytes should deserialize successfully",
		},
		{
			name: "deserialize invalid length - too short",
			setupBytes: func() []byte {
				return make([]byte, 16)
			},
			expectError: true,
			description: "invalid length should return error",
		},
		{
			name: "deserialize invalid length - too long",
			setupBytes: func() []byte {
				return make([]byte, 64)
			},
			expectError: true,
			description: "too long bytes should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := tt.setupBytes()
			scalar, err := grp.DeserializeScalar(bytes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, scalar)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, scalar)
			}
		})
	}
}

// TestMockGroup_ElementLength tests the ElementLength method of mockGroup
func TestMockGroup_ElementLength(t *testing.T) {
	grp := newMockGroup()

	length := grp.ElementLength()
	assert.Equal(t, 64, length)
}

// TestMockGroup_Name tests the Name method of mockGroup
func TestMockGroup_Name(t *testing.T) {
	grp := newMockGroup()

	name := grp.Name()
	assert.Equal(t, "mock-group", name)
}

// TestCreateParticipantIDs tests the createParticipantIDs helper function
func TestCreateParticipantIDs(t *testing.T) {
	tests := []struct {
		name        string
		count       int
		description string
	}{
		{
			name:        "create single participant",
			count:       1,
			description: "should create one participant ID",
		},
		{
			name:        "create multiple participants",
			count:       5,
			description: "should create five participant IDs",
		},
		{
			name:        "create zero participants",
			count:       0,
			description: "should create empty slice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := createParticipantIDs(tt.count)

			assert.Equal(t, tt.count, len(ids))

			// Verify IDs are sequential starting from 1
			for i := 0; i < tt.count; i++ {
				assert.Equal(t, i+1, int(ids[i]))
			}
		})
	}
}

// TestMockScalarFromBig tests the newMockScalarFromBig constructor
func TestMockScalarFromBig(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       *big.Int
		description string
	}{
		{
			name:        "create from big int zero",
			value:       big.NewInt(0),
			description: "should create zero scalar",
		},
		{
			name:        "create from big int positive",
			value:       big.NewInt(42),
			description: "should create scalar with value 42",
		},
		{
			name:        "create from big int larger than order",
			value:       big.NewInt(200),
			description: "should reduce modulo order",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scalar := newMockScalarFromBig(tt.value, grp.order)

			assert.NotNil(t, scalar)
			assert.NotNil(t, scalar.value)

			// Verify value is reduced modulo order
			assert.True(t, scalar.value.Cmp(grp.order) < 0)
			assert.True(t, scalar.value.Cmp(big.NewInt(0)) >= 0)
		})
	}
}

// TestMockScalar_RoundTrip tests serialization round-trip
func TestMockScalar_RoundTrip(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		value       int64
		description string
	}{
		{
			name:        "round-trip zero",
			value:       0,
			description: "zero should round-trip correctly",
		},
		{
			name:        "round-trip small value",
			value:       42,
			description: "small value should round-trip correctly",
		},
		{
			name:        "round-trip larger value",
			value:       95,
			description: "value near order should round-trip correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newMockScalar(tt.value, grp.order)
			bytes := original.Bytes()
			restored, err := grp.DeserializeScalar(bytes)

			assert.NoError(t, err)
			assert.True(t, original.Equal(restored))
		})
	}
}

// TestMockElement_RoundTrip tests element serialization round-trip
func TestMockElement_RoundTrip(t *testing.T) {
	grp := newMockGroup()

	tests := []struct {
		name        string
		x           int64
		y           int64
		description string
	}{
		{
			name:        "round-trip small coordinates",
			x:           3,
			y:           5,
			description: "small coordinates should round-trip correctly",
		},
		{
			name:        "round-trip larger coordinates",
			x:           100,
			y:           200,
			description: "larger coordinates should round-trip correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newMockElement(tt.x, tt.y, grp.order)
			bytes, err := grp.SerializeElement(original)
			assert.NoError(t, err)

			restored, err := grp.DeserializeElement(bytes)
			assert.NoError(t, err)
			assert.True(t, original.Equal(restored))
		})
	}
}
