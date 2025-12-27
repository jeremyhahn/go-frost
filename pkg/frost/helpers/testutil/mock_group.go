package testutil

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// Group name constants for mock groups
const (
	groupNameP256      = "p256"
	groupNameSecp256k1 = "secp256k1"
)

// MockGroup is a simple mock implementation of group.Group for testing
// It uses a small prime field for simplicity
type MockGroup struct {
	order *big.Int
	name  string
}

// NewMockGroup creates a new mock group with a small prime order (for testing)
func NewMockGroup() *MockGroup {
	// Use a small prime for testing: 2^255 - 19 (Ed25519 order, simplified)
	order := new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return &MockGroup{order: order, name: "MockGroup"}
}

// NewMockGroupWithName creates a new mock group with a specific name for testing
// endianness behavior. Supported names that trigger big-endian encoding:
// - "p256" or "secp256k1" -> big-endian
// - Any other name -> little-endian (default, like ed25519/ristretto255)
func NewMockGroupWithName(name string) *MockGroup {
	order := new(big.Int)
	order.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return &MockGroup{order: order, name: name}
}

func (m *MockGroup) Order() []byte {
	return m.order.Bytes()
}

// Cofactor returns the cofactor of the mock group (always 1 for testing).
func (m *MockGroup) Cofactor() group.Scalar {
	return &MockScalar{value: big.NewInt(1), order: m.order, groupName: m.name}
}

func (m *MockGroup) Identity() group.Element {
	return &MockElement{value: big.NewInt(0), group: m}
}

func (m *MockGroup) Generator() group.Element {
	return &MockElement{value: big.NewInt(1), group: m}
}

func (m *MockGroup) NewScalar() group.Scalar {
	return &MockScalar{value: big.NewInt(0), order: m.order, groupName: m.name}
}

func (m *MockGroup) NewElement() group.Element {
	return &MockElement{value: big.NewInt(0), group: m}
}

func (m *MockGroup) RandomScalar() (group.Scalar, error) {
	maxVal := new(big.Int).Set(m.order)
	val, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		return nil, err
	}
	return &MockScalar{value: val, order: m.order, groupName: m.name}, nil
}

func (m *MockGroup) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	elem := element.(*MockElement)
	scal := scalar.(*MockScalar)

	result := new(big.Int).Mul(elem.value, scal.value)
	result.Mod(result, m.order)

	return &MockElement{value: result, group: m}
}

func (m *MockGroup) ScalarBaseMult(scalar group.Scalar) group.Element {
	return m.ScalarMult(m.Generator(), scalar)
}

func (m *MockGroup) SerializeElement(element group.Element) ([]byte, error) {
	elem := element.(*MockElement)
	if elem.IsIdentity() {
		return nil, errors.New("cannot serialize identity element")
	}
	return elem.Bytes(), nil
}

func (m *MockGroup) DeserializeElement(data []byte) (group.Element, error) {
	value := new(big.Int).SetBytes(data)
	if value.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("cannot deserialize identity element")
	}
	return &MockElement{value: value, group: m}, nil
}

func (m *MockGroup) SerializeScalar(scalar group.Scalar) []byte {
	return scalar.Bytes()
}

func (m *MockGroup) DeserializeScalar(data []byte) (group.Scalar, error) {
	var value *big.Int

	// Use big-endian for p256/secp256k1, little-endian for others
	if m.name == groupNameP256 || m.name == groupNameSecp256k1 {
		// Big-endian: bytes are already in the correct order for big.Int
		value = new(big.Int).SetBytes(data)
	} else {
		// Little-endian: reverse bytes for big.Int
		reversed := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			reversed[i] = data[len(data)-1-i]
		}
		value = new(big.Int).SetBytes(reversed)
	}

	// Reduce modulo order instead of rejecting (mocks use small orders for testing)
	value.Mod(value, m.order)
	return &MockScalar{value: value, order: m.order, groupName: m.name}, nil
}

func (m *MockGroup) ElementLength() int {
	return 32
}

func (m *MockGroup) ScalarLength() int {
	return 32
}

func (m *MockGroup) Name() string {
	return m.name
}

func (m *MockGroup) ByteOrder() group.ByteOrder {
	if m.name == groupNameP256 || m.name == groupNameSecp256k1 {
		return group.BigEndian
	}
	return group.LittleEndian
}

// MockElement implements group.Element
type MockElement struct {
	value *big.Int
	group *MockGroup
}

func (e *MockElement) Add(other group.Element) group.Element {
	o := other.(*MockElement)
	result := new(big.Int).Add(e.value, o.value)
	result.Mod(result, e.group.order)
	return &MockElement{value: result, group: e.group}
}

func (e *MockElement) Negate() group.Element {
	result := new(big.Int).Neg(e.value)
	result.Mod(result, e.group.order)
	return &MockElement{value: result, group: e.group}
}

func (e *MockElement) IsIdentity() bool {
	return e.value.Cmp(big.NewInt(0)) == 0
}

func (e *MockElement) Equal(other group.Element) bool {
	o := other.(*MockElement)
	return e.value.Cmp(o.value) == 0
}

func (e *MockElement) Bytes() []byte {
	bytes := e.value.Bytes()
	// Pad to 32 bytes
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		return padded
	}
	return bytes
}

func (e *MockElement) Copy() group.Element {
	return &MockElement{value: new(big.Int).Set(e.value), group: e.group}
}

// MockScalar implements group.Scalar
type MockScalar struct {
	value     *big.Int
	order     *big.Int
	groupName string
}

func (s *MockScalar) Add(other group.Scalar) group.Scalar {
	o := other.(*MockScalar)
	result := new(big.Int).Add(s.value, o.value)
	result.Mod(result, s.order)
	return &MockScalar{value: result, order: s.order, groupName: s.groupName}
}

func (s *MockScalar) Sub(other group.Scalar) group.Scalar {
	o := other.(*MockScalar)
	result := new(big.Int).Sub(s.value, o.value)
	result.Mod(result, s.order)
	return &MockScalar{value: result, order: s.order, groupName: s.groupName}
}

func (s *MockScalar) Mul(other group.Scalar) group.Scalar {
	o := other.(*MockScalar)
	result := new(big.Int).Mul(s.value, o.value)
	result.Mod(result, s.order)
	return &MockScalar{value: result, order: s.order, groupName: s.groupName}
}

func (s *MockScalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	result := new(big.Int).ModInverse(s.value, s.order)
	if result == nil {
		return nil, errors.New("inverse does not exist")
	}
	return &MockScalar{value: result, order: s.order, groupName: s.groupName}, nil
}

func (s *MockScalar) Negate() group.Scalar {
	result := new(big.Int).Neg(s.value)
	result.Mod(result, s.order)
	return &MockScalar{value: result, order: s.order, groupName: s.groupName}
}

func (s *MockScalar) IsZero() bool {
	return s.value.Cmp(big.NewInt(0)) == 0
}

func (s *MockScalar) Equal(other group.Scalar) bool {
	o := other.(*MockScalar)
	return s.value.Cmp(o.value) == 0
}

func (s *MockScalar) Bytes() []byte {
	bytes := s.value.Bytes()
	// Pad to 32 bytes (big-endian from big.Int)
	padded := make([]byte, 32)
	if len(bytes) < 32 {
		copy(padded[32-len(bytes):], bytes)
	} else {
		copy(padded, bytes)
	}

	// Use big-endian for p256/secp256k1, little-endian for others
	if s.groupName == groupNameP256 || s.groupName == groupNameSecp256k1 {
		// Big-endian: already in correct format from big.Int
		return padded
	}

	// Little-endian: reverse bytes to match ed25519/ristretto255
	for i := 0; i < 16; i++ {
		padded[i], padded[31-i] = padded[31-i], padded[i]
	}
	return padded
}

func (s *MockScalar) Copy() group.Scalar {
	return &MockScalar{value: new(big.Int).Set(s.value), order: new(big.Int).Set(s.order), groupName: s.groupName}
}

func (s *MockScalar) Compare(other group.Scalar) int {
	o := other.(*MockScalar)
	return s.value.Cmp(o.value)
}

// SetBytes sets the scalar value from bytes (little-endian)
func (s *MockScalar) SetBytes(data []byte) {
	// Reverse from little-endian to big-endian for big.Int
	reversed := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		reversed[i] = data[len(data)-1-i]
	}
	s.value.SetBytes(reversed)
	s.value.Mod(s.value, s.order)
}
