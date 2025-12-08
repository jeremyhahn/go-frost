package keygen

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
)

// mockScalar implements group.Scalar for testing
type mockScalar struct {
	value *big.Int
	order *big.Int
}

func newMockScalar(value int64, order *big.Int) *mockScalar {
	v := big.NewInt(value)
	v.Mod(v, order)
	return &mockScalar{value: v, order: order}
}

func newMockScalarFromBig(value *big.Int, order *big.Int) *mockScalar {
	v := new(big.Int).Set(value)
	v.Mod(v, order)
	return &mockScalar{value: v, order: order}
}

func (s *mockScalar) Add(other group.Scalar) group.Scalar {
	o := other.(*mockScalar)
	result := new(big.Int).Add(s.value, o.value)
	result.Mod(result, s.order)
	return &mockScalar{value: result, order: s.order}
}

func (s *mockScalar) Sub(other group.Scalar) group.Scalar {
	o := other.(*mockScalar)
	result := new(big.Int).Sub(s.value, o.value)
	result.Mod(result, s.order)
	return &mockScalar{value: result, order: s.order}
}

func (s *mockScalar) Mul(other group.Scalar) group.Scalar {
	o := other.(*mockScalar)
	result := new(big.Int).Mul(s.value, o.value)
	result.Mod(result, s.order)
	return &mockScalar{value: result, order: s.order}
}

func (s *mockScalar) Inv() (group.Scalar, error) {
	if s.IsZero() {
		return nil, fmt.Errorf("cannot invert zero scalar")
	}
	result := new(big.Int).ModInverse(s.value, s.order)
	if result == nil {
		return nil, fmt.Errorf("inverse does not exist")
	}
	return &mockScalar{value: result, order: s.order}, nil
}

func (s *mockScalar) Negate() group.Scalar {
	result := new(big.Int).Neg(s.value)
	result.Mod(result, s.order)
	return &mockScalar{value: result, order: s.order}
}

func (s *mockScalar) IsZero() bool {
	return s.value.Sign() == 0
}

func (s *mockScalar) Equal(other group.Scalar) bool {
	o := other.(*mockScalar)
	return s.value.Cmp(o.value) == 0
}

func (s *mockScalar) Bytes() []byte {
	bytes := s.value.Bytes()
	// Pad to 32 bytes (big-endian from big.Int)
	padded := make([]byte, 32)
	if len(bytes) < 32 {
		copy(padded[32-len(bytes):], bytes)
	} else {
		copy(padded, bytes)
	}
	// Reverse to little-endian to match ristretto255
	for i := 0; i < 16; i++ {
		padded[i], padded[31-i] = padded[31-i], padded[i]
	}
	return padded
}

func (s *mockScalar) Copy() group.Scalar {
	return &mockScalar{
		value: new(big.Int).Set(s.value),
		order: s.order,
	}
}

func (s *mockScalar) Compare(other group.Scalar) int {
	o := other.(*mockScalar)
	return s.value.Cmp(o.value)
}

// mockElement implements group.Element for testing
type mockElement struct {
	x     *big.Int
	y     *big.Int
	order *big.Int
}

func newMockElement(x, y int64, order *big.Int) *mockElement {
	return &mockElement{
		x:     big.NewInt(x),
		y:     big.NewInt(y),
		order: order,
	}
}

func (e *mockElement) Add(other group.Element) group.Element {
	o := other.(*mockElement)
	return &mockElement{
		x:     new(big.Int).Add(e.x, o.x),
		y:     new(big.Int).Add(e.y, o.y),
		order: e.order,
	}
}

func (e *mockElement) Negate() group.Element {
	return &mockElement{
		x:     new(big.Int).Neg(e.x),
		y:     new(big.Int).Neg(e.y),
		order: e.order,
	}
}

func (e *mockElement) IsIdentity() bool {
	return e.x.Sign() == 0 && e.y.Sign() == 0
}

func (e *mockElement) Equal(other group.Element) bool {
	o := other.(*mockElement)
	return e.x.Cmp(o.x) == 0 && e.y.Cmp(o.y) == 0
}

func (e *mockElement) Bytes() []byte {
	xBytes := e.x.Bytes()
	yBytes := e.y.Bytes()
	result := make([]byte, 64)
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result
}

func (e *mockElement) Copy() group.Element {
	return &mockElement{
		x:     new(big.Int).Set(e.x),
		y:     new(big.Int).Set(e.y),
		order: e.order,
	}
}

// mockGroup implements group.Group for testing
type mockGroup struct {
	order     *big.Int
	generator *mockElement
}

func newMockGroup() *mockGroup {
	// Use a small prime for testing
	order := big.NewInt(97) // Small prime
	return &mockGroup{
		order:     order,
		generator: newMockElement(3, 5, order),
	}
}

func (g *mockGroup) Order() []byte {
	return g.order.Bytes()
}

func (g *mockGroup) Cofactor() group.Scalar {
	return newMockScalar(1, g.order)
}

func (g *mockGroup) Identity() group.Element {
	return newMockElement(0, 0, g.order)
}

func (g *mockGroup) Generator() group.Element {
	return g.generator.Copy()
}

func (g *mockGroup) NewScalar() group.Scalar {
	return newMockScalar(0, g.order)
}

func (g *mockGroup) NewElement() group.Element {
	return g.Identity()
}

func (g *mockGroup) RandomScalar() (group.Scalar, error) {
	max := new(big.Int).Sub(g.order, big.NewInt(1))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	n.Add(n, big.NewInt(1)) // Ensure non-zero
	return newMockScalarFromBig(n, g.order), nil
}

func (g *mockGroup) ScalarMult(element group.Element, scalar group.Scalar) group.Element {
	s := scalar.(*mockScalar)

	// Implement scalar multiplication as repeated addition
	// This is a simplified implementation for testing
	result := g.Identity()
	temp := element.Copy()

	// Get the scalar value
	scalarVal := new(big.Int).Set(s.value)

	for scalarVal.Sign() > 0 {
		if new(big.Int).And(scalarVal, big.NewInt(1)).Sign() > 0 {
			result = result.Add(temp)
		}
		temp = temp.Add(temp)
		scalarVal.Rsh(scalarVal, 1)
	}

	return result
}

func (g *mockGroup) ScalarBaseMult(scalar group.Scalar) group.Element {
	return g.ScalarMult(g.generator, scalar)
}

func (g *mockGroup) SerializeElement(element group.Element) ([]byte, error) {
	if element.IsIdentity() {
		return nil, fmt.Errorf("cannot serialize identity element")
	}
	return element.Bytes(), nil
}

func (g *mockGroup) DeserializeElement(data []byte) (group.Element, error) {
	if len(data) != 64 {
		return nil, fmt.Errorf("invalid element encoding length")
	}
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:])
	elem := &mockElement{x: x, y: y, order: g.order}
	if elem.IsIdentity() {
		return nil, fmt.Errorf("deserialized identity element")
	}
	return elem, nil
}

func (g *mockGroup) SerializeScalar(scalar group.Scalar) []byte {
	return scalar.Bytes()
}

func (g *mockGroup) DeserializeScalar(data []byte) (group.Scalar, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid scalar encoding length")
	}
	// Interpret bytes as little-endian to match ristretto255
	reversed := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		reversed[i] = data[len(data)-1-i]
	}
	value := new(big.Int).SetBytes(reversed)
	// Reduce modulo order instead of rejecting (mocks use small orders for testing)
	value.Mod(value, g.order)
	return newMockScalarFromBig(value, g.order), nil
}

func (g *mockGroup) ElementLength() int {
	return 64
}

func (g *mockGroup) ScalarLength() int {
	return 32
}

func (g *mockGroup) Name() string {
	return "mock-group"
}

func (g *mockGroup) ByteOrder() group.ByteOrder {
	return group.LittleEndian
}

// Helper function to create participant identifiers
func createParticipantIDs(count int) []frost.Identifier {
	ids := make([]frost.Identifier, count)
	for i := 0; i < count; i++ {
		ids[i] = frost.Identifier(i + 1)
	}
	return ids
}
