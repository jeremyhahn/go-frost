package secmem

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	// Init should be idempotent
	Init()
	Init()
}

func TestNewSecretBytes_NilOrEmpty(t *testing.T) {
	assert.Nil(t, NewSecretBytes(nil))
	assert.Nil(t, NewSecretBytes([]byte{}))
}

func TestNewSecretBytes_ZerosOriginal(t *testing.T) {
	Init()

	original := []byte{0x01, 0x02, 0x03, 0x04}
	secret := NewSecretBytes(original)
	require.NotNil(t, secret)

	// Original data should be zeroed
	for _, b := range original {
		assert.Equal(t, byte(0), b)
	}

	secret.Destroy()
}

func TestSecretBytes_RoundTrip(t *testing.T) {
	Init()

	data := []byte("super secret key material")
	expected := make([]byte, len(data))
	copy(expected, data)

	secret := NewSecretBytes(data)
	require.NotNil(t, secret)
	assert.Equal(t, len(expected), secret.Size())

	// Open and verify contents
	buf, err := secret.Open()
	require.NoError(t, err)
	assert.Equal(t, expected, buf.Bytes())

	secret.Reseal(buf)

	// Open again to verify reseal worked
	buf2, err := secret.Open()
	require.NoError(t, err)
	assert.Equal(t, expected, buf2.Bytes())

	secret.Reseal(buf2)
	secret.Destroy()
}

func TestSecretBytes_Destroy(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("destroy me"))
	require.NotNil(t, secret)

	secret.Destroy()

	assert.Equal(t, 0, secret.Size())

	// Open after destroy should fail
	_, err := secret.Open()
	assert.ErrorIs(t, err, ErrDestroyed)

	// Double destroy should not panic
	secret.Destroy()
}

func TestSecretBytes_NilOperations(t *testing.T) {
	var s *SecretBytes

	_, err := s.Open()
	assert.ErrorIs(t, err, ErrNilSecret)

	assert.Equal(t, 0, s.Size())

	// Should not panic
	s.Destroy()
	s.Reseal(nil)
}

func TestWithSecret(t *testing.T) {
	Init()

	data := []byte("with secret test data")
	expected := make([]byte, len(data))
	copy(expected, data)

	secret := NewSecretBytes(data)
	require.NotNil(t, secret)

	var retrieved []byte
	err := WithSecret(secret, func(b []byte) error {
		retrieved = make([]byte, len(b))
		copy(retrieved, b)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, expected, retrieved)

	secret.Destroy()
}

func TestWithSecret_Nil(t *testing.T) {
	err := WithSecret(nil, func(b []byte) error {
		return nil
	})
	assert.ErrorIs(t, err, ErrNilSecret)
}

func TestWithSecret_ErrorPropagation(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("error test"))
	require.NotNil(t, secret)

	expectedErr := assert.AnError
	err := WithSecret(secret, func(b []byte) error {
		return expectedErr
	})
	assert.ErrorIs(t, err, expectedErr)

	// Secret should still be usable after error
	err = WithSecret(secret, func(b []byte) error {
		assert.Equal(t, []byte("error test"), b)
		return nil
	})
	assert.NoError(t, err)

	secret.Destroy()
}

func TestWithSecret_Destroyed(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("destroyed test"))
	require.NotNil(t, secret)

	secret.Destroy()

	err := WithSecret(secret, func(b []byte) error {
		t.Fatal("should not be called")
		return nil
	})
	assert.ErrorIs(t, err, ErrDestroyed)
}

func TestZeroBytes(t *testing.T) {
	b := []byte{0xff, 0xfe, 0xfd, 0xfc}
	ZeroBytes(b)
	for _, v := range b {
		assert.Equal(t, byte(0), v)
	}

	// Empty and nil should not panic
	ZeroBytes([]byte{})
	ZeroBytes(nil)
}

func TestZeroString(t *testing.T) {
	// Create a string with known content
	s := string([]byte{0x41, 0x42, 0x43, 0x44}) // "ABCD"
	assert.Equal(t, "ABCD", s)

	ZeroString(&s)

	// The backing bytes should now be zeroed
	assert.Equal(t, "\x00\x00\x00\x00", s)
	assert.Equal(t, 4, len(s))
}

func TestZeroString_Empty(t *testing.T) {
	s := ""
	ZeroString(&s)
	assert.Equal(t, "", s)
}

func TestZeroString_Nil(t *testing.T) {
	// Should not panic
	ZeroString(nil)
}

func TestSecretBytes_ConcurrentAccess(t *testing.T) {
	Init()

	data := []byte("concurrent access test data")
	expected := make([]byte, len(data))
	copy(expected, data)

	secret := NewSecretBytes(data)
	require.NotNil(t, secret)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithSecret(secret, func(b []byte) error {
				assert.Equal(t, expected, b)
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
	secret.Destroy()
}
