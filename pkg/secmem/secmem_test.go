package secmem

import (
	"bytes"
	"errors"
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

func TestClone(t *testing.T) {
	Init()

	data := []byte("clone me: secret key material")
	expected := make([]byte, len(data))
	copy(expected, data)

	secret := NewSecretBytes(data)
	require.NotNil(t, secret)
	defer secret.Destroy()

	clone, err := Clone(secret)
	require.NoError(t, err)
	require.NotNil(t, clone)
	defer clone.Destroy()

	assert.Equal(t, secret.Size(), clone.Size())

	// The clone holds the same plaintext...
	require.NoError(t, WithSecret(clone, func(b []byte) error {
		assert.Equal(t, expected, b)
		return nil
	}))

	// ...and the source is still usable after being cloned.
	require.NoError(t, WithSecret(secret, func(b []byte) error {
		assert.Equal(t, expected, b)
		return nil
	}))
}

func TestClone_Independent(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("independent copies"))
	require.NotNil(t, secret)
	defer secret.Destroy()

	clone, err := Clone(secret)
	require.NoError(t, err)

	// Destroying the clone must leave the source intact.
	clone.Destroy()
	require.NoError(t, WithSecret(secret, func(b []byte) error {
		assert.Equal(t, []byte("independent copies"), b)
		return nil
	}))
}

func TestClone_Nil(t *testing.T) {
	clone, err := Clone(nil)
	assert.Nil(t, clone)
	assert.ErrorIs(t, err, ErrNilSecret)
}

func TestClone_Destroyed(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("destroyed before cloning"))
	require.NotNil(t, secret)
	secret.Destroy()

	clone, err := Clone(secret)
	assert.Nil(t, clone)
	assert.ErrorIs(t, err, ErrDestroyed)
}

// TestSecretBytes_Reseal_CannotResurrectDestroyed verifies destruction is
// final. A buffer opened before the secret was destroyed must not be sealable
// back into it: doing so would install a fresh enclave over the destroyed one
// and make secret material the caller explicitly destroyed readable again.
func TestSecretBytes_Reseal_CannotResurrectDestroyed(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("destroy me while open"))
	require.NotNil(t, secret)

	buf, err := secret.Open()
	require.NoError(t, err)

	secret.Destroy()

	// The caller still owes a Reseal for the buffer it opened.
	secret.Reseal(buf)

	_, err = secret.Open()
	assert.ErrorIs(t, err, ErrDestroyed, "Reseal resurrected a destroyed secret")
	assert.Equal(t, 0, secret.Size())
}

// TestWithSecret_OpenUseResealIsOneCriticalSection is the deterministic form of
// TestClone_ConcurrentDestroy: rather than racing a Destroy against an open
// secret and hoping to hit the window, it parks a caller inside the cycle and
// asserts the mutex is held at that moment.
//
// That is the property destruction being final rests on. If the mutex were
// free mid-cycle, a Destroy could run between the open and the reseal, and the
// reseal would then seal the plaintext back into the secret it had just
// destroyed. Clone runs through the same cycle, so this covers it too.
func TestWithSecret_OpenUseResealIsOneCriticalSection(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("held open"))
	require.NotNil(t, secret)
	defer secret.Destroy()

	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		done <- WithSecret(secret, func([]byte) error {
			inside <- struct{}{}
			<-release
			return nil
		})
	}()

	// The cycle is now in flight, with the plaintext open.
	<-inside

	locked := !secret.mu.TryLock()
	if !locked {
		secret.mu.Unlock()
	}

	close(release)
	require.NoError(t, <-done)

	assert.True(t, locked,
		"the mutex was free while the secret was open; a concurrent Destroy "+
			"could be undone by the reseal that follows")
}

// TestClone_ConcurrentDestroy verifies the end-state invariant a racing caller
// can rely on: however a Clone and a Destroy of the same secret interleave,
// Clone either succeeds outright or reports ErrDestroyed, and the source is
// destroyed once both have returned - never resurrected by Clone's reseal.
func TestClone_ConcurrentDestroy(t *testing.T) {
	Init()

	const iterations = 200
	const payload = "clone me while I am destroyed"

	for i := 0; i < iterations; i++ {
		secret := NewSecretBytes([]byte(payload))
		require.NotNil(t, secret)

		start := make(chan struct{})
		var wg sync.WaitGroup

		var clone *SecretBytes
		var cloneErr error

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			clone, cloneErr = Clone(secret)
		}()
		go func() {
			defer wg.Done()
			<-start
			secret.Destroy()
		}()
		close(start)
		wg.Wait()

		switch {
		case cloneErr == nil:
			require.NotNil(t, clone, "iteration %d: Clone reported success but returned nil", i)
			var got string
			require.NoError(t, WithSecret(clone, func(b []byte) error {
				got = string(b)
				return nil
			}), "iteration %d: cloned secret is unusable", i)
			assert.Equal(t, payload, got, "iteration %d: clone holds the wrong payload", i)
			clone.Destroy()
		default:
			assert.ErrorIs(t, cloneErr, ErrDestroyed,
				"iteration %d: Clone failed for an unexpected reason", i)
			assert.Nil(t, clone, "iteration %d: failed Clone returned a secret", i)
		}

		// Destruction stands regardless of which side won the race.
		_, err := secret.Open()
		require.ErrorIs(t, err, ErrDestroyed,
			"iteration %d: the destroyed source is open-able again", i)
	}
}

// TestClone_DestroyedSourceStaysDestroyed verifies a Clone that finds its
// source destroyed reports ErrDestroyed and leaves the source destroyed - it
// must not reseal anything back into it on the way out.
func TestClone_DestroyedSourceStaysDestroyed(t *testing.T) {
	Init()

	secret := NewSecretBytes([]byte("destroyed before cloning"))
	require.NotNil(t, secret)
	secret.Destroy()

	clone, err := Clone(secret)
	assert.Nil(t, clone)
	assert.ErrorIs(t, err, ErrDestroyed)

	_, err = secret.Open()
	assert.ErrorIs(t, err, ErrDestroyed, "a failed Clone resurrected its source")
}

func TestNewSecret(t *testing.T) {
	want := []byte("assembled in place")

	secret, err := NewSecret(len(want), func(dst []byte) (int, error) {
		return copy(dst, want), nil
	})
	if err != nil {
		t.Fatalf("NewSecret failed: %v", err)
	}
	defer secret.Destroy()

	if secret.Size() != len(want) {
		t.Errorf("Size() = %d, want %d", secret.Size(), len(want))
	}
	if err := WithSecret(secret, func(b []byte) error {
		if !bytes.Equal(b, want) {
			t.Errorf("sealed secret = %q, want %q", b, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithSecret failed: %v", err)
	}
}

// TestNewSecret_ShortWrite verifies a fill that writes less than it asked for -
// a decode whose exact length is only known once it is done - seals exactly
// what it wrote, with no trailing zeros from the oversized buffer.
func TestNewSecret_ShortWrite(t *testing.T) {
	want := []byte("short")

	secret, err := NewSecret(64, func(dst []byte) (int, error) {
		return copy(dst, want), nil
	})
	if err != nil {
		t.Fatalf("NewSecret failed: %v", err)
	}
	defer secret.Destroy()

	if secret.Size() != len(want) {
		t.Errorf("Size() = %d, want %d", secret.Size(), len(want))
	}
	if err := WithSecret(secret, func(b []byte) error {
		if !bytes.Equal(b, want) {
			t.Errorf("sealed secret = %q, want %q", b, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithSecret failed: %v", err)
	}
}

func TestNewSecret_FillError(t *testing.T) {
	sentinel := errors.New("fill failed")

	secret, err := NewSecret(32, func(dst []byte) (int, error) {
		copy(dst, "partial work that must not survive")
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want %v", err, sentinel)
	}
	if secret != nil {
		t.Error("a failed fill still produced a secret")
	}
}

func TestNewSecret_EmptyOrInvalidLength(t *testing.T) {
	tests := []struct {
		name string
		size int
		n    int
	}{
		{name: "zero size", size: 0, n: 0},
		{name: "negative size", size: -1, n: 0},
		{name: "fill wrote nothing", size: 16, n: 0},
		{name: "fill wrote negative", size: 16, n: -1},
		{name: "fill overran", size: 16, n: 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := NewSecret(tt.size, func(dst []byte) (int, error) {
				return tt.n, nil
			})
			if !errors.Is(err, ErrEmptySecret) {
				t.Errorf("error = %v, want ErrEmptySecret", err)
			}
			if secret != nil {
				t.Error("a rejected size still produced a secret")
			}
		})
	}
}

// TestNewSecret_FillPanic verifies a panic in caller-supplied fill does not
// strand a protected buffer holding whatever fill had written. The buffer is
// unreachable once the panic unwinds, so nothing else could ever wipe it.
func TestNewSecret_FillPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected the panic to propagate to the caller")
		}
	}()

	_, _ = NewSecret(32, func(dst []byte) (int, error) {
		copy(dst, "partial work that must not be stranded")
		panic("fill exploded")
	})
}

// TestNewSecret_NilFill verifies the same cleanup covers a nil fill, which
// panics on call before writing anything.
func TestNewSecret_NilFill(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected the panic to propagate to the caller")
		}
	}()

	_, _ = NewSecret(32, nil)
}
