// Package secmem protects raw []byte key material with memguard (mlock, enclaves, guard pages); group.Scalar values cannot be protected.
package secmem

import (
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/awnumar/memguard"
)

var (
	initOnce sync.Once

	// ErrDestroyed is returned when accessing a SecretBytes that has been destroyed.
	ErrDestroyed = errors.New("secmem: secret has been destroyed")

	// ErrNilSecret is returned when a nil SecretBytes is passed to an operation.
	ErrNilSecret = errors.New("secmem: secret is nil")

	// ErrEmptySecret is returned when a secret would hold no bytes. Protected
	// memory cannot hold a zero-length secret, so an empty one is an error
	// rather than a usable value.
	ErrEmptySecret = errors.New("secmem: secret is empty")
)

// Init installs a handler that purges secure memory on termination signals; idempotent.
func Init() {
	initOnce.Do(func() {
		memguard.CatchInterrupt()
	})
}

// Purge destroys all secure memory allocations and safely terminates the
// memguard core. This should be called during application shutdown,
// typically via defer.
func Purge() {
	memguard.Purge()
}

// SecretBytes holds sensitive byte data encrypted at rest using memguard's
// Enclave (XSalsa20-Poly1305). Data is only decrypted into mlock'd memory
// when explicitly opened.
type SecretBytes struct {
	mu      sync.Mutex
	enclave *memguard.Enclave
	size    int
}

// NewSecretBytes seals a copy of data into an Enclave and zeroes data; nil for empty input.
func NewSecretBytes(data []byte) *SecretBytes {
	if len(data) == 0 {
		return nil
	}

	size := len(data)

	// Create a LockedBuffer from the data (copies into mlock'd memory)
	buf := memguard.NewBufferFromBytes(data)

	// Zero the original data
	ZeroBytes(data)

	// Seal into an Enclave (encrypts at rest)
	enclave := buf.Seal()

	return &SecretBytes{
		enclave: enclave,
		size:    size,
	}
}

// NewSecret seals what fill writes into a protected size-byte buffer, so assembled secrets never touch the heap; ErrEmptySecret for a bad size or length.
func NewSecret(size int, fill func(dst []byte) (int, error)) (*SecretBytes, error) {
	if size <= 0 {
		return nil, ErrEmptySecret
	}

	buf := memguard.NewBuffer(size)

	// Destroy the buffer even if fill panics; Destroy is idempotent.
	defer func() { buf.Destroy() }()

	n, err := fill(buf.Bytes())
	if err != nil {
		buf.Destroy()
		return nil, err
	}
	if n <= 0 || n > size {
		buf.Destroy()
		return nil, ErrEmptySecret
	}

	if n < size {
		// Copy protected buffer to protected buffer: the plaintext is never
		// anywhere but mlock'd memory, and the oversized original is destroyed.
		exact := memguard.NewBuffer(n)
		exact.Copy(buf.Bytes()[:n])
		buf.Destroy()
		buf = exact
	}

	// Seal destroys buf.
	return &SecretBytes{
		enclave: buf.Seal(),
		size:    n,
	}, nil
}

// Open decrypts into a protected LockedBuffer the caller must Reseal; prefer WithSecret, which is atomic with Destroy.
func (s *SecretBytes) Open() (*memguard.LockedBuffer, error) {
	if s == nil {
		return nil, ErrNilSecret
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.enclave == nil {
		return nil, ErrDestroyed
	}

	buf, err := s.enclave.Open()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Reseal re-encrypts and destroys the buffer; if the secret was destroyed meanwhile, the plaintext is discarded.
func (s *SecretBytes) Reseal(buf *memguard.LockedBuffer) {
	if s == nil || buf == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.enclave == nil {
		buf.Destroy()
		return
	}

	s.enclave = buf.Seal()
}

// Destroy permanently destroys the secret data. After calling Destroy,
// all subsequent calls to Open will return ErrDestroyed.
func (s *SecretBytes) Destroy() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.enclave != nil {
		// Open and destroy the buffer to ensure cleanup
		buf, err := s.enclave.Open()
		if err == nil {
			buf.Destroy()
		}
		s.enclave = nil
	}
	s.size = 0
}

// Size returns the size in bytes of the secret data, or 0 once it has been
// destroyed. Read under the mutex, since Destroy writes it.
func (s *SecretBytes) Size() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.size
}

// withOpen runs fn on the plaintext holding s.mu for the whole cycle, atomic with Destroy; fn must not call s or retain the slice.
func (s *SecretBytes) withOpen(fn func([]byte) error) error {
	if s == nil {
		return ErrNilSecret
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.enclave == nil {
		return ErrDestroyed
	}

	buf, err := s.enclave.Open()
	if err != nil {
		return err
	}

	// Reseal in the same critical section. Seal destroys buf, so the plaintext
	// does not outlive the cycle on either path out of fn.
	defer func() { s.enclave = buf.Seal() }()

	return fn(buf.Bytes())
}

// WithSecret runs fn on the plaintext and reseals it, atomically with Destroy; fn must not retain the slice or call secret.
func WithSecret(secret *SecretBytes, fn func([]byte) error) error {
	return secret.withOpen(fn)
}

// ZeroBytes overwrites a byte slice with zeros using constant-time
// comparison to prevent compiler optimizations from eliding the write.
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use subtle.ConstantTimeCopy to zero: copy zeros over b
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// Clone returns an independent protected copy the caller destroys; ErrNilSecret or ErrDestroyed on bad input.
func Clone(s *SecretBytes) (*SecretBytes, error) {
	var clone *SecretBytes

	if err := s.withOpen(func(b []byte) error {
		dup := memguard.NewBuffer(len(b))
		dup.Copy(b)
		clone = &SecretBytes{
			enclave: dup.Seal(),
			size:    len(b),
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return clone, nil
}
