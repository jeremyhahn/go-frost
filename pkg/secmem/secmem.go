// Package secmem provides secure memory management for cryptographic key material.
//
// It wraps the memguard library to provide mlock'd memory (protected from swap),
// encrypted at-rest storage via Enclave, and guard pages for sensitive byte slices.
//
// Key constraint: group.Scalar values used for arithmetic cannot be wrapped in
// memguard since they are managed by external crypto libraries. This package
// focuses on protecting raw []byte key material.
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

// Init initializes the secure memory subsystem.
// It installs an interrupt handler that will purge all secure memory on
// termination signals. This function is idempotent and safe to call
// multiple times.
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

// NewSecretBytes creates a new SecretBytes from the given data.
// The data is copied into a mlock'd LockedBuffer, then sealed into an
// Enclave. The original data slice is zeroed before returning.
//
// Returns nil if data is nil or empty.
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

// NewSecret builds a secret in place inside protected memory. It allocates a
// mlock'd, guard-paged buffer of size bytes, passes it to fill, and seals the
// prefix fill reports having written.
//
// Use it wherever secret material has to be assembled or decoded rather than
// simply copied: the working buffer is protected from the moment it is
// allocated, so the material never exists as an ordinary heap allocation that
// the runtime may swap out and that this package cannot reach to zeroize.
// NewSecretBytes, by contrast, can only seal what is already on the heap.
//
// fill returns the number of bytes it wrote. Writing fewer than size bytes is
// allowed - the exact length of a decoded secret is not always known up front -
// and the shorter secret is re-sealed through a second protected buffer, so a
// short write does not put the material on the heap either. Every buffer
// involved is destroyed before NewSecret returns.
//
// fill must write only into dst and must not retain it. If fill returns an
// error the buffer is destroyed and that error is returned unwrapped;
// ErrEmptySecret is returned when size is not positive or fill reports a
// length outside (0, size].
func NewSecret(size int, fill func(dst []byte) (int, error)) (*SecretBytes, error) {
	if size <= 0 {
		return nil, ErrEmptySecret
	}

	buf := memguard.NewBuffer(size)

	// fill is caller-supplied, so it can panic. Without this the buffer would
	// be left mlock'd holding whatever fill had written into it before the
	// panic, with nothing left alive to wipe it. Destroy is idempotent and
	// reads buf at the time it runs, so it covers the reassignment below and
	// costs nothing on the path where Seal has already destroyed the buffer.
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

// Open decrypts the SecretBytes into a mlock'd LockedBuffer for use.
// The caller MUST call Reseal() when done to re-encrypt the data,
// or use WithSecret() for automatic open/reseal lifecycle management.
//
// The returned LockedBuffer is protected by mlock (won't be swapped to disk)
// and surrounded by guard pages.
//
// Open and Reseal are two separate critical sections, so a Destroy can land
// between them: the plaintext in the returned buffer stays readable until the
// caller reseals it, and Reseal then discards it rather than sealing it back.
// Prefer WithSecret, whose open/use/reseal cycle is atomic with respect to
// Destroy.
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

// Reseal re-encrypts a LockedBuffer back into the Enclave after use.
// The LockedBuffer is destroyed (zeroed and munlock'd) in the process.
//
// Destruction is final: if the secret was destroyed while this buffer was
// open, the plaintext is discarded instead of being sealed back, because
// installing a fresh enclave over the destroyed one would resurrect secret
// material the caller explicitly destroyed.
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

// withOpen runs fn against the plaintext of the secret, holding s.mu for the
// entire open/use/reseal cycle.
//
// Holding the mutex across the whole cycle is what makes the cycle atomic with
// respect to Destroy: a concurrent Destroy lands either entirely before it (fn
// is never called and ErrDestroyed is returned) or entirely after it. Were the
// reseal able to interleave with a Destroy, it would install a fresh enclave
// over the nil one Destroy left behind, resurrecting secret material the
// caller had explicitly destroyed.
//
// fn must not call any method on s - s.mu is not reentrant - and must not
// retain the byte slice it is given.
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

// WithSecret opens a SecretBytes, passes the raw bytes to the provided
// function, and re-seals the data when the function returns.
// This is the recommended way to access secret data as it ensures
// the data is always re-encrypted after use.
//
// The open/use/reseal cycle is atomic with respect to Destroy: a concurrent
// Destroy either prevents fn from running at all (ErrDestroyed) or takes
// effect once the cycle has finished, and can never be undone by the reseal.
//
// The byte slice passed to fn must not be retained after fn returns, and fn
// must not call any method on secret.
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

// Clone returns an independent copy of a SecretBytes. The plaintext is copied
// between mlock'd buffers and never exists as a plain heap []byte: the source
// enclave is opened, its contents are copied into a fresh LockedBuffer, and
// that buffer is sealed into the returned enclave.
//
// The caller owns the returned SecretBytes and is responsible for destroying
// it; destroying it does not affect the source.
//
// The copy is made inside a single open/use/reseal cycle, so cloning a secret
// cannot be interleaved with destroying it.
//
// Returns ErrNilSecret if s is nil, or ErrDestroyed if s has been destroyed.
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
