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
	"unsafe"

	"github.com/awnumar/memguard"
)

var (
	initOnce sync.Once

	// ErrDestroyed is returned when accessing a SecretBytes that has been destroyed.
	ErrDestroyed = errors.New("secmem: secret has been destroyed")

	// ErrNilSecret is returned when a nil SecretBytes is passed to an operation.
	ErrNilSecret = errors.New("secmem: secret is nil")
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

// Open decrypts the SecretBytes into a mlock'd LockedBuffer for use.
// The caller MUST call Reseal() when done to re-encrypt the data,
// or use WithSecret() for automatic open/reseal lifecycle management.
//
// The returned LockedBuffer is protected by mlock (won't be swapped to disk)
// and surrounded by guard pages.
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
func (s *SecretBytes) Reseal(buf *memguard.LockedBuffer) {
	if s == nil || buf == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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

// Size returns the size in bytes of the secret data.
func (s *SecretBytes) Size() int {
	if s == nil {
		return 0
	}
	return s.size
}

// WithSecret opens a SecretBytes, passes the raw bytes to the provided
// function, and re-seals the data when the function returns.
// This is the recommended way to access secret data as it ensures
// the data is always re-encrypted after use.
//
// The byte slice passed to fn must not be retained after fn returns.
func WithSecret(secret *SecretBytes, fn func([]byte) error) error {
	if secret == nil {
		return ErrNilSecret
	}

	buf, err := secret.Open()
	if err != nil {
		return err
	}
	defer secret.Reseal(buf)

	return fn(buf.Bytes())
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

// ZeroString overwrites the backing bytes of a Go string with zeros.
// Go strings are nominally immutable, so this uses unsafe to access the
// underlying byte array. This is a best-effort operation: the GC may have
// already copied the string data elsewhere. Use this to zero sensitive
// strings (e.g., hex-encoded secrets) as soon as they are no longer needed.
//
//go:nosplit
func ZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// A Go string header is {Data unsafe.Pointer, Len int}.
	// We reinterpret it to get the underlying byte pointer.
	type stringHeader struct {
		Data unsafe.Pointer
		Len  int
	}
	hdr := (*stringHeader)(unsafe.Pointer(s))     // #nosec G103 -- intentional: zeroing secret string backing memory
	b := unsafe.Slice((*byte)(hdr.Data), hdr.Len) // #nosec G103 -- intentional: zeroing secret string backing memory
	ZeroBytes(b)
}
