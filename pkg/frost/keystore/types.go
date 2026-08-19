// Package keystore provides secure storage for FROST key material using go-xkms.
//
// The keystore layer abstracts key storage operations and provides integration with
// the go-xkms library for secure, production-ready key management.
package keystore

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// StoredKeyPackage represents a KeyPackage with metadata for storage.
type StoredKeyPackage struct {
	// Identifier of the participant
	Identifier frost.Identifier

	// SecretShareProtected holds the participant's secret key share in
	// encrypted, mlock'd memory. It is the only in-memory copy of the share:
	// the struct never holds a plaintext duplicate. The field itself is not
	// serialized; Seal emits the share directly from the enclave into a
	// document that is itself protected, and OpenStoredKeyPackage decodes such
	// a document straight back into one.
	SecretShareProtected *secmem.SecretBytes `json:"-"`

	// GroupPublicKey is the group's public key (serialized)
	GroupPublicKey []byte

	// VerificationShares contains all participants' verification shares (serialized)
	VerificationShares []StoredVerificationShare

	// Metadata contains additional information about the key package
	Metadata KeyMetadata
}

// StoredVerificationShare represents a serialized verification share.
type StoredVerificationShare struct {
	// Identifier of the participant
	Identifier frost.Identifier

	// VerificationKey is the public verification key (serialized)
	VerificationKey []byte
}

// KeyMetadata contains metadata about a stored key package.
type KeyMetadata struct {
	// KeyID is a unique identifier for this key package
	KeyID string

	// GroupID identifies the signing group this key belongs to
	GroupID string

	// MinSigners is the threshold (minimum signers required)
	MinSigners uint32

	// MaxSigners is the total number of participants in the group
	MaxSigners uint32

	// CreatedAt is the Unix timestamp when the key was created
	CreatedAt int64

	// UpdatedAt is the Unix timestamp when the key was last updated
	UpdatedAt int64

	// Tags are user-defined key-value pairs for organizing keys
	Tags map[string]string
}

// GroupPublicKeyEntry represents a stored group public key.
type GroupPublicKeyEntry struct {
	// GroupID uniquely identifies the signing group
	GroupID string

	// PublicKey is the group's public key (serialized)
	PublicKey []byte

	// MinSigners is the threshold
	MinSigners uint32

	// MaxSigners is the total number of participants
	MaxSigners uint32

	// CreatedAt is the Unix timestamp when the key was created
	CreatedAt int64
}

// MarshalJSON implements json.Marshaler for StoredKeyPackage by refusing.
//
// A serialized key package carries the secret share, so the document is secret
// too, and encoding/json cannot produce one without leaving the share on the
// ordinary heap: it assembles the result in a pooled buffer it neither
// zeroizes nor releases, and returns a second heap copy. The refusal is the
// point - it makes json.Marshal(storedKeyPackage) fail loudly rather than
// quietly write a document the caller cannot clean up.
//
// Use Seal instead, which returns the same document sealed in protected
// memory. See wire.go.
func (s *StoredKeyPackage) MarshalJSON() ([]byte, error) {
	return nil, ErrPlaintextSerialization
}

// UnmarshalJSON implements json.Unmarshaler for StoredKeyPackage by refusing,
// for the reason MarshalJSON does: the document holds the secret share, and
// decoding it here would put a plaintext copy on the ordinary heap.
//
// Use OpenStoredKeyPackage instead, which decodes the document from inside its
// enclave and seals the share into protected memory without either ever
// existing as a heap allocation. See wire.go.
func (s *StoredKeyPackage) UnmarshalJSON(data []byte) error {
	return ErrPlaintextSerialization
}

// Zeroize destroys the protected secret share held by the stored key package.
// It is safe to call on a nil receiver and safe to call more than once.
func (s *StoredKeyPackage) Zeroize() {
	if s == nil {
		return
	}
	s.SecretShareProtected.Destroy()
	s.SecretShareProtected = nil
}

// ToKeyPackage converts a StoredKeyPackage back to a frost.KeyPackage.
// The secret share is decrypted from protected memory for the duration of the
// deserialization only; ErrMissingSecretShare is returned when the stored key
// package carries no protected share.
func (s *StoredKeyPackage) ToKeyPackage(g group.Group) (*frost.KeyPackage, error) {
	if s.SecretShareProtected == nil {
		return nil, ErrMissingSecretShare
	}

	// Deserialize secret share from protected memory
	var secretShare group.Scalar
	var deserErr error
	if err := secmem.WithSecret(s.SecretShareProtected, func(b []byte) error {
		var err error
		secretShare, err = g.DeserializeScalar(b)
		if err != nil {
			deserErr = ErrDeserializeScalar.Wrap(err)
		}
		return nil
	}); err != nil {
		return nil, ErrProtectedMemory.Wrap(err)
	}
	if deserErr != nil {
		return nil, deserErr
	}

	// Deserialize group public key
	groupPublicKey, err := g.DeserializeElement(s.GroupPublicKey)
	if err != nil {
		return nil, ErrDeserializeElement.Wrap(err)
	}

	// Deserialize verification shares
	verificationShares := make([]frost.VerificationShare, len(s.VerificationShares))
	for i, vs := range s.VerificationShares {
		verificationKey, err := g.DeserializeElement(vs.VerificationKey)
		if err != nil {
			return nil, ErrDeserializeElement.Wrap(err)
		}
		verificationShares[i] = frost.VerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: verificationKey,
		}
	}

	return &frost.KeyPackage{
		Identifier:         s.Identifier,
		SecretShare:        secretShare,
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
	}, nil
}

// FromKeyPackage creates a StoredKeyPackage from a frost.KeyPackage.
// The secret share is held only in protected memory via SecretShareProtected;
// the serialized plaintext produced here is zeroized as it is sealed. Callers
// own the returned package and should Zeroize it once they are done with it.
func FromKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32, createdAt int64) (*StoredKeyPackage, error) {
	if kp == nil || kp.SecretShare == nil {
		return nil, ErrInvalidKeyPackage
	}

	// PROTECTED-MEMORY BOUNDARY. Serializing the share allocates it on the
	// ordinary heap for the length of this one call, and that allocation
	// cannot be avoided: it is the only thing the scalar implementations can
	// hand back.
	//
	// group.Scalar is this package's own interface, but every implementation
	// of Bytes delegates to a dependency whose sole exported encoding returns
	// a fresh slice, with no variant that fills a caller-provided
	// destination:
	//
	//	filippo.io/edwards25519  Scalar.Bytes() []byte
	//	                         (bytes(out *[32]byte) is unexported)
	//	filippo.io/bigmod        Nat.Bytes(m *Modulus) []byte  - allocates
	//	gitlab.com/yawning/
	//	  secp256k1-voi          Scalar.Bytes() []byte
	//	                         (getBytes(dst *[32]byte) is unexported)
	//	github.com/gtank/
	//	  ristretto255           Scalar.Bytes() []byte. Encode(b []byte) does
	//	                         take a destination, but it is deprecated and
	//	                         copies from Bytes() anyway - same allocation
	//
	// So the window is closed rather than removed: the serialized share is
	// passed straight into NewSecretBytes, which copies it into mlock'd memory
	// and zeroizes the transient in place before returning. It is never bound
	// to a variable here and cannot escape this expression.
	// TestFromKeyPackage_LeavesNoPlaintextShare holds that bound by scanning
	// process memory for the share afterwards.
	//
	// Widening group.Scalar with a fill-destination method would not help and
	// would mislead: four of the five suites would implement it as a copy out
	// of Bytes(), making the same allocation behind an API that promised
	// otherwise. The scalar itself is heap-resident for its whole life anyway,
	// which is the constraint the secmem package documents - arithmetic on
	// these types cannot happen inside protected memory.
	secretShareProtected := secmem.NewSecretBytes(kp.SecretShare.Bytes())
	if secretShareProtected == nil {
		return nil, ErrInvalidKeyPackage
	}

	// Serialize group public key
	groupPublicKey := kp.GroupPublicKey.Bytes()

	// Serialize verification shares
	verificationShares := make([]StoredVerificationShare, len(kp.VerificationShares))
	for i, vs := range kp.VerificationShares {
		verificationKey := vs.VerificationKey.Bytes()
		verificationShares[i] = StoredVerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: verificationKey,
		}
	}

	return &StoredKeyPackage{
		Identifier:           kp.Identifier,
		SecretShareProtected: secretShareProtected,
		GroupPublicKey:       groupPublicKey,
		VerificationShares:   verificationShares,
		Metadata: KeyMetadata{
			KeyID:      keyID,
			GroupID:    groupID,
			MinSigners: minSigners,
			MaxSigners: maxSigners,
			CreatedAt:  createdAt,
			UpdatedAt:  createdAt,
			Tags:       make(map[string]string),
		},
	}, nil
}
