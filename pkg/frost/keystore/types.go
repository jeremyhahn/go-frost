// Package keystore provides secure storage for FROST key material using go-xkms.
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

	// SecretShareProtected is the only in-memory copy of the share, in mlock'd memory; Seal and OpenStoredKeyPackage serialize it.
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

// MarshalJSON refuses, because encoding/json would leave the share on the heap; use Seal.
func (s *StoredKeyPackage) MarshalJSON() ([]byte, error) {
	return nil, ErrPlaintextSerialization
}

// UnmarshalJSON refuses, because decoding here would put the share on the heap; use OpenStoredKeyPackage.
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

// ToKeyPackage returns the frost.KeyPackage, decrypting the share only while deserializing; ErrMissingSecretShare if none.
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

// FromKeyPackage returns a StoredKeyPackage with the share only in protected memory; callers should Zeroize it.
func FromKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32, createdAt int64) (*StoredKeyPackage, error) {
	if kp == nil || kp.SecretShare == nil {
		return nil, ErrInvalidKeyPackage
	}

	// The scalar types only return a fresh []byte, so the serialized share goes straight into NewSecretBytes, which zeroizes it.
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
