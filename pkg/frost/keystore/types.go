// Package keystore provides secure storage for FROST key material using go-xkms.
//
// The keystore layer abstracts key storage operations and provides integration with
// the go-xkms library for secure, production-ready key management.
package keystore

import (
	"encoding/json"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// StoredKeyPackage represents a KeyPackage with metadata for storage.
type StoredKeyPackage struct {
	// Identifier of the participant
	Identifier frost.Identifier

	// SecretShare is the participant's secret key share (serialized).
	// Used for JSON serialization; prefer SecretShareProtected for in-memory access.
	SecretShare []byte

	// SecretShareProtected holds the secret share in encrypted, mlock'd memory.
	// This field is not serialized to JSON; it is populated from SecretShare
	// during FromKeyPackage and used during ToKeyPackage.
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

// MarshalJSON implements json.Marshaler for StoredKeyPackage.
func (s *StoredKeyPackage) MarshalJSON() ([]byte, error) {
	type Alias StoredKeyPackage
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// UnmarshalJSON implements json.Unmarshaler for StoredKeyPackage.
func (s *StoredKeyPackage) UnmarshalJSON(data []byte) error {
	type Alias StoredKeyPackage
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	return json.Unmarshal(data, aux)
}

// ToKeyPackage converts a StoredKeyPackage back to a frost.KeyPackage.
// If SecretShareProtected is set, the secret share is decrypted from secure memory;
// otherwise it falls back to the plaintext SecretShare field.
func (s *StoredKeyPackage) ToKeyPackage(g group.Group) (*frost.KeyPackage, error) {
	// Deserialize secret share, preferring protected memory if available
	var secretShare group.Scalar
	if s.SecretShareProtected != nil {
		var deserErr error
		if err := secmem.WithSecret(s.SecretShareProtected, func(b []byte) error {
			var err error
			secretShare, err = g.DeserializeScalar(b)
			if err != nil {
				deserErr = ErrDeserializeScalar.Wrap(err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if deserErr != nil {
			return nil, deserErr
		}
	} else {
		var err error
		secretShare, err = g.DeserializeScalar(s.SecretShare)
		if err != nil {
			return nil, ErrDeserializeScalar.Wrap(err)
		}
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
// The secret share is stored both as a plaintext []byte (for JSON serialization)
// and in protected memory via SecretShareProtected.
func FromKeyPackage(keyID, groupID string, kp *frost.KeyPackage, minSigners, maxSigners uint32, createdAt int64) (*StoredKeyPackage, error) {
	// Serialize secret share
	secretShare := kp.SecretShare.Bytes()

	// Protect the secret share in secure memory
	secretShareProtected := secmem.NewSecretBytes(secretShare)

	// secretShare was zeroed by NewSecretBytes; re-serialize for JSON field.
	// Note: caller is responsible for zeroing SecretShare in the returned StoredKeyPackage
	// after it has been serialized.
	secretShareForJSON := kp.SecretShare.Bytes()

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
		SecretShare:          secretShareForJSON,
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
