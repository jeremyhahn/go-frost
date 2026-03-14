package serialization

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Serializer provides versioned serialization for FROST data structures.
type Serializer struct {
	suite         ciphersuite.Ciphersuite
	ciphersuiteID uint32
}

// NewSerializer creates a new Serializer for the given ciphersuite.
func NewSerializer(suite ciphersuite.Ciphersuite) *Serializer {
	return &Serializer{
		suite:         suite,
		ciphersuiteID: CiphersuiteIDFromString(suite.ID()),
	}
}

// SerializeSignature serializes a FROST signature with header.
func (s *Serializer) SerializeSignature(sig frost.Signature) ([]byte, error) {
	if sig.R == nil || sig.Z == nil {
		return nil, ErrInvalidData
	}

	grp := s.suite.Group()
	header := NewHeader(s.ciphersuiteID, DataTypeSignature)

	rBytes, err := grp.SerializeElement(sig.R)
	if err != nil {
		return nil, err
	}
	zBytes := grp.SerializeScalar(sig.Z)

	data := make([]byte, HeaderSize+len(rBytes)+len(zBytes))
	copy(data[:HeaderSize], header.Serialize())
	copy(data[HeaderSize:HeaderSize+len(rBytes)], rBytes)
	copy(data[HeaderSize+len(rBytes):], zBytes)

	return data, nil
}

// DeserializeSignature deserializes a FROST signature.
func (s *Serializer) DeserializeSignature(data []byte) (frost.Signature, error) {
	header, err := DeserializeHeader(data)
	if err != nil {
		return frost.Signature{}, err
	}

	if err := header.Validate(s.ciphersuiteID, DataTypeSignature); err != nil {
		return frost.Signature{}, err
	}

	grp := s.suite.Group()
	elemLen := grp.ElementLength()
	scalarLen := grp.ScalarLength()

	expectedLen := HeaderSize + elemLen + scalarLen
	if len(data) != expectedLen {
		return frost.Signature{}, ErrInvalidData
	}

	// Bounds already validated above via expectedLen check
	r, err := grp.DeserializeElement(data[HeaderSize : HeaderSize+elemLen]) //nolint:gosec // G602: bounds checked above
	if err != nil {
		return frost.Signature{}, err
	}

	z, err := grp.DeserializeScalar(data[HeaderSize+elemLen:])
	if err != nil {
		return frost.Signature{}, err
	}

	return frost.Signature{R: r, Z: z}, nil
}

// SerializeSigningCommitments serializes signing commitments with header.
func (s *Serializer) SerializeSigningCommitments(sc frost.SigningCommitments) ([]byte, error) {
	if sc.HidingNonceCommitment == nil || sc.BindingNonceCommitment == nil {
		return nil, ErrInvalidData
	}

	grp := s.suite.Group()
	header := NewHeader(s.ciphersuiteID, DataTypeSigningCommitments)

	hidingBytes, err := grp.SerializeElement(sc.HidingNonceCommitment)
	if err != nil {
		return nil, err
	}
	bindingBytes, err := grp.SerializeElement(sc.BindingNonceCommitment)
	if err != nil {
		return nil, err
	}

	// Format: header (8) + identifier (4) + hiding (elemLen) + binding (elemLen)
	data := make([]byte, HeaderSize+4+len(hidingBytes)+len(bindingBytes))
	copy(data[:HeaderSize], header.Serialize())
	binary.BigEndian.PutUint32(data[HeaderSize:HeaderSize+4], uint32(sc.Identifier))
	copy(data[HeaderSize+4:HeaderSize+4+len(hidingBytes)], hidingBytes)
	copy(data[HeaderSize+4+len(hidingBytes):], bindingBytes)

	return data, nil
}

// DeserializeSigningCommitments deserializes signing commitments.
func (s *Serializer) DeserializeSigningCommitments(data []byte) (frost.SigningCommitments, error) {
	header, err := DeserializeHeader(data)
	if err != nil {
		return frost.SigningCommitments{}, err
	}

	if err := header.Validate(s.ciphersuiteID, DataTypeSigningCommitments); err != nil {
		return frost.SigningCommitments{}, err
	}

	grp := s.suite.Group()
	elemLen := grp.ElementLength()

	expectedLen := HeaderSize + 4 + elemLen*2
	if len(data) != expectedLen {
		return frost.SigningCommitments{}, ErrInvalidData
	}

	identifier := frost.Identifier(binary.BigEndian.Uint32(data[HeaderSize : HeaderSize+4]))

	hiding, err := grp.DeserializeElement(data[HeaderSize+4 : HeaderSize+4+elemLen])
	if err != nil {
		return frost.SigningCommitments{}, err
	}

	binding, err := grp.DeserializeElement(data[HeaderSize+4+elemLen:])
	if err != nil {
		return frost.SigningCommitments{}, err
	}

	return frost.SigningCommitments{
		Identifier:             identifier,
		HidingNonceCommitment:  hiding,
		BindingNonceCommitment: binding,
	}, nil
}

// SerializeSignatureShare serializes a signature share with header.
func (s *Serializer) SerializeSignatureShare(ss frost.SignatureShare) ([]byte, error) {
	if ss.SignatureShare == nil {
		return nil, ErrInvalidData
	}

	grp := s.suite.Group()
	header := NewHeader(s.ciphersuiteID, DataTypeSignatureShare)

	shareBytes := grp.SerializeScalar(ss.SignatureShare)

	// Format: header (8) + identifier (4) + share (scalarLen)
	data := make([]byte, HeaderSize+4+len(shareBytes))
	copy(data[:HeaderSize], header.Serialize())
	binary.BigEndian.PutUint32(data[HeaderSize:HeaderSize+4], uint32(ss.Identifier))
	copy(data[HeaderSize+4:], shareBytes)

	return data, nil
}

// DeserializeSignatureShare deserializes a signature share.
func (s *Serializer) DeserializeSignatureShare(data []byte) (frost.SignatureShare, error) {
	header, err := DeserializeHeader(data)
	if err != nil {
		return frost.SignatureShare{}, err
	}

	if err := header.Validate(s.ciphersuiteID, DataTypeSignatureShare); err != nil {
		return frost.SignatureShare{}, err
	}

	grp := s.suite.Group()
	scalarLen := grp.ScalarLength()

	expectedLen := HeaderSize + 4 + scalarLen
	if len(data) != expectedLen {
		return frost.SignatureShare{}, ErrInvalidData
	}

	identifier := frost.Identifier(binary.BigEndian.Uint32(data[HeaderSize : HeaderSize+4]))

	share, err := grp.DeserializeScalar(data[HeaderSize+4:])
	if err != nil {
		return frost.SignatureShare{}, err
	}

	return frost.SignatureShare{
		Identifier:     identifier,
		SignatureShare: share,
	}, nil
}

// SerializePublicKey serializes a public key (group element) with header.
func (s *Serializer) SerializePublicKey(pk group.Element) ([]byte, error) {
	if pk == nil {
		return nil, ErrInvalidData
	}

	grp := s.suite.Group()
	header := NewHeader(s.ciphersuiteID, DataTypePublicKey)

	pkBytes, err := grp.SerializeElement(pk)
	if err != nil {
		return nil, err
	}

	data := make([]byte, HeaderSize+len(pkBytes))
	copy(data[:HeaderSize], header.Serialize())
	copy(data[HeaderSize:], pkBytes)

	return data, nil
}

// DeserializePublicKey deserializes a public key.
func (s *Serializer) DeserializePublicKey(data []byte) (group.Element, error) {
	header, err := DeserializeHeader(data)
	if err != nil {
		return nil, err
	}

	if err := header.Validate(s.ciphersuiteID, DataTypePublicKey); err != nil {
		return nil, err
	}

	grp := s.suite.Group()
	elemLen := grp.ElementLength()

	expectedLen := HeaderSize + elemLen
	if len(data) != expectedLen {
		return nil, ErrInvalidData
	}

	return grp.DeserializeElement(data[HeaderSize:])
}

// SerializeSecretShare serializes a secret share (scalar) with header.
// WARNING: This serializes sensitive secret data. Handle with care.
func (s *Serializer) SerializeSecretShare(share group.Scalar) ([]byte, error) {
	if share == nil {
		return nil, ErrInvalidData
	}

	grp := s.suite.Group()
	header := NewHeader(s.ciphersuiteID, DataTypeSecretShare)

	shareBytes := grp.SerializeScalar(share)

	data := make([]byte, HeaderSize+len(shareBytes))
	copy(data[:HeaderSize], header.Serialize())
	copy(data[HeaderSize:], shareBytes)
	secmem.ZeroBytes(shareBytes)

	return data, nil
}

// DeserializeSecretShare deserializes a secret share.
func (s *Serializer) DeserializeSecretShare(data []byte) (group.Scalar, error) {
	header, err := DeserializeHeader(data)
	if err != nil {
		return nil, err
	}

	if err := header.Validate(s.ciphersuiteID, DataTypeSecretShare); err != nil {
		return nil, err
	}

	grp := s.suite.Group()
	scalarLen := grp.ScalarLength()

	expectedLen := HeaderSize + scalarLen
	if len(data) != expectedLen {
		return nil, ErrInvalidData
	}

	return grp.DeserializeScalar(data[HeaderSize:])
}
