package helpers

import (
	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/group"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// BindingFactorComputer computes binding factors for the signing protocol.
type BindingFactorComputer interface {
	// Compute calculates binding factors for all participants in the commitment list.
	//
	// Inputs:
	// - groupPublicKey: The group's public key
	// - commitmentList: Sorted list of participant commitments
	// - msg: The message to be signed
	//
	// Outputs:
	// - bindingFactors: List of binding factors for each participant
	//
	// The binding factor for participant i is computed as:
	// H1(group_public_key || H4(msg) || H5(encoded_commitment_list) || identifier_i)
	Compute(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte) (frost.BindingFactorList, error)

	// GetBindingFactor retrieves the binding factor for a specific participant.
	//
	// Inputs:
	// - bindingFactors: List of binding factors
	// - identifier: The participant's identifier
	//
	// Outputs:
	// - bindingFactor: The binding factor for the participant
	//
	// Errors:
	// - Returns error if the participant is not found
	GetBindingFactor(bindingFactors frost.BindingFactorList, identifier frost.Identifier) (group.Scalar, error)
}

// NewBindingFactorComputer creates a new binding factor computer.
func NewBindingFactorComputer(suite ciphersuite.Ciphersuite) BindingFactorComputer {
	return &bindingFactorComputer{suite: suite}
}

type bindingFactorComputer struct {
	suite ciphersuite.Ciphersuite
}

// Compute implements BindingFactorComputer.Compute
//
// Calculates binding factors for all participants in the commitment list.
// The binding factor for participant i is computed as:
// H1(group_public_key || H4(msg) || H5(encoded_commitment_list) || identifier_i)
//
// Algorithm (from RFC 9591 Section 4.4):
//  1. Serialize group public key
//  2. Compute msg_hash = H4(msg)
//  3. Encode commitment list and compute encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))
//  4. Create rho_input_prefix = group_public_key_enc || msg_hash || encoded_commitment_hash
//  5. For each participant:
//     a. Compute rho_input = rho_input_prefix || identifier
//     b. Compute binding_factor = H1(rho_input)
//     c. Add (identifier, binding_factor) to list
func (b *bindingFactorComputer) Compute(groupPublicKey group.Element, commitmentList frost.CommitmentList, msg []byte) (frost.BindingFactorList, error) {
	if groupPublicKey == nil {
		return nil, frost.NewParameterError("groupPublicKey", "cannot be nil", frost.ErrInvalidParameters)
	}

	if len(commitmentList) == 0 {
		return nil, frost.ErrEmptyCommitmentList
	}

	// 1. Serialize group public key
	groupPublicKeyBytes := groupPublicKey.Bytes()

	// 2. Compute msg_hash = H4(msg)
	msgHash := b.suite.H4(msg)

	// 3. Encode commitment list and compute encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))
	encoder := NewCommitmentListEncoder(b.suite.Group())
	encodedCommitmentList, err := encoder.Encode(commitmentList)
	if err != nil {
		return nil, frost.NewParameterError("commitmentList", "failed to encode", err)
	}
	encodedCommitmentHash := b.suite.H5(encodedCommitmentList)

	// 4. Create rho_input_prefix = group_public_key_enc || msg_hash || encoded_commitment_hash
	rhoInputPrefix := append(groupPublicKeyBytes, msgHash...)
	rhoInputPrefix = append(rhoInputPrefix, encodedCommitmentHash...)

	// 5. For each participant, compute binding factor
	bindingFactors := make(frost.BindingFactorList, len(commitmentList))
	scalarLen := b.suite.Group().ScalarLength()

	for i, commitment := range commitmentList {
		// a. Compute rho_input = rho_input_prefix || identifier
		identifierBytes := make([]byte, scalarLen)
		id := uint32(commitment.Identifier)

		// Encode identifier using the group's native byte order
		if b.suite.Group().ByteOrder() == group.BigEndian {
			// Big-endian encoding
			identifierBytes[scalarLen-1] = byte(id)
			identifierBytes[scalarLen-2] = byte(id >> 8)
			identifierBytes[scalarLen-3] = byte(id >> 16)
			identifierBytes[scalarLen-4] = byte(id >> 24)
		} else {
			// Little-endian encoding (Ed25519, Ed448, ristretto255)
			for j := 0; j < 4 && j < len(identifierBytes); j++ {
				identifierBytes[j] = byte(id >> (8 * j))
			}
		}

		// Create a new slice to avoid append reusing rhoInputPrefix's backing array
		rhoInput := make([]byte, len(rhoInputPrefix)+len(identifierBytes))
		copy(rhoInput, rhoInputPrefix)
		copy(rhoInput[len(rhoInputPrefix):], identifierBytes)

		// b. Compute binding_factor = H1(rho_input)
		bindingFactor := b.suite.H1(rhoInput)

		// Zero ephemeral buffers
		secmem.ZeroBytes(identifierBytes)
		secmem.ZeroBytes(rhoInput)

		// c. Add (identifier, binding_factor) to list
		bindingFactors[i] = frost.BindingFactor{
			Identifier:    commitment.Identifier,
			BindingFactor: bindingFactor,
		}
	}

	// Zero the prefix buffer
	secmem.ZeroBytes(rhoInputPrefix)

	return bindingFactors, nil
}

// GetBindingFactor implements BindingFactorComputer.GetBindingFactor
//
// Retrieves the binding factor for a specific participant from the binding factor list.
func (b *bindingFactorComputer) GetBindingFactor(bindingFactors frost.BindingFactorList, identifier frost.Identifier) (group.Scalar, error) {
	for _, bf := range bindingFactors {
		if bf.Identifier == identifier {
			return bf.BindingFactor, nil
		}
	}

	return nil, frost.NewParticipantError(identifier, "binding factor not found", frost.ErrInvalidParticipant)
}
