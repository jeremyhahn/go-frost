// Package main provides C-compatible library bindings for go-frost.
// Build with: go build -buildmode=c-shared -o libfrost.so ./cmd/libfrost
// Or: go build -buildmode=c-archive -o libfrost.a ./cmd/libfrost
package main

/*
#include <stdlib.h>
#include <stdint.h>

// Error codes
typedef enum {
    FROST_OK = 0,
    FROST_ERR_INVALID_PARAMS = 1,
    FROST_ERR_KEYGEN_FAILED = 2,
    FROST_ERR_SIGN_FAILED = 3,
    FROST_ERR_VERIFY_FAILED = 4,
    FROST_ERR_SERIALIZE_FAILED = 5,
    FROST_ERR_DESERIALIZE_FAILED = 6,
    FROST_ERR_INTERNAL = 99
} frost_error_t;

// Ciphersuite identifiers
typedef enum {
    FROST_CIPHERSUITE_RISTRETTO255_SHA512 = 0,
    FROST_CIPHERSUITE_ED25519_SHA512 = 1,
    FROST_CIPHERSUITE_ED448_SHAKE256 = 2,
    FROST_CIPHERSUITE_P256_SHA256 = 3,
    FROST_CIPHERSUITE_SECP256K1_SHA256 = 4
} frost_ciphersuite_t;
*/
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// Global service instances per ciphersuite
var services = make(map[C.frost_ciphersuite_t]service.FrostService)

func getCiphersuite(cs C.frost_ciphersuite_t) ciphersuite.Ciphersuite {
	switch cs {
	case C.FROST_CIPHERSUITE_RISTRETTO255_SHA512:
		return ristretto255_sha512.New()
	case C.FROST_CIPHERSUITE_ED25519_SHA512:
		return ed25519_sha512.New()
	case C.FROST_CIPHERSUITE_ED448_SHAKE256:
		return ed448_shake256.New()
	case C.FROST_CIPHERSUITE_P256_SHA256:
		return p256_sha256.New()
	case C.FROST_CIPHERSUITE_SECP256K1_SHA256:
		return secp256k1_sha256.New()
	default:
		return ristretto255_sha512.New()
	}
}

func getService(cs C.frost_ciphersuite_t) service.FrostService {
	if svc, ok := services[cs]; ok {
		return svc
	}
	suite := getCiphersuite(cs)
	svc := service.NewFrostService(suite)
	services[cs] = svc
	return svc
}

//export frost_version
func frost_version() *C.char {
	return C.CString("1.0.0")
}

//export frost_free_string
func frost_free_string(s *C.char) {
	C.free(unsafe.Pointer(s))
}

//export frost_free_bytes
func frost_free_bytes(b *C.uint8_t) {
	C.free(unsafe.Pointer(b))
}

//export frost_generate_keys
func frost_generate_keys(
	cs C.frost_ciphersuite_t,
	minSigners C.uint32_t,
	maxSigners C.uint32_t,
	keysOut **C.char,
	keysOutLen *C.size_t,
	publicKeyOut **C.uint8_t,
	publicKeyOutLen *C.size_t,
) C.frost_error_t {
	if minSigners < 2 || maxSigners < minSigners {
		return C.FROST_ERR_INVALID_PARAMS
	}

	svc := getService(cs)
	suite := getCiphersuite(cs)

	config := frost.Configuration{
		MinSigners: uint32(minSigners),
		MaxSigners: uint32(maxSigners),
		Group:      suite.Group(),
	}

	// Generate participant IDs
	participantIDs := make([]frost.Identifier, maxSigners)
	for i := uint32(0); i < uint32(maxSigners); i++ {
		participantIDs[i] = frost.Identifier(i + 1)
	}

	keyPackages, groupPublicKey, err := svc.GenerateKeys(config, participantIDs)
	if err != nil {
		return C.FROST_ERR_KEYGEN_FAILED
	}

	// Serialize key packages to JSON
	keysJSON, err := json.Marshal(keyPackages)
	if err != nil {
		return C.FROST_ERR_SERIALIZE_FAILED
	}

	// Copy keys to C memory
	*keysOut = C.CString(string(keysJSON))
	*keysOutLen = C.size_t(len(keysJSON))
	secmem.ZeroBytes(keysJSON)

	// Serialize public key
	pubKeyBytes := groupPublicKey.Bytes()
	*publicKeyOutLen = C.size_t(len(pubKeyBytes))
	*publicKeyOut = (*C.uint8_t)(C.malloc(C.size_t(len(pubKeyBytes))))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(*publicKeyOut)), len(pubKeyBytes)), pubKeyBytes)

	return C.FROST_OK
}

//export frost_sign
func frost_sign(
	cs C.frost_ciphersuite_t,
	keysJSON *C.char,
	keysJSONLen C.size_t,
	signerIndices *C.uint32_t,
	signerIndicesLen C.size_t,
	message *C.uint8_t,
	messageLen C.size_t,
	signatureOut **C.uint8_t,
	signatureOutLen *C.size_t,
) C.frost_error_t {
	if keysJSON == nil || message == nil || signerIndicesLen < 2 {
		return C.FROST_ERR_INVALID_PARAMS
	}

	svc := getService(cs)

	// Parse key packages
	keysData := C.GoBytes(unsafe.Pointer(keysJSON), C.int(keysJSONLen))
	var keyPackages []frost.KeyPackage
	if err := json.Unmarshal(keysData, &keyPackages); err != nil {
		secmem.ZeroBytes(keysData)
		return C.FROST_ERR_DESERIALIZE_FAILED
	}
	secmem.ZeroBytes(keysData)

	// Get signer indices
	indices := unsafe.Slice((*uint32)(unsafe.Pointer(signerIndices)), signerIndicesLen)

	// Select signing key packages
	signingPackages := make([]frost.KeyPackage, len(indices))
	for i, idx := range indices {
		if int(idx) >= len(keyPackages) {
			return C.FROST_ERR_INVALID_PARAMS
		}
		signingPackages[i] = keyPackages[idx]
	}

	// Get message
	msg := C.GoBytes(unsafe.Pointer(message), C.int(messageLen))

	// Sign
	signature, err := svc.Sign(signingPackages, msg)
	if err != nil {
		return C.FROST_ERR_SIGN_FAILED
	}

	// Serialize signature
	suite := getCiphersuite(cs)
	sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)

	*signatureOutLen = C.size_t(len(sigBytes))
	*signatureOut = (*C.uint8_t)(C.malloc(C.size_t(len(sigBytes))))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(*signatureOut)), len(sigBytes)), sigBytes)

	_ = suite // Suppress unused warning
	return C.FROST_OK
}

//export frost_verify
func frost_verify(
	cs C.frost_ciphersuite_t,
	message *C.uint8_t,
	messageLen C.size_t,
	signature *C.uint8_t,
	signatureLen C.size_t,
	publicKey *C.uint8_t,
	publicKeyLen C.size_t,
) C.frost_error_t {
	if message == nil || signature == nil || publicKey == nil {
		return C.FROST_ERR_INVALID_PARAMS
	}

	svc := getService(cs)
	suite := getCiphersuite(cs)
	grp := suite.Group()

	// Parse message
	msg := C.GoBytes(unsafe.Pointer(message), C.int(messageLen))

	// Parse signature
	sigBytes := C.GoBytes(unsafe.Pointer(signature), C.int(signatureLen))
	elementLen := grp.ElementLength()
	scalarLen := grp.ScalarLength()

	if len(sigBytes) != elementLen+scalarLen {
		return C.FROST_ERR_INVALID_PARAMS
	}

	R, err := grp.DeserializeElement(sigBytes[:elementLen])
	if err != nil {
		return C.FROST_ERR_DESERIALIZE_FAILED
	}

	Z, err := grp.DeserializeScalar(sigBytes[elementLen:])
	if err != nil {
		return C.FROST_ERR_DESERIALIZE_FAILED
	}

	sig := frost.Signature{R: R, Z: Z}

	// Parse public key
	pubKeyBytes := C.GoBytes(unsafe.Pointer(publicKey), C.int(publicKeyLen))
	groupPublicKey, err := grp.DeserializeElement(pubKeyBytes)
	if err != nil {
		return C.FROST_ERR_DESERIALIZE_FAILED
	}

	// Verify
	err = svc.Verify(msg, sig, groupPublicKey)
	if err != nil {
		return C.FROST_ERR_VERIFY_FAILED
	}

	return C.FROST_OK
}

func main() {}
