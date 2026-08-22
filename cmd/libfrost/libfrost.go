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
    // The requested ciphersuite exists but is not permitted in this runtime,
    // which today means it is built on algorithms FIPS 140-3 does not approve
    // while the module is enforcing approved-only operation
    // (GODEBUG=fips140=only).
    FROST_ERR_CIPHERSUITE_NOT_ALLOWED = 7,
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
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// The mirrors in suite.go must track the C enums above, or the shim would
// resolve the wrong ciphersuite while every Go-level test still passed. Each
// pair is pinned in both directions: converting a negative untyped constant to
// uint is a compile error, so a divergence stops the build rather than
// shipping.
const (
	_ = uint(C.FROST_OK - statusOK)
	_ = uint(statusOK - C.FROST_OK)
	_ = uint(C.FROST_ERR_INVALID_PARAMS - statusInvalidParams)
	_ = uint(statusInvalidParams - C.FROST_ERR_INVALID_PARAMS)
	_ = uint(C.FROST_ERR_CIPHERSUITE_NOT_ALLOWED - statusCiphersuiteNotAllowed)
	_ = uint(statusCiphersuiteNotAllowed - C.FROST_ERR_CIPHERSUITE_NOT_ALLOWED)

	_ = uint(C.FROST_CIPHERSUITE_RISTRETTO255_SHA512 - suiteRistretto255SHA512)
	_ = uint(suiteRistretto255SHA512 - C.FROST_CIPHERSUITE_RISTRETTO255_SHA512)
	_ = uint(C.FROST_CIPHERSUITE_ED25519_SHA512 - suiteEd25519SHA512)
	_ = uint(suiteEd25519SHA512 - C.FROST_CIPHERSUITE_ED25519_SHA512)
	_ = uint(C.FROST_CIPHERSUITE_ED448_SHAKE256 - suiteEd448SHAKE256)
	_ = uint(suiteEd448SHAKE256 - C.FROST_CIPHERSUITE_ED448_SHAKE256)
	_ = uint(C.FROST_CIPHERSUITE_P256_SHA256 - suiteP256SHA256)
	_ = uint(suiteP256SHA256 - C.FROST_CIPHERSUITE_P256_SHA256)
	_ = uint(C.FROST_CIPHERSUITE_SECP256K1_SHA256 - suiteSecp256k1SHA256)
	_ = uint(suiteSecp256k1SHA256 - C.FROST_CIPHERSUITE_SECP256K1_SHA256)
)

// getCiphersuite resolves a C enum value to a ciphersuite and the status code
// to return to the caller. The logic lives in resolveSuite so it can be tested
// without cgo.
func getCiphersuite(cs C.frost_ciphersuite_t) (ciphersuite.Ciphersuite, C.frost_error_t) {
	suite, status := resolveSuite(int(cs))
	return suite, C.frost_error_t(status)
}

// getService resolves a C enum value to a FROST service and the status code to
// return to the caller.
func getService(cs C.frost_ciphersuite_t) (service.FrostService, C.frost_error_t) {
	svc, status := resolveService(int(cs))
	return svc, C.frost_error_t(status)
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

	suite, rc := getCiphersuite(cs)
	if rc != C.FROST_OK {
		return rc
	}
	svc := service.NewFrostService(suite)

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

	svc, rc := getService(cs)
	if rc != C.FROST_OK {
		return rc
	}

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
	sigBytes := append(signature.R.Bytes(), signature.Z.Bytes()...)

	*signatureOutLen = C.size_t(len(sigBytes))
	*signatureOut = (*C.uint8_t)(C.malloc(C.size_t(len(sigBytes))))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(*signatureOut)), len(sigBytes)), sigBytes)

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

	suite, rc := getCiphersuite(cs)
	if rc != C.FROST_OK {
		return rc
	}
	svc := service.NewFrostService(suite)
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
