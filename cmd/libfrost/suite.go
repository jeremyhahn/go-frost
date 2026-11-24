package main

import (
	"errors"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// No import "C" here, so the ciphersuite mapping and status codes are testable; libfrost.go asserts the mirrors match the C enums.

// Status codes mirroring frost_error_t.
const (
	statusOK                    = 0
	statusInvalidParams         = 1
	statusCiphersuiteNotAllowed = 7
)

// Ciphersuite selectors mirroring frost_ciphersuite_t.
const (
	suiteRistretto255SHA512 = 0
	suiteEd25519SHA512      = 1
	suiteEd448SHAKE256      = 2
	suiteP256SHA256         = 3
	suiteSecp256k1SHA256    = 4
)

// suiteIDs maps a frost_ciphersuite_t value onto the library's canonical
// identifier. A value absent from this table is a caller error.
var suiteIDs = map[int]ciphersuite.CiphersuiteID{
	suiteRistretto255SHA512: ciphersuite.Ristretto255SHA512,
	suiteEd25519SHA512:      ciphersuite.Ed25519SHA512,
	suiteEd448SHAKE256:      ciphersuite.Ed448SHAKE256,
	suiteP256SHA256:         ciphersuite.P256SHA256,
	suiteSecp256k1SHA256:    ciphersuite.Secp256k1SHA256,
}

// resolveSuite resolves a frost_ciphersuite_t to a ciphersuite and status; unknown or FIPS-excluded values are reported, never substituted.
func resolveSuite(cs int) (ciphersuite.Ciphersuite, int) {
	id, ok := suiteIDs[cs]
	if !ok {
		return nil, statusInvalidParams
	}

	suite, err := suites.Get(id)
	if err != nil {
		if errors.Is(err, ciphersuite.ErrNotFIPSSelectable) {
			return nil, statusCiphersuiteNotAllowed
		}
		return nil, statusInvalidParams
	}
	return suite, statusOK
}

// resolveService resolves a frost_ciphersuite_t to a FROST service, built per call so C threads cannot race on a cache.
func resolveService(cs int) (service.FrostService, int) {
	suite, status := resolveSuite(cs)
	if status != statusOK {
		return nil, status
	}
	return service.NewFrostService(suite), statusOK
}
