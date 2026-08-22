package main

import (
	"errors"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// This file deliberately does not import "C". The ciphersuite mapping and the
// status codes it returns are the security-relevant part of the C shim — a
// swapped entry would sign on the wrong curve, or allow a suite FIPS policy
// excludes — and a cgo file cannot be exercised from a test, because a test
// file gets its own preamble and cannot see the enums declared in libfrost.go.
// Keeping the logic in ordinary Go makes it testable; libfrost.go asserts at
// compile time that the mirrors below still equal their C counterparts.

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

// resolveSuite resolves a frost_ciphersuite_t value to a ciphersuite, together
// with the status code to hand back to the caller.
//
// An unrecognized value and a suite the FIPS 140-3 policy excludes are both
// reported; neither substitutes ristretto255, as this used to do silently — a
// caller that passed a value the library did not understand got keys on a
// curve it never asked for.
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

// resolveService resolves a frost_ciphersuite_t value to a FROST service. A
// service is a thin wrapper over the ciphersuite, so it is built per call
// rather than cached in a package map that C callers on several threads could
// race on.
func resolveService(cs int) (service.FrostService, int) {
	suite, status := resolveSuite(cs)
	if status != statusOK {
		return nil, status
	}
	return service.NewFrostService(suite), statusOK
}
