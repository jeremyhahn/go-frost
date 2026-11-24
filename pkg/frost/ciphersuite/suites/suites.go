// Package suites resolves the five RFC 9591 ciphersuites by identifier and applies the FIPS 140-3 selection policy; FROST is not FIPS-approved and nothing here is a compliance claim.
package suites

import (
	"crypto/fips140"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"
)

// listing is the canonical order List and the CLI help report, most
// recommended first. Every other table in this file is keyed by these
// identifiers.
var listing = []ciphersuite.CiphersuiteID{
	ciphersuite.Ristretto255SHA512,
	ciphersuite.Ed25519SHA512,
	ciphersuite.Ed448SHAKE256,
	ciphersuite.P256SHA256,
	ciphersuite.Secp256k1SHA256,
}

// constructors maps each identifier to the constructor for its implementation.
var constructors = map[ciphersuite.CiphersuiteID]func() ciphersuite.Ciphersuite{
	ciphersuite.Ristretto255SHA512: func() ciphersuite.Ciphersuite { return ristretto255_sha512.New() },
	ciphersuite.Ed25519SHA512:      func() ciphersuite.Ciphersuite { return ed25519_sha512.New() },
	ciphersuite.Ed448SHAKE256:      func() ciphersuite.Ciphersuite { return ed448_shake256.New() },
	ciphersuite.P256SHA256:         func() ciphersuite.Ciphersuite { return p256_sha256.New() },
	ciphersuite.Secp256k1SHA256:    func() ciphersuite.Ciphersuite { return secp256k1_sha256.New() },
}

// shortNames maps each identifier to the spelling a human types.
var shortNames = map[ciphersuite.CiphersuiteID]string{
	ciphersuite.Ristretto255SHA512: "ristretto255",
	ciphersuite.Ed25519SHA512:      "ed25519",
	ciphersuite.Ed448SHAKE256:      "ed448",
	ciphersuite.P256SHA256:         "p256",
	ciphersuite.Secp256k1SHA256:    "secp256k1",
}

// longNames maps each identifier to its "<group>-<hash>" spelling.
var longNames = map[ciphersuite.CiphersuiteID]string{
	ciphersuite.Ristretto255SHA512: "ristretto255-sha512",
	ciphersuite.Ed25519SHA512:      "ed25519-sha512",
	ciphersuite.Ed448SHAKE256:      "ed448-shake256",
	ciphersuite.P256SHA256:         "p256-sha256",
	ciphersuite.Secp256k1SHA256:    "secp256k1-sha256",
}

// fipsSelectable lists the suites handed out under FIPS enforcement: only P-256/SHA-256, whose primitives are approved; FROST itself is not.
var fipsSelectable = map[ciphersuite.CiphersuiteID]struct{}{
	ciphersuite.P256SHA256: {},
}

// aliases maps every accepted lower-cased spelling to a canonical identifier; matching is case-insensitive.
var aliases = buildAliases()

func buildAliases() map[string]ciphersuite.CiphersuiteID {
	a := make(map[string]ciphersuite.CiphersuiteID, len(listing)*3)
	for _, id := range listing {
		// The canonical context string resolves too, so a caller can hand back
		// what Ciphersuite.ID() returned without translating it first.
		a[strings.ToLower(string(id))] = id
		a[shortNames[id]] = id
		a[longNames[id]] = id
	}
	return a
}

// Parse resolves a context string, short name or "<group>-<hash>" form, in any case, to its RFC 9591 identifier; empty means Default.
func Parse(name string) (ciphersuite.CiphersuiteID, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return Default(), nil
	}

	id, ok := aliases[strings.ToLower(trimmed)]
	if !ok {
		return "", ciphersuite.NewLookupError(name, ciphersuite.ErrUnknownCiphersuite)
	}
	return id, nil
}

// Get returns a new ciphersuite for the identifier, refusing a non-FIPSSelectable suite with ErrNotFIPSSelectable under GODEBUG=fips140=only.
func Get(id ciphersuite.CiphersuiteID) (ciphersuite.Ciphersuite, error) {
	newSuite, ok := constructors[id]
	if !ok {
		return nil, ciphersuite.NewLookupError(string(id), ciphersuite.ErrUnknownCiphersuite)
	}
	if fips140.Enforced() && !FIPSSelectable(id) {
		return nil, ciphersuite.NewLookupError(string(id), ciphersuite.ErrNotFIPSSelectable)
	}
	return newSuite(), nil
}

// ByName resolves a name with Parse and returns the ciphersuite it selects.
// It is the entry point for a command line, a configuration file or a peer's
// session information.
func ByName(name string) (ciphersuite.Ciphersuite, error) {
	id, err := Parse(name)
	if err != nil {
		return nil, err
	}
	return Get(id)
}

// List returns the canonical identifiers of every ciphersuite RFC 9591
// defines, in a stable order. The caller owns the returned slice.
func List() []ciphersuite.CiphersuiteID {
	return slices.Clone(listing)
}

// ShortName returns the command-line spelling of an identifier, or the
// identifier itself if it names no known ciphersuite.
func ShortName(id ciphersuite.CiphersuiteID) string {
	if name, ok := shortNames[id]; ok {
		return name
	}
	return string(id)
}

// FIPSSelectable reports whether this library hands out the suite under FIPS enforcement (only P-256/SHA-256); it is not an approval.
func FIPSSelectable(id ciphersuite.CiphersuiteID) bool {
	_, ok := fipsSelectable[id]
	return ok
}

// Default returns ristretto255/SHA-512, or P-256/SHA-256 whenever the FIPS 140-3 module is active, so FIPS ceremonies mint usable shares; Get(Default()) always succeeds.
func Default() ciphersuite.CiphersuiteID {
	if fips140.Enabled() {
		return ciphersuite.P256SHA256
	}
	return ciphersuite.Ristretto255SHA512
}
