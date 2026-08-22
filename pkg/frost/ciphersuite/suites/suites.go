// Package suites resolves the RFC 9591 ciphersuites from an identifier, so a
// suite can be chosen from a configuration file, a command-line flag or a
// peer's session information instead of by importing one implementation
// package directly.
//
// Selection is the only place FIPS 140-3 policy is applied. Get refuses a
// ciphersuite that is not FIPSSelectable while the module is enforcing
// approved-only operation, and Default names FROST(P-256, SHA-256) whenever
// the module is active, so a ceremony started under FIPS produces shares that
// remain usable under FIPS.
//
// # No part of this package is a FIPS approval claim
//
// Read this before repeating anything here to an auditor.
//
// FROST IS NOT A FIPS-APPROVED SIGNATURE SCHEME. FIPS 186-5 approves ECDSA,
// EdDSA and RSA; FROST is threshold Schnorr, which is none of them. NIST's
// threshold cryptography work (the NISTIR 8214 series) is a project, not an
// approved standard. Producing a FROST signature is therefore a non-approved
// operation whatever curve and hash it is built on, and selecting P-256 here
// does not make the resulting signature FIPS-compliant.
//
// Nor is the implementation inside a validated boundary. go-frost is not a
// validated cryptographic module. Its P-256 point arithmetic comes from
// crypto/elliptic, but its scalar field arithmetic runs through
// filippo.io/bigmod (pkg/frost/group/p256) — a re-export of Go's internal
// fips140/bigmod, and outside the validated boundary all the same.
//
// FIPSSelectable is therefore named for what it does: it decides which suite
// this library will hand out while FIPS enforcement is active. It reports a
// local policy, not an approval, not a validation, and not a compliance
// guarantee. See issue #14, which asks the owner what go-frost should do here.
//
// The set is closed: it holds exactly the five ciphersuites RFC 9591 defines
// and nothing can be added at run time. That is deliberate rather than an
// omission — an extensible registry would admit a suite the FIPS policy table
// knows nothing about, and the gate above would pass it. Code that genuinely
// needs a non-standard suite constructs it directly and passes the
// ciphersuite.Ciphersuite value along; it just does not get to be selectable
// by name.
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

// fipsSelectable records which ciphersuites this library hands out while FIPS
// enforcement is active. FROST(P-256, SHA-256) is the only one, because P-256
// and SHA-256 are the only underlying primitives FIPS approves at all — the
// other four are built on Curve25519, Ed448 or secp256k1, which are not
// approved curves in any scheme.
//
// That is a comparative statement, not an approval: FROST itself is not an
// approved signature scheme, so no entry in this table is FIPS-compliant. The
// table exists so that a deployment which has chosen to run FROST under FIPS
// at least does so on the approved primitives rather than on Curve25519.
// Whether this library should run under enforcement at all is issue #14, an
// open question for the owner.
var fipsSelectable = map[ciphersuite.CiphersuiteID]struct{}{
	ciphersuite.P256SHA256: {},
}

// aliases maps every accepted spelling, lower-cased, to a canonical
// identifier. Matching is deliberately case-insensitive: RFC 9591 spells the
// secp256k1 context string in lower case and the other four in upper, so a
// consumer that upper-cases them uniformly would otherwise name a suite that
// does not exist.
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

// Parse resolves a ciphersuite name to its canonical RFC 9591 identifier. It
// accepts the context string Ciphersuite.ID reports, the short name used on a
// command line, and the "<group>-<hash>" long form, in any case and with
// surrounding space trimmed. The empty string means "no preference" and
// resolves to Default.
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

// Get returns a new instance of the ciphersuite with the given canonical
// identifier.
//
// While the FIPS 140-3 module is enforcing approved-only operation
// (GODEBUG=fips140=only), a ciphersuite that fails FIPSSelectable is refused
// here with ErrNotFIPSSelectable rather than left to fail somewhere deeper in
// the protocol. Under GODEBUG=fips140=on the module permits unapproved
// algorithms, so an explicit choice is honored and only Default shifts.
//
// Passing this gate means this library was willing to hand the suite over. It
// is not an approval, not a validation, and not a compliance guarantee — see
// the package comment.
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

// FIPSSelectable reports whether this library will hand out a ciphersuite
// while FIPS enforcement is active, independent of whether it currently is.
// Only FROST(P-256, SHA-256) is, because only its underlying primitives are
// FIPS-approved ones.
//
// The name is deliberately about selection rather than approval. FROST is not
// a FIPS-approved signature scheme and go-frost is not a validated module, so
// there is no sense in which a true result here makes an operation compliant.
// Read the package comment before repeating this to an auditor.
func FIPSSelectable(id ciphersuite.CiphersuiteID) bool {
	_, ok := fipsSelectable[id]
	return ok
}

// Default returns the identifier a new ceremony uses when the caller
// expresses no preference: FROST(ristretto255, SHA-512) normally, and
// FROST(P-256, SHA-256) whenever the FIPS 140-3 module is active
// (GODEBUG=fips140=on or fips140=only). Shares outlive the ceremony that
// produced them, so a ceremony run under FIPS must not mint shares that a
// FIPS deployment then cannot use. Owner ruling 2026-08-20 (go-frost#12).
//
// Get(Default()) always succeeds.
func Default() ciphersuite.CiphersuiteID {
	if fips140.Enabled() {
		return ciphersuite.P256SHA256
	}
	return ciphersuite.Ristretto255SHA512
}
