package main

import (
	"crypto/fips140"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
)

// enumCases pins each frost_ciphersuite_t value to the suite a C caller gets.
// The identifiers are spelled out rather than read back from suiteIDs, so a
// swapped entry in that table fails here instead of agreeing with itself.
var enumCases = []struct {
	name string
	enum int
	want ciphersuite.CiphersuiteID
}{
	{"ristretto255", suiteRistretto255SHA512, ciphersuite.Ristretto255SHA512},
	{"ed25519", suiteEd25519SHA512, ciphersuite.Ed25519SHA512},
	{"ed448", suiteEd448SHAKE256, ciphersuite.Ed448SHAKE256},
	{"p256", suiteP256SHA256, ciphersuite.P256SHA256},
	{"secp256k1", suiteSecp256k1SHA256, ciphersuite.Secp256k1SHA256},
}

func TestResolveSuite_MapsEveryEnumToItsOwnSuite(t *testing.T) {
	for _, tc := range enumCases {
		t.Run(tc.name, func(t *testing.T) {
			suite, status := resolveSuite(tc.enum)

			if fips140.Enforced() && !suites.FIPSSelectable(tc.want) {
				if status != statusCiphersuiteNotAllowed {
					t.Fatalf("enum %d under fips140=only: status = %d, want %d", tc.enum, status, statusCiphersuiteNotAllowed)
				}
				if suite != nil {
					t.Errorf("enum %d returned a suite alongside a refusal", tc.enum)
				}
				return
			}

			if status != statusOK {
				t.Fatalf("enum %d: status = %d, want statusOK", tc.enum, status)
			}
			if suite == nil {
				t.Fatalf("enum %d returned a nil ciphersuite", tc.enum)
			}
			if suite.ID() != string(tc.want) {
				t.Errorf("enum %d resolved to %q, want %q", tc.enum, suite.ID(), tc.want)
			}
		})
	}
}

// TestSuiteIDs_CoversExactlyTheStandardSuites catches an enum being added to
// the C header without a mapping, or a mapping outliving its enum.
func TestSuiteIDs_CoversExactlyTheStandardSuites(t *testing.T) {
	if len(suiteIDs) != len(enumCases) {
		t.Errorf("suiteIDs has %d entries, the enum has %d", len(suiteIDs), len(enumCases))
	}

	standard := make(map[ciphersuite.CiphersuiteID]bool)
	for _, id := range suites.List() {
		standard[id] = true
	}

	seen := make(map[ciphersuite.CiphersuiteID]bool, len(suiteIDs))
	for enum, id := range suiteIDs {
		if !standard[id] {
			t.Errorf("enum %d maps to %q, which is not an RFC 9591 suite", enum, id)
		}
		if seen[id] {
			t.Errorf("%q is reachable from more than one enum value", id)
		}
		seen[id] = true
	}

	for id := range standard {
		if !seen[id] {
			t.Errorf("no enum value reaches %q", id)
		}
	}
}

func TestResolveSuite_UnknownEnumIsRejected(t *testing.T) {
	for _, enum := range []int{-1, 5, 99, 1 << 20} {
		suite, status := resolveSuite(enum)
		if status != statusInvalidParams {
			t.Errorf("resolveSuite(%d) status = %d, want statusInvalidParams", enum, status)
		}
		if suite != nil {
			t.Errorf("resolveSuite(%d) returned a suite; it used to substitute ristretto255", enum)
		}
	}
}

// TestResolveSuite_FIPSRefusalIsDistinguishable matters at the C boundary: a
// caller has to be able to tell "you passed nonsense" from "this build will
// not do that algorithm".
func TestResolveSuite_FIPSRefusalIsDistinguishable(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; the fips CI job runs this")
	}

	if _, status := resolveSuite(suiteRistretto255SHA512); status != statusCiphersuiteNotAllowed {
		t.Errorf("ristretto255 status = %d, want statusCiphersuiteNotAllowed", status)
	}
	if _, status := resolveSuite(99); status != statusInvalidParams {
		t.Errorf("unknown enum status = %d, want statusInvalidParams", status)
	}
	if _, status := resolveSuite(suiteP256SHA256); status != statusOK {
		t.Errorf("p256 status = %d, want statusOK under FIPS", status)
	}
}

func TestResolveService(t *testing.T) {
	svc, status := resolveService(suiteP256SHA256)
	if status != statusOK {
		t.Fatalf("resolveService(p256) status = %d, want statusOK", status)
	}
	if svc == nil {
		t.Fatal("resolveService(p256) returned a nil service")
	}
	if got := svc.GetCiphersuite().ID(); got != string(ciphersuite.P256SHA256) {
		t.Errorf("service carries the suite %q", got)
	}

	if svc, status := resolveService(99); status != statusInvalidParams || svc != nil {
		t.Errorf("resolveService(99) = (%v, %d), want (nil, statusInvalidParams)", svc, status)
	}
}

// TestResolveService_P256EndToEnd exercises the path every exported C
// operation takes, on the one suite available in every runtime mode.
func TestResolveService_P256EndToEnd(t *testing.T) {
	svc, status := resolveService(suiteP256SHA256)
	if status != statusOK {
		t.Fatalf("resolveService status = %d", status)
	}

	suite, _ := resolveSuite(suiteP256SHA256)
	config := frost.Configuration{MinSigners: 2, MaxSigners: 3, Group: suite.Group()}

	keyPackages, groupPublicKey, err := svc.GenerateKeys(config, []frost.Identifier{1, 2, 3})
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	message := []byte("libfrost p256 round trip")
	signature, err := svc.Sign(keyPackages[:2], message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := svc.Verify(message, signature, groupPublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if err := svc.Verify([]byte("a different message"), signature, groupPublicKey); err == nil {
		t.Error("Verify accepted a message that was not signed")
	}
}
