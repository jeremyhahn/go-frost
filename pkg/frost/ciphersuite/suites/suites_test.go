package suites_test

import (
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
)

func TestParse_ResolvesEverySpelling(t *testing.T) {
	tests := []struct {
		name string
		want ciphersuite.CiphersuiteID
	}{
		{"ristretto255", ciphersuite.Ristretto255SHA512},
		{"ristretto255-sha512", ciphersuite.Ristretto255SHA512},
		{"FROST-RISTRETTO255-SHA512-v1", ciphersuite.Ristretto255SHA512},
		{"ed25519", ciphersuite.Ed25519SHA512},
		{"ed25519-sha512", ciphersuite.Ed25519SHA512},
		{"FROST-ED25519-SHA512-v1", ciphersuite.Ed25519SHA512},
		{"ed448", ciphersuite.Ed448SHAKE256},
		{"ed448-shake256", ciphersuite.Ed448SHAKE256},
		{"FROST-ED448-SHAKE256-v1", ciphersuite.Ed448SHAKE256},
		{"p256", ciphersuite.P256SHA256},
		{"p256-sha256", ciphersuite.P256SHA256},
		{"FROST-P256-SHA256-v1", ciphersuite.P256SHA256},
		{"secp256k1", ciphersuite.Secp256k1SHA256},
		{"secp256k1-sha256", ciphersuite.Secp256k1SHA256},
		{"FROST-secp256k1-SHA256-v1", ciphersuite.Secp256k1SHA256},
		// RFC 9591 spells secp256k1 in lower case and the other four in upper.
		// A consumer that upper-cases them uniformly must still resolve.
		{"FROST-SECP256K1-SHA256-v1", ciphersuite.Secp256k1SHA256},
		{"P256", ciphersuite.P256SHA256},
		{"  p256  ", ciphersuite.P256SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := suites.Parse(tt.name)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tt.name, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestParse_EmptyResolvesToDefault(t *testing.T) {
	for _, name := range []string{"", "   "} {
		got, err := suites.Parse(name)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", name, err)
		}
		if got != suites.Default() {
			t.Errorf("Parse(%q) = %q, want the default %q", name, got, suites.Default())
		}
	}
}

func TestParse_UnknownIsTyped(t *testing.T) {
	for _, name := range []string{"p-256", "curve25519", "FROST-P256-SHA256-v2"} {
		t.Run(name, func(t *testing.T) {
			got, err := suites.Parse(name)
			if err == nil {
				t.Fatalf("Parse(%q) = %q, want an error", name, got)
			}
			if !errors.Is(err, ciphersuite.ErrUnknownCiphersuite) {
				t.Errorf("Parse(%q) error = %v, want ErrUnknownCiphersuite", name, err)
			}

			var lookupErr *ciphersuite.LookupError
			if !errors.As(err, &lookupErr) {
				t.Fatalf("Parse(%q) error = %v, want a *LookupError", name, err)
			}
			// The reported identifier is what the caller typed, not a
			// normalized form — it is the part worth putting in a message.
			if lookupErr.ID != name {
				t.Errorf("LookupError.ID = %q, want %q", lookupErr.ID, name)
			}
		})
	}
}

func TestGet_ResolvesEveryStandardSuiteToItself(t *testing.T) {
	for _, id := range suites.List() {
		t.Run(string(id), func(t *testing.T) {
			suite, err := suites.Get(id)

			if fips140.Enforced() && !suites.FIPSSelectable(id) {
				if !errors.Is(err, ciphersuite.ErrNotFIPSSelectable) {
					t.Fatalf("Get(%q) under fips140=only: err = %v, want ErrNotFIPSSelectable", id, err)
				}
				if suite != nil {
					t.Errorf("Get(%q) returned a suite alongside an error", id)
				}
				return
			}

			if err != nil {
				t.Fatalf("Get(%q) returned error: %v", id, err)
			}
			if suite == nil {
				t.Fatalf("Get(%q) returned a nil ciphersuite", id)
			}
			// Catches a mis-wired constructor table, which is exactly the
			// class of defect a name-to-suite switch has produced before.
			if suite.ID() != string(id) {
				t.Errorf("Get(%q) returned the suite %q", id, suite.ID())
			}
			if suite.Group() == nil {
				t.Errorf("Get(%q) returned a suite with no group", id)
			}
		})
	}
}

func TestGet_UnknownIsTyped(t *testing.T) {
	suite, err := suites.Get(ciphersuite.CiphersuiteID("FROST-BLS12381-SHA256-v1"))
	if err == nil {
		t.Fatal("Get on an unregistered identifier returned no error")
	}
	if suite != nil {
		t.Error("Get on an unregistered identifier returned a suite alongside an error")
	}
	if !errors.Is(err, ciphersuite.ErrUnknownCiphersuite) {
		t.Errorf("error = %v, want ErrUnknownCiphersuite", err)
	}
}

// TestGet_P256IsAlwaysSelectable pins the property issue #12 exists for: the
// one FIPS-approved suite resolves in every runtime mode, never nil.
func TestGet_P256IsAlwaysSelectable(t *testing.T) {
	suite, err := suites.Get(ciphersuite.P256SHA256)
	if err != nil {
		t.Fatalf("Get(P256SHA256) returned error: %v", err)
	}
	if suite == nil {
		t.Fatal("Get(P256SHA256) returned a nil ciphersuite")
	}
	if suite.ID() != string(ciphersuite.P256SHA256) {
		t.Errorf("Get(P256SHA256) returned the suite %q", suite.ID())
	}
}

func TestByName(t *testing.T) {
	suite, err := suites.ByName("p256")
	if err != nil {
		t.Fatalf("ByName(\"p256\") returned error: %v", err)
	}
	if suite.ID() != string(ciphersuite.P256SHA256) {
		t.Errorf("ByName(\"p256\") returned the suite %q", suite.ID())
	}

	if _, err := suites.ByName("nonsense"); !errors.Is(err, ciphersuite.ErrUnknownCiphersuite) {
		t.Errorf("ByName(\"nonsense\") error = %v, want ErrUnknownCiphersuite", err)
	}
}

func TestList_IsCompleteAndOwnedByTheCaller(t *testing.T) {
	got := suites.List()
	if len(got) != 5 {
		t.Fatalf("List() returned %d ciphersuites, want the 5 RFC 9591 defines", len(got))
	}

	seen := make(map[ciphersuite.CiphersuiteID]bool, len(got))
	for _, id := range got {
		if seen[id] {
			t.Errorf("List() reported %q twice", id)
		}
		seen[id] = true
	}
	for _, want := range []ciphersuite.CiphersuiteID{
		ciphersuite.Ristretto255SHA512,
		ciphersuite.Ed25519SHA512,
		ciphersuite.Ed448SHAKE256,
		ciphersuite.P256SHA256,
		ciphersuite.Secp256k1SHA256,
	} {
		if !seen[want] {
			t.Errorf("List() omitted %q", want)
		}
	}

	got[0] = ciphersuite.CiphersuiteID("scribbled")
	if suites.List()[0] == ciphersuite.CiphersuiteID("scribbled") {
		t.Error("List() handed out the package's own slice")
	}
}

func TestFIPSSelectable(t *testing.T) {
	if !suites.FIPSSelectable(ciphersuite.P256SHA256) {
		t.Error("FIPSSelectable(P256SHA256) = false, want true")
	}
	for _, id := range []ciphersuite.CiphersuiteID{
		ciphersuite.Ristretto255SHA512,
		ciphersuite.Ed25519SHA512,
		ciphersuite.Ed448SHAKE256,
		ciphersuite.Secp256k1SHA256,
		ciphersuite.CiphersuiteID("FROST-BLS12381-SHA256-v1"),
	} {
		if suites.FIPSSelectable(id) {
			t.Errorf("FIPSSelectable(%q) = true, want false", id)
		}
	}
}

func TestShortName(t *testing.T) {
	if got := suites.ShortName(ciphersuite.P256SHA256); got != "p256" {
		t.Errorf("ShortName(P256SHA256) = %q, want \"p256\"", got)
	}

	// An identifier with no short spelling reports itself rather than "".
	unknown := ciphersuite.CiphersuiteID("FROST-BLS12381-SHA256-v1")
	if got := suites.ShortName(unknown); got != string(unknown) {
		t.Errorf("ShortName(%q) = %q, want the identifier itself", unknown, got)
	}

	// Every listed suite round-trips through Parse.
	for _, id := range suites.List() {
		got, err := suites.Parse(suites.ShortName(id))
		if err != nil {
			t.Errorf("Parse(ShortName(%q)) returned error: %v", id, err)
			continue
		}
		if got != id {
			t.Errorf("Parse(ShortName(%q)) = %q", id, got)
		}
	}
}

// TestDefault_TracksTheRuntimeMode covers both halves of the owner ruling: a
// FIPS-active runtime defaults new ceremonies to P-256, and every other
// runtime keeps the RFC-aligned ristretto255 default so existing shares are
// unaffected.
func TestDefault_TracksTheRuntimeMode(t *testing.T) {
	got := suites.Default()

	want := ciphersuite.Ristretto255SHA512
	if fips140.Enabled() {
		want = ciphersuite.P256SHA256
	}
	if got != want {
		t.Errorf("Default() = %q, want %q (fips140.Enabled() = %t)", got, want, fips140.Enabled())
	}

	// The default must always be selectable, or a caller expressing no
	// preference cannot start a ceremony at all.
	if _, err := suites.Get(got); err != nil {
		t.Errorf("Get(Default()) returned error: %v", err)
	}
}
