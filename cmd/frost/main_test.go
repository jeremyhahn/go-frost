package main

import (
	"crypto/fips140"
	"flag"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
)

// subprocessEnv marks the re-executed child in the tests that need to observe
// os.Exit, which cannot be done in-process.
const subprocessEnv = "FROST_TEST_SUBPROCESS"

// runSelfTest re-executes this test binary with only the named test enabled,
// with extra environment applied. It is how the os.Exit paths get asserted.
func runSelfTest(t *testing.T, testName string, extraEnv ...string) (string, int) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), subprocessEnv+"=1")
	cmd.Env = append(cmd.Env, extraEnv...)

	out, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if err != nil {
		if !asExitError(err, &exitErr) {
			t.Fatalf("running child: %v (output: %s)", err, out)
		}
		code = exitErr.ExitCode()
	}
	return string(out), code
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func TestGetCiphersuite_ResolvesNames(t *testing.T) {
	tests := []struct {
		name string
		want ciphersuite.CiphersuiteID
	}{
		{"p256", ciphersuite.P256SHA256},
		{"p256-sha256", ciphersuite.P256SHA256},
		{"FROST-P256-SHA256-v1", ciphersuite.P256SHA256},
		{"ristretto255", ciphersuite.Ristretto255SHA512},
		{"ed25519", ciphersuite.Ed25519SHA512},
		{"ed448", ciphersuite.Ed448SHAKE256},
		{"secp256k1", ciphersuite.Secp256k1SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fips140.Enforced() && !suites.FIPSSelectable(tt.want) {
				t.Skip("refused under fips140=only; covered by TestGetCiphersuite_ExitsOnUnapprovedSuiteUnderFIPS")
			}
			if got := getCiphersuite(tt.name).ID(); got != string(tt.want) {
				t.Errorf("getCiphersuite(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// TestGetCiphersuite_OmittedFlagUsesRuntimeDefault is the assertion behind the
// flag default change: the empty string a subcommand now starts with has to
// land on the library default, and that default has to follow the runtime.
func TestGetCiphersuite_OmittedFlagUsesRuntimeDefault(t *testing.T) {
	want := ciphersuite.Ristretto255SHA512
	if fips140.Enabled() {
		want = ciphersuite.P256SHA256
	}
	if got := getCiphersuite("").ID(); got != string(want) {
		t.Errorf("getCiphersuite(\"\") = %q, want %q (fips140.Enabled() = %t)", got, want, fips140.Enabled())
	}
}

// TestGetCiphersuite_DefaultIsP256UnderFIPS runs the same check in a child
// process under GODEBUG=fips140=only, so the FIPS half is covered even when
// the suite itself is running without FIPS.
func TestGetCiphersuite_DefaultIsP256UnderFIPS(t *testing.T) {
	if os.Getenv(subprocessEnv) == "1" {
		if !fips140.Enabled() {
			t.Fatal("child was expected to run with the FIPS module active")
		}
		if got := getCiphersuite("").ID(); got != string(ciphersuite.P256SHA256) {
			t.Fatalf("under FIPS, an omitted --ciphersuite resolved to %q", got)
		}
		return
	}

	out, code := runSelfTest(t, "TestGetCiphersuite_DefaultIsP256UnderFIPS", "GODEBUG=fips140=only")
	if code != 0 {
		t.Errorf("child exited %d; output:\n%s", code, out)
	}
}

func TestGetCiphersuite_ExitsOnUnknownName(t *testing.T) {
	if os.Getenv(subprocessEnv) == "1" {
		// Must not return: a typo used to warn and carry on with ristretto255.
		getCiphersuite("p-256")
		t.Fatal("getCiphersuite returned for an unknown name instead of exiting")
	}

	out, code := runSelfTest(t, "TestGetCiphersuite_ExitsOnUnknownName")
	if code != 1 {
		t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
	}
	if !strings.Contains(out, "unknown ciphersuite") {
		t.Errorf("stderr did not name the failure; output:\n%s", out)
	}
	if !strings.Contains(out, "p-256") {
		t.Errorf("stderr did not echo the rejected value; output:\n%s", out)
	}
	if !strings.Contains(out, "Supported ciphersuites:") {
		t.Errorf("stderr did not list the accepted values; output:\n%s", out)
	}
}

func TestGetCiphersuite_ExitsOnUnapprovedSuiteUnderFIPS(t *testing.T) {
	if os.Getenv(subprocessEnv) == "1" {
		getCiphersuite("ristretto255")
		t.Fatal("getCiphersuite returned an unapproved suite under fips140=only")
	}

	out, code := runSelfTest(t, "TestGetCiphersuite_ExitsOnUnapprovedSuiteUnderFIPS", "GODEBUG=fips140=only")
	if code != 1 {
		t.Errorf("exit code = %d, want 1; output:\n%s", code, out)
	}
	if !strings.Contains(out, "not selectable under FIPS 140-3 enforcement") {
		t.Errorf("stderr did not give the FIPS reason; output:\n%s", out)
	}
}

// TestAddCiphersuiteFlag_DefaultIsEmpty pins the default to "" — the value
// that means "ask the library". Pinning it to a suite name, as it used to be,
// makes the FIPS default unreachable from the CLI.
func TestAddCiphersuiteFlag_DefaultIsEmpty(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	value := addCiphersuiteFlag(fs)

	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parsing no arguments: %v", err)
	}
	if *value != "" {
		t.Errorf("default = %q, want the empty string", *value)
	}

	f := fs.Lookup("ciphersuite")
	if f == nil {
		t.Fatal("the flag is not named \"ciphersuite\"")
	}
	if f.DefValue != "" {
		t.Errorf("DefValue = %q, want the empty string", f.DefValue)
	}
}

func TestAddCiphersuiteFlag_ParsesAValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	value := addCiphersuiteFlag(fs)

	if err := fs.Parse([]string{"--ciphersuite", "p256"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if *value != "p256" {
		t.Errorf("parsed %q, want \"p256\"", *value)
	}
}

// TestEverySubcommandUsesTheSharedFlag guards the regression Codex named: one
// subcommand keeping its own declaration, and so its own default, while the
// other five move. The helper is the only place the flag may be declared.
func TestEverySubcommandUsesTheSharedFlag(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}

	raw := regexp.MustCompile(`fs\.String\("ciphersuite"`)
	if got := len(raw.FindAll(source, -1)); got != 1 {
		t.Errorf("found %d raw --ciphersuite declarations, want exactly 1 (inside addCiphersuiteFlag)", got)
	}

	// Every subcommand that resolves a suite must have obtained its flag from
	// the helper, so the counts have to agree.
	uses := len(regexp.MustCompile(`addCiphersuiteFlag\(fs\)`).FindAll(source, -1))
	resolves := len(regexp.MustCompile(`getCiphersuite\(\*ciphersuiteFlag\)`).FindAll(source, -1))
	if uses != resolves {
		t.Errorf("%d subcommands declare the flag but %d resolve it", uses, resolves)
	}
	if uses == 0 {
		t.Error("no subcommand declares the flag; the guard would pass vacuously")
	}
}

func TestGetSupportedCiphersuites(t *testing.T) {
	got := getSupportedCiphersuites()

	for _, id := range suites.List() {
		if !strings.Contains(got, suites.ShortName(id)) {
			t.Errorf("help text omits %q", suites.ShortName(id))
		}
		if !strings.Contains(got, string(id)) {
			t.Errorf("help text omits the identifier %q", id)
		}
	}

	if !strings.Contains(got, "[FIPS-selectable]") {
		t.Error("help text does not mark the FIPS-selectable suite")
	}
	// The label must claim selectability only. FROST is not an approved
	// signature scheme, so any "approved" wording here would be false.
	if strings.Contains(got, "approved") {
		t.Errorf("help text claims FIPS approval:\n%s", got)
	}

	if lines := strings.Split(got, "\n"); len(lines) != len(suites.List()) {
		t.Errorf("help text has %d lines for %d suites", len(lines), len(suites.List()))
	}
	if !strings.Contains(got, "[default]") {
		t.Error("help text does not mark the runtime default")
	}
}
