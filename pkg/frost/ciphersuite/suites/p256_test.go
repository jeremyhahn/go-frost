package suites_test

import (
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/suites"
	"github.com/jeremyhahn/go-frost/pkg/frost/service"
)

// RFC 9591 Appendix E.4, FROST(P-256, SHA-256). The full vector — shares,
// nonces, binding factors and signature shares — drives the protocol-step
// suite in test/testvectors, which is dark on shared runners (company task
// #49). The three values below are the ones that make a self-contained
// known-answer check, and they run wherever ./pkg/... runs, including the
// FIPS job.
const (
	rfc9591E4GroupPublicKey = "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70"
	rfc9591E4Message        = "74657374"
	rfc9591E4Signature      = "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return b
}

// TestP256_RFC9591AppendixE4 checks the suite reached through the selection
// API against the published RFC 9591 vector, so a mis-wired lookup cannot
// pass by returning some other working suite.
func TestP256_RFC9591AppendixE4(t *testing.T) {
	suite, err := suites.Get(ciphersuite.P256SHA256)
	if err != nil {
		t.Fatalf("Get(P256SHA256) returned error: %v", err)
	}

	if got := suite.ContextString(); got != "FROST-P256-SHA256-v1" {
		t.Errorf("ContextString() = %q, want the RFC 9591 §6.4 context string", got)
	}

	publicKey, err := suite.Group().DeserializeElement(mustDecodeHex(t, rfc9591E4GroupPublicKey))
	if err != nil {
		t.Fatalf("deserializing the vector group public key: %v", err)
	}

	message := mustDecodeHex(t, rfc9591E4Message)
	signature := mustDecodeHex(t, rfc9591E4Signature)

	if err := suite.VerifySignature(message, signature, publicKey); err != nil {
		t.Errorf("the RFC 9591 §E.4 signature did not verify: %v", err)
	}

	t.Run("RejectsAnAlteredMessage", func(t *testing.T) {
		altered := append([]byte(nil), message...)
		altered[0] ^= 0x01
		if err := suite.VerifySignature(altered, signature, publicKey); err == nil {
			t.Error("verification accepted an altered message")
		}
	})

	t.Run("RejectsAnAlteredSignature", func(t *testing.T) {
		altered := append([]byte(nil), signature...)
		altered[len(altered)-1] ^= 0x01
		if err := suite.VerifySignature(message, altered, publicKey); err == nil {
			t.Error("verification accepted an altered signature")
		}
	})
}

// TestP256_EndToEndThroughSelection is issue #12's verification: a complete
// 2-of-3 keygen, sign and verify on the suite obtained by name, which is the
// path a FIPS ceremony takes. Under GODEBUG=fips140=only this is the only
// suite that can run it at all.
func TestP256_EndToEndThroughSelection(t *testing.T) {
	suite, err := suites.ByName("p256")
	if err != nil {
		t.Fatalf("ByName(\"p256\") returned error: %v", err)
	}

	svc := service.NewFrostService(suite)
	config := frost.Configuration{
		MinSigners: 2,
		MaxSigners: 3,
		Group:      suite.Group(),
	}
	participants := []frost.Identifier{1, 2, 3}

	keyPackages, groupPublicKey, err := svc.GenerateKeys(config, participants)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if len(keyPackages) != len(participants) {
		t.Fatalf("GenerateKeys returned %d key packages, want %d", len(keyPackages), len(participants))
	}

	for _, keyPackage := range keyPackages {
		if err := svc.VerifyKeyShare(keyPackage); err != nil {
			t.Fatalf("VerifyKeyShare for participant %d: %v", keyPackage.Identifier, err)
		}
	}

	message := []byte("p256 threshold ceremony")
	signature, err := svc.Sign(keyPackages[:config.MinSigners], message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := svc.Verify(message, signature, groupPublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	t.Run("RejectsAnAlteredMessage", func(t *testing.T) {
		if err := svc.Verify([]byte("p256 threshold ceremonY"), signature, groupPublicKey); err == nil {
			t.Error("Verify accepted a message that was not signed")
		}
	})
}
