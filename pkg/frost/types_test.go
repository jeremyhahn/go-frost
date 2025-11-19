package frost_test

import (
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
)

// TestSigningNonces_Zeroize tests that nonces are properly zeroized
func TestSigningNonces_Zeroize(t *testing.T) {
	// Setup
	grp := ristretto255.NewGroup()

	// Create two non-zero scalars for testing
	hidingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate hiding nonce: %v", err)
	}

	bindingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate binding nonce: %v", err)
	}

	// Verify nonces are not zero initially
	if hidingNonce.IsZero() {
		t.Fatal("Hiding nonce should not be zero initially")
	}
	if bindingNonce.IsZero() {
		t.Fatal("Binding nonce should not be zero initially")
	}

	// Store original byte values to verify they were non-zero
	originalHidingBytes := make([]byte, len(hidingNonce.Bytes()))
	copy(originalHidingBytes, hidingNonce.Bytes())

	originalBindingBytes := make([]byte, len(bindingNonce.Bytes()))
	copy(originalBindingBytes, bindingNonce.Bytes())

	// Create commitments (these can be zero/identity for this test)
	commitments := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  grp.Identity(),
		BindingNonceCommitment: grp.Identity(),
	}

	// Create SigningNonces
	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitments,
	}

	// Zeroize the nonces
	nonces.Zeroize()

	// Verify nonces are zero after zeroization
	if !nonces.HidingNonce.IsZero() {
		t.Error("Hiding nonce should be zero after Zeroize()")
	}

	if !nonces.BindingNonce.IsZero() {
		t.Error("Binding nonce should be zero after Zeroize()")
	}

	// Verify the bytes are all zeros
	hidingBytes := nonces.HidingNonce.Bytes()
	for i, b := range hidingBytes {
		if b != 0 {
			t.Errorf("Hiding nonce byte %d is not zero: got %d", i, b)
		}
	}

	bindingBytes := nonces.BindingNonce.Bytes()
	for i, b := range bindingBytes {
		if b != 0 {
			t.Errorf("Binding nonce byte %d is not zero: got %d", i, b)
		}
	}

	// Verify original values were actually non-zero (sanity check)
	hasNonZero := false
	for _, b := range originalHidingBytes {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Original hiding nonce bytes were all zero - test may be invalid")
	}

	hasNonZero = false
	for _, b := range originalBindingBytes {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Original binding nonce bytes were all zero - test may be invalid")
	}
}

// TestSigningNonces_Zeroize_NilScalars tests that Zeroize handles nil scalars gracefully
func TestSigningNonces_Zeroize_NilScalars(t *testing.T) {
	grp := ristretto255.NewGroup()

	commitments := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  grp.Identity(),
		BindingNonceCommitment: grp.Identity(),
	}

	// Test with nil HidingNonce
	t.Run("NilHidingNonce", func(t *testing.T) {
		bindingNonce, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("Failed to generate binding nonce: %v", err)
		}

		nonces := frost.SigningNonces{
			HidingNonce:  nil,
			BindingNonce: bindingNonce,
			Commitments:  commitments,
		}

		// Should not panic
		nonces.Zeroize()

		// Verify binding nonce was still zeroized
		if !nonces.BindingNonce.IsZero() {
			t.Error("Binding nonce should be zero after Zeroize()")
		}
	})

	// Test with nil BindingNonce
	t.Run("NilBindingNonce", func(t *testing.T) {
		hidingNonce, err := grp.RandomScalar()
		if err != nil {
			t.Fatalf("Failed to generate hiding nonce: %v", err)
		}

		nonces := frost.SigningNonces{
			HidingNonce:  hidingNonce,
			BindingNonce: nil,
			Commitments:  commitments,
		}

		// Should not panic
		nonces.Zeroize()

		// Verify hiding nonce was still zeroized
		if !nonces.HidingNonce.IsZero() {
			t.Error("Hiding nonce should be zero after Zeroize()")
		}
	})

	// Test with both nil
	t.Run("BothNil", func(t *testing.T) {
		nonces := frost.SigningNonces{
			HidingNonce:  nil,
			BindingNonce: nil,
			Commitments:  commitments,
		}

		// Should not panic
		nonces.Zeroize()
	})
}

// TestSigningNonces_Zeroize_MultipleCallsSafe tests that calling Zeroize multiple times is safe
func TestSigningNonces_Zeroize_MultipleCallsSafe(t *testing.T) {
	grp := ristretto255.NewGroup()

	hidingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate hiding nonce: %v", err)
	}

	bindingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate binding nonce: %v", err)
	}

	commitments := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  grp.Identity(),
		BindingNonceCommitment: grp.Identity(),
	}

	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitments,
	}

	// Call Zeroize multiple times
	nonces.Zeroize()
	nonces.Zeroize()
	nonces.Zeroize()

	// Should still be zero
	if !nonces.HidingNonce.IsZero() {
		t.Error("Hiding nonce should be zero after multiple Zeroize() calls")
	}

	if !nonces.BindingNonce.IsZero() {
		t.Error("Binding nonce should be zero after multiple Zeroize() calls")
	}
}

// TestSigningNonces_Zeroize_Integration tests zeroization in a realistic scenario
func TestSigningNonces_Zeroize_Integration(t *testing.T) {
	// Setup ciphersuite
	suite := ristretto255_sha512.New()
	grp := suite.Group()

	// Generate random nonces as would be done in RoundOne
	hidingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate hiding nonce: %v", err)
	}

	bindingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate binding nonce: %v", err)
	}

	// Create commitments
	hidingCommitment := grp.ScalarBaseMult(hidingNonce)
	bindingCommitment := grp.ScalarBaseMult(bindingNonce)

	commitments := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  hidingCommitment,
		BindingNonceCommitment: bindingCommitment,
	}

	// Create nonces
	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitments,
	}

	// Verify commitments are valid before zeroization
	if hidingCommitment.IsIdentity() {
		t.Error("Hiding commitment should not be identity")
	}
	if bindingCommitment.IsIdentity() {
		t.Error("Binding commitment should not be identity")
	}

	// Store commitment bytes to verify they don't change
	originalHidingCommitment := hidingCommitment.Bytes()
	originalBindingCommitment := bindingCommitment.Bytes()

	// Zeroize nonces
	nonces.Zeroize()

	// Verify nonces are zero
	if !nonces.HidingNonce.IsZero() {
		t.Error("Hiding nonce should be zero after Zeroize()")
	}
	if !nonces.BindingNonce.IsZero() {
		t.Error("Binding nonce should be zero after Zeroize()")
	}

	// Verify commitments are unchanged (we only zeroize nonces, not commitments)
	currentHidingCommitment := nonces.Commitments.HidingNonceCommitment.Bytes()
	currentBindingCommitment := nonces.Commitments.BindingNonceCommitment.Bytes()

	if len(originalHidingCommitment) != len(currentHidingCommitment) {
		t.Error("Hiding commitment length changed after Zeroize()")
	}

	for i := range originalHidingCommitment {
		if originalHidingCommitment[i] != currentHidingCommitment[i] {
			t.Error("Hiding commitment changed after Zeroize() - should remain unchanged")
			break
		}
	}

	if len(originalBindingCommitment) != len(currentBindingCommitment) {
		t.Error("Binding commitment length changed after Zeroize()")
	}

	for i := range originalBindingCommitment {
		if originalBindingCommitment[i] != currentBindingCommitment[i] {
			t.Error("Binding commitment changed after Zeroize() - should remain unchanged")
			break
		}
	}
}

// TestSigningNonces_Zeroize_MemoryCleared tests that the actual bytes are cleared
func TestSigningNonces_Zeroize_MemoryCleared(t *testing.T) {
	grp := ristretto255.NewGroup()

	// Generate nonces
	hidingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate hiding nonce: %v", err)
	}

	bindingNonce, err := grp.RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate binding nonce: %v", err)
	}

	// Get initial byte representations
	hidingBytesBefore := hidingNonce.Bytes()
	bindingBytesBefore := bindingNonce.Bytes()

	// Verify they're not all zeros
	allZeroHiding := true
	for _, b := range hidingBytesBefore {
		if b != 0 {
			allZeroHiding = false
			break
		}
	}

	allZeroBinding := true
	for _, b := range bindingBytesBefore {
		if b != 0 {
			allZeroBinding = false
			break
		}
	}

	if allZeroHiding || allZeroBinding {
		t.Fatal("Generated nonces should not be all zeros")
	}

	// Create nonces struct
	commitments := frost.SigningCommitments{
		Identifier:             1,
		HidingNonceCommitment:  grp.Identity(),
		BindingNonceCommitment: grp.Identity(),
	}

	nonces := frost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments:  commitments,
	}

	// Zeroize
	nonces.Zeroize()

	// Get byte representations after zeroization
	hidingBytesAfter := nonces.HidingNonce.Bytes()
	bindingBytesAfter := nonces.BindingNonce.Bytes()

	// Verify all bytes are zero
	for i, b := range hidingBytesAfter {
		if b != 0 {
			t.Errorf("Hiding nonce byte %d not cleared: expected 0, got %d", i, b)
		}
	}

	for i, b := range bindingBytesAfter {
		if b != 0 {
			t.Errorf("Binding nonce byte %d not cleared: expected 0, got %d", i, b)
		}
	}

	// Verify bytes changed from before to after
	bytesChanged := false
	for i := range hidingBytesBefore {
		if hidingBytesBefore[i] != hidingBytesAfter[i] {
			bytesChanged = true
			break
		}
	}

	if !bytesChanged {
		t.Error("Hiding nonce bytes did not change after Zeroize()")
	}

	bytesChanged = false
	for i := range bindingBytesBefore {
		if bindingBytesBefore[i] != bindingBytesAfter[i] {
			bytesChanged = true
			break
		}
	}

	if !bytesChanged {
		t.Error("Binding nonce bytes did not change after Zeroize()")
	}
}
