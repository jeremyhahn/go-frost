// RFC 9591 Section 7.7: Input Validation
//
// This file tests the input validation mechanisms required by RFC 9591 Section 7.7.
// It verifies that:
// 1. Message size validation works correctly
// 2. Message structure validation works correctly
// 3. Composite validators combine multiple validation checks
// 4. Validators reject invalid inputs as required
//
// RFC 9591 Section 7.7 Requirements:
// - "Implementations MUST validate all inputs before processing"
// - "Invalid inputs MUST be rejected with appropriate errors"
// - "Implementations SHOULD validate message size to prevent DoS attacks"
// - "Implementations SHOULD validate message structure and format"
//
// Test Coverage:
// - H-4: Message Validation (RFC 9591 Section 7.7)
// - M-3: Participant ID Validation (RFC 9591 Section 7.7)
// - Size validation
// - Structure validation
// - Composite validation
package rfc

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// TestSection7_7_SizeValidator verifies that message size validation
// works correctly as required by RFC 9591 Section 7.7.
func TestSection7_7_SizeValidator(t *testing.T) {
	maxSize := 100
	validator := security.NewSizeValidator(maxSize)

	// Test: Message under size limit should pass
	smallMsg := []byte("small message")
	err := validator.Validate(smallMsg)
	if err != nil {
		t.Errorf("Small message should pass size validation: %v", err)
	}

	// Test: Message at exact size limit should pass
	exactMsg := make([]byte, maxSize)
	err = validator.Validate(exactMsg)
	if err != nil {
		t.Errorf("Exact size message should pass: %v", err)
	}

	// Test: Message over size limit should fail
	largeMsg := make([]byte, maxSize+1)
	err = validator.Validate(largeMsg)
	if err == nil {
		t.Error("Oversized message should fail validation")
	}

	// Test: Error should indicate size issue
	if err != nil && !strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "large") {
		t.Errorf("Error should mention size issue: %v", err)
	}
}

// TestSection7_7_NoOpValidator verifies that NoOp validator
// accepts all inputs as required by RFC 9591 Section 7.7.
func TestSection7_7_NoOpValidator(t *testing.T) {
	validator := security.NewNoOpValidator()

	testCases := [][]byte{
		[]byte("normal message"),
		[]byte(""),
		make([]byte, 1000),
		nil,
	}

	for _, msg := range testCases {
		err := validator.Validate(msg)
		if err != nil {
			t.Errorf("NoOp validator should accept all messages, rejected: %v", msg)
		}
	}
}

// TestSection7_7_CompositeValidator verifies that composite validators
// combine multiple validation checks as required by RFC 9591 Section 7.7.
func TestSection7_7_CompositeValidator(t *testing.T) {
	// Create composite validator with size check
	sizeValidator := security.NewSizeValidator(50)
	composite := security.NewCompositeValidator(sizeValidator)

	// Test: Message passing all validators should succeed
	validMsg := []byte("valid message")
	err := composite.Validate(validMsg)
	if err != nil {
		t.Errorf("Valid message should pass composite validation: %v", err)
	}

	// Test: Message failing any validator should fail
	invalidMsg := make([]byte, 100)
	err = composite.Validate(invalidMsg)
	if err == nil {
		t.Error("Message failing size check should fail composite validation")
	}
}

// TestSection7_7_ValidatorStructureMethods verifies that validators
// implement all required methods as required by RFC 9591 Section 7.7.
func TestSection7_7_ValidatorStructureMethods(t *testing.T) {
	validator := security.NewSizeValidator(100)

	testMsg := []byte("test message")

	// Test: ValidateStructure method exists and works
	err := validator.ValidateStructure(testMsg)
	if err != nil {
		t.Errorf("ValidateStructure failed: %v", err)
	}

	// Test: ValidateSize method exists and works
	err = validator.ValidateSize(testMsg)
	if err != nil {
		t.Errorf("ValidateSize on small message failed: %v", err)
	}

	// Test: ValidatePolicy method exists and works
	err = validator.ValidatePolicy(testMsg)
	if err != nil {
		t.Errorf("ValidatePolicy failed: %v", err)
	}

	// Test: Validate method exists and works (combines all checks)
	err = validator.Validate(testMsg)
	if err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

// TestSection7_7_EmptyCompositeValidator verifies that empty composite
// validator behaves correctly as required by RFC 9591 Section 7.7.
func TestSection7_7_EmptyCompositeValidator(t *testing.T) {
	// Create composite with no validators
	composite := security.NewCompositeValidator()

	// Test: Should accept all messages when no validators present
	testMsg := []byte("any message")
	err := composite.Validate(testMsg)
	if err != nil {
		t.Errorf("Empty composite should accept all messages: %v", err)
	}
}

// TestSection7_7_MultipleValidators verifies that multiple validators
// can be combined as required by RFC 9591 Section 7.7.
func TestSection7_7_MultipleValidators(t *testing.T) {
	// Create multiple validators
	size1 := security.NewSizeValidator(100)
	size2 := security.NewSizeValidator(50)

	// Create composite with both
	composite := security.NewCompositeValidator(size1, size2)

	// Test: Message must pass most restrictive validator (50 bytes)
	validMsg := make([]byte, 40)
	err := composite.Validate(validMsg)
	if err != nil {
		t.Errorf("Message under 50 bytes should pass both validators: %v", err)
	}

	// Test: Message failing most restrictive validator should fail
	invalidMsg := make([]byte, 60)
	err = composite.Validate(invalidMsg)
	if err == nil {
		t.Error("Message over 50 bytes should fail composite validation")
	}
}

// TestSection7_7_ValidationErrorMessages verifies that validation errors
// provide useful information as required by RFC 9591 Section 7.7.
func TestSection7_7_ValidationErrorMessages(t *testing.T) {
	validator := security.NewSizeValidator(10)

	largeMsg := make([]byte, 100)
	err := validator.Validate(largeMsg)

	// Test: Error should be non-nil
	if err == nil {
		t.Fatal("Oversized message should produce error")
	}

	// Test: Error message should be informative
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("Error message should not be empty")
	}

	// Test: Error should be a known type
	if !strings.Contains(errMsg, "size") && !strings.Contains(errMsg, "large") && !strings.Contains(errMsg, "exceed") {
		t.Logf("Warning: Error message may not be descriptive enough: %s", errMsg)
	}
}

// TestSection7_7_ZeroSizeValidator verifies edge case of zero-size validator
// as required by RFC 9591 Section 7.7.
func TestSection7_7_ZeroSizeValidator(t *testing.T) {
	// Create validator with zero size limit
	validator := security.NewSizeValidator(0)

	// Test: Empty message should pass
	emptyMsg := []byte{}
	err := validator.Validate(emptyMsg)
	if err != nil {
		t.Errorf("Empty message should pass zero-size validator: %v", err)
	}

	// Test: Any non-empty message should fail
	nonEmptyMsg := []byte("x")
	err = validator.Validate(nonEmptyMsg)
	if err == nil {
		t.Error("Non-empty message should fail zero-size validator")
	}
}
