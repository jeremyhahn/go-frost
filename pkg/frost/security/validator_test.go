// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security

import (
	"bytes"
	"errors"
	"testing"
)

// TestNoOpValidator_ValidateStructure tests that NoOpValidator allows all messages.
func TestNoOpValidator_ValidateStructure(t *testing.T) {
	validator := NewNoOpValidator()

	// Should accept any message
	testCases := [][]byte{
		[]byte("valid message"),
		[]byte(""),
		make([]byte, 1024*1024), // 1 MB
		make([]byte, 10*1024*1024), // 10 MB
	}

	for i, msg := range testCases {
		err := validator.ValidateStructure(msg)
		if err != nil {
			t.Errorf("case %d: expected nil, got error: %v", i, err)
		}
	}
}

// TestNoOpValidator_ValidateSize tests that NoOpValidator allows all message sizes.
func TestNoOpValidator_ValidateSize(t *testing.T) {
	validator := NewNoOpValidator()

	// Should accept any size
	testCases := [][]byte{
		[]byte("small"),
		make([]byte, 1024*1024), // 1 MB
		make([]byte, 100*1024*1024), // 100 MB
	}

	for i, msg := range testCases {
		err := validator.ValidateSize(msg)
		if err != nil {
			t.Errorf("case %d: expected nil, got error: %v", i, err)
		}
	}
}

// TestNoOpValidator_ValidatePolicy tests that NoOpValidator allows all messages.
func TestNoOpValidator_ValidatePolicy(t *testing.T) {
	validator := NewNoOpValidator()

	testCases := [][]byte{
		[]byte("any content"),
		[]byte("forbidden words"),
		[]byte("malicious payload"),
	}

	for i, msg := range testCases {
		err := validator.ValidatePolicy(msg)
		if err != nil {
			t.Errorf("case %d: expected nil, got error: %v", i, err)
		}
	}
}

// TestNoOpValidator_Validate tests the convenience method.
func TestNoOpValidator_Validate(t *testing.T) {
	validator := NewNoOpValidator()

	err := validator.Validate(make([]byte, 100*1024*1024))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestSizeValidator_ValidateSize_Success tests successful size validation.
func TestSizeValidator_ValidateSize_Success(t *testing.T) {
	maxSize := 1024 // 1 KB
	validator := NewSizeValidator(maxSize)

	testCases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 100},
		{"exact max", maxSize},
		{"one below max", maxSize - 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := make([]byte, tc.size)
			err := validator.ValidateSize(msg)
			if err != nil {
				t.Errorf("expected nil for size %d, got error: %v", tc.size, err)
			}
		})
	}
}

// TestSizeValidator_ValidateSize_Failure tests size validation failures.
func TestSizeValidator_ValidateSize_Failure(t *testing.T) {
	maxSize := 1024 // 1 KB
	validator := NewSizeValidator(maxSize)

	testCases := []struct {
		name string
		size int
	}{
		{"one over max", maxSize + 1},
		{"much larger", maxSize * 10},
		{"extremely large", maxSize * 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := make([]byte, tc.size)
			err := validator.ValidateSize(msg)
			if err == nil {
				t.Errorf("expected error for size %d, got nil", tc.size)
			}

			if !errors.Is(err, ErrMessageTooLarge) {
				t.Errorf("expected ErrMessageTooLarge, got: %v", err)
			}
		})
	}
}

// TestSizeValidator_ValidateStructure tests that structure validation is a no-op.
func TestSizeValidator_ValidateStructure(t *testing.T) {
	validator := NewSizeValidator(1024)

	// Should always pass (no-op)
	err := validator.ValidateStructure([]byte("any content"))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestSizeValidator_ValidatePolicy tests that policy validation is a no-op.
func TestSizeValidator_ValidatePolicy(t *testing.T) {
	validator := NewSizeValidator(1024)

	// Should always pass (no-op)
	err := validator.ValidatePolicy([]byte("any content"))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestSizeValidator_Validate tests the convenience method.
func TestSizeValidator_Validate(t *testing.T) {
	maxSize := 1024
	validator := NewSizeValidator(maxSize)

	// Should pass for valid size
	err := validator.Validate(make([]byte, maxSize))
	if err != nil {
		t.Errorf("expected nil for valid size, got error: %v", err)
	}

	// Should fail for invalid size
	err = validator.Validate(make([]byte, maxSize+1))
	if err == nil {
		t.Error("expected error for invalid size, got nil")
	}
}

// TestSizeValidator_MaxSize tests the MaxSize getter.
func TestSizeValidator_MaxSize(t *testing.T) {
	maxSize := 2048
	validator := NewSizeValidator(maxSize)

	if validator.MaxSize() != maxSize {
		t.Errorf("expected max size %d, got %d", maxSize, validator.MaxSize())
	}
}

// TestSizeValidator_ProductionDefaults tests recommended production limits.
func TestSizeValidator_ProductionDefaults(t *testing.T) {
	testCases := []struct {
		name    string
		maxSize int
		msgSize int
		valid   bool
	}{
		{"1 MB limit - 500 KB msg", 1024 * 1024, 500 * 1024, true},
		{"1 MB limit - 1 MB msg", 1024 * 1024, 1024 * 1024, true},
		{"1 MB limit - 2 MB msg", 1024 * 1024, 2 * 1024 * 1024, false},
		{"10 MB limit - 5 MB msg", 10 * 1024 * 1024, 5 * 1024 * 1024, true},
		{"10 MB limit - 20 MB msg", 10 * 1024 * 1024, 20 * 1024 * 1024, false},
		{"100 KB limit - 50 KB msg", 100 * 1024, 50 * 1024, true},
		{"100 KB limit - 200 KB msg", 100 * 1024, 200 * 1024, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewSizeValidator(tc.maxSize)
			msg := make([]byte, tc.msgSize)
			err := validator.ValidateSize(msg)

			if tc.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestCompositeValidator_SingleValidator tests composite with one validator.
func TestCompositeValidator_SingleValidator(t *testing.T) {
	sizeValidator := NewSizeValidator(1024)
	composite := NewCompositeValidator(sizeValidator)

	// Should pass
	err := composite.Validate(make([]byte, 512))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}

	// Should fail
	err = composite.Validate(make([]byte, 2048))
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestCompositeValidator_MultipleValidators tests composite with multiple validators.
func TestCompositeValidator_MultipleValidators(t *testing.T) {
	validator1 := NewSizeValidator(1024)
	validator2 := NewSizeValidator(512) // More restrictive

	composite := NewCompositeValidator(validator1, validator2)

	// Should pass both (512 bytes)
	err := composite.Validate(make([]byte, 256))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}

	// Should fail second validator (> 512 bytes)
	err = composite.Validate(make([]byte, 768))
	if err == nil {
		t.Error("expected error from second validator, got nil")
	}
}

// TestCompositeValidator_Add tests adding validators dynamically.
func TestCompositeValidator_Add(t *testing.T) {
	composite := NewCompositeValidator()

	// Initially no validators - should pass anything
	err := composite.Validate(make([]byte, 10*1024*1024))
	if err != nil {
		t.Errorf("expected nil with no validators, got error: %v", err)
	}

	// Add size validator
	composite.Add(NewSizeValidator(1024))

	// Now should enforce size
	err = composite.Validate(make([]byte, 2048))
	if err == nil {
		t.Error("expected error after adding validator, got nil")
	}

	// Should pass valid size
	err = composite.Validate(make([]byte, 512))
	if err != nil {
		t.Errorf("expected nil for valid size, got error: %v", err)
	}
}

// TestCompositeValidator_ValidateStructure tests structure validation.
func TestCompositeValidator_ValidateStructure(t *testing.T) {
	composite := NewCompositeValidator(NewSizeValidator(1024))

	// Should run all validators
	err := composite.ValidateStructure([]byte("test"))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestCompositeValidator_ValidateSize tests size validation.
func TestCompositeValidator_ValidateSize(t *testing.T) {
	composite := NewCompositeValidator(NewSizeValidator(1024))

	// Should enforce size
	err := composite.ValidateSize(make([]byte, 2048))
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// TestCompositeValidator_ValidatePolicy tests policy validation.
func TestCompositeValidator_ValidatePolicy(t *testing.T) {
	composite := NewCompositeValidator(NewSizeValidator(1024))

	// Should run all validators
	err := composite.ValidatePolicy([]byte("test"))
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestCompositeValidator_FailFast tests that validation stops on first error.
func TestCompositeValidator_FailFast(t *testing.T) {
	validator1 := NewSizeValidator(100) // Will fail
	validator2 := NewSizeValidator(1000) // Would pass

	composite := NewCompositeValidator(validator1, validator2)

	// Should fail on first validator
	err := composite.Validate(make([]byte, 500))
	if err == nil {
		t.Error("expected error, got nil")
	}

	// Verify it's from the first validator
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got: %v", err)
	}
}

// mockValidator is a test validator that can be configured to fail.
type mockValidator struct {
	failStructure bool
	failSize      bool
	failPolicy    bool
}

func (m *mockValidator) ValidateStructure(msg []byte) error {
	if m.failStructure {
		return ErrMessageValidationFailed
	}
	return nil
}

func (m *mockValidator) ValidateSize(msg []byte) error {
	if m.failSize {
		return ErrMessageTooLarge
	}
	return nil
}

func (m *mockValidator) ValidatePolicy(msg []byte) error {
	if m.failPolicy {
		return ErrMessageValidationFailed
	}
	return nil
}

func (m *mockValidator) Validate(msg []byte) error {
	if err := m.ValidateStructure(msg); err != nil {
		return err
	}
	if err := m.ValidateSize(msg); err != nil {
		return err
	}
	if err := m.ValidatePolicy(msg); err != nil {
		return err
	}
	return nil
}

// TestCompositeValidator_OrderMatters tests validator execution order.
func TestCompositeValidator_OrderMatters(t *testing.T) {
	mock1 := &mockValidator{failStructure: true}
	mock2 := &mockValidator{failSize: true}

	composite := NewCompositeValidator(mock1, mock2)

	// Should fail with structure error (first validator)
	err := composite.ValidateStructure([]byte("test"))
	if !errors.Is(err, ErrMessageValidationFailed) {
		t.Errorf("expected structure validation error, got: %v", err)
	}

	// Reverse order
	composite2 := NewCompositeValidator(mock2, mock1)
	err = composite2.ValidateStructure([]byte("test"))
	if !errors.Is(err, ErrMessageValidationFailed) {
		t.Errorf("expected structure validation error, got: %v", err)
	}
}

// TestValidator_EmptyMessage tests validation of empty messages.
func TestValidator_EmptyMessage(t *testing.T) {
	validators := []MessageValidator{
		NewNoOpValidator(),
		NewSizeValidator(1024),
		NewCompositeValidator(NewSizeValidator(1024)),
	}

	emptyMsg := []byte{}

	for i, validator := range validators {
		err := validator.Validate(emptyMsg)
		if err != nil {
			t.Errorf("validator %d: expected nil for empty message, got error: %v", i, err)
		}
	}
}

// TestValidator_NilMessage tests validation of nil messages.
func TestValidator_NilMessage(t *testing.T) {
	validators := []MessageValidator{
		NewNoOpValidator(),
		NewSizeValidator(1024),
		NewCompositeValidator(NewSizeValidator(1024)),
	}

	for i, validator := range validators {
		err := validator.Validate(nil)
		if err != nil {
			t.Errorf("validator %d: expected nil for nil message, got error: %v", i, err)
		}
	}
}

// TestValidator_BinaryMessage tests validation of binary (non-text) messages.
func TestValidator_BinaryMessage(t *testing.T) {
	// Create binary message with all byte values
	binaryMsg := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryMsg[i] = byte(i)
	}

	validator := NewSizeValidator(1024)
	err := validator.Validate(binaryMsg)
	if err != nil {
		t.Errorf("expected nil for binary message, got error: %v", err)
	}
}

// TestValidator_LargeMessagePerformance tests validation performance with large messages.
func TestValidator_LargeMessagePerformance(t *testing.T) {
	validator := NewSizeValidator(100 * 1024 * 1024) // 100 MB

	// 10 MB message
	largeMsg := make([]byte, 10*1024*1024)

	// Should complete quickly (size check is O(1))
	err := validator.ValidateSize(largeMsg)
	if err != nil {
		t.Errorf("expected nil, got error: %v", err)
	}
}

// TestSizeValidator_ExactBoundary tests exact size boundaries.
func TestSizeValidator_ExactBoundary(t *testing.T) {
	maxSize := 1000
	validator := NewSizeValidator(maxSize)

	// Test boundary cases
	testCases := []struct {
		size  int
		valid bool
	}{
		{maxSize - 2, true},
		{maxSize - 1, true},
		{maxSize, true},      // Exact match should pass
		{maxSize + 1, false}, // One over should fail
		{maxSize + 2, false},
	}

	for _, tc := range testCases {
		msg := make([]byte, tc.size)
		err := validator.ValidateSize(msg)

		if tc.valid && err != nil {
			t.Errorf("size %d: expected valid, got error: %v", tc.size, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("size %d: expected error, got nil", tc.size)
		}
	}
}

// TestValidator_MessageContent tests that validators don't modify message content.
func TestValidator_MessageContent(t *testing.T) {
	originalMsg := []byte("test message content")
	msg := make([]byte, len(originalMsg))
	copy(msg, originalMsg)

	validators := []MessageValidator{
		NewNoOpValidator(),
		NewSizeValidator(1024),
		NewCompositeValidator(NewSizeValidator(1024)),
	}

	for i, validator := range validators {
		_ = validator.Validate(msg)

		// Verify message wasn't modified
		if !bytes.Equal(msg, originalMsg) {
			t.Errorf("validator %d modified message content", i)
		}
	}
}
