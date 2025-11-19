// Copyright (c) 2025 go-frost authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package security_test

import (
	"fmt"

	"github.com/jeremyhahn/go-frost/pkg/frost/security"
)

// Example_errorSanitization_Production demonstrates error sanitization in production mode.
// Sensitive cryptographic data is completely redacted to prevent information leakage.
func Example_errorSanitization_Production() {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	// Example 1: Hex values are redacted
	err1 := fmt.Errorf("signature verification failed: scalar=0x1234567890abcdef1234567890abcdef")
	sanitized1 := sanitizer.Sanitize(err1)
	fmt.Println("Production mode (hex):", sanitized1.Error())

	// Example 2: Commitment values are redacted
	err2 := fmt.Errorf("hiding=0xabcdefabcdefabcdefabcdef, binding=0x9876543210987654")
	sanitized2 := sanitizer.Sanitize(err2)
	fmt.Println("Production mode (commitment):", sanitized2.Error())

	// Example 3: Multiple sensitive values
	err3 := fmt.Errorf("error: nonce=secret_value, session abc-123")
	sanitized3 := sanitizer.Sanitize(err3)
	fmt.Println("Production mode (multiple):", sanitized3.Error())

	// Output:
	// Production mode (hex): signature verification failed: scalar=[REDACTED]
	// Production mode (commitment): hiding=[REDACTED], binding=[REDACTED]
	// Production mode (multiple): error: nonce=[REDACTED], session: [REDACTED]
}

// Example_errorSanitization_Development demonstrates error sanitization in development mode.
// Sensitive data is redacted but length information is preserved for debugging.
func Example_errorSanitization_Development() {
	sanitizer := security.NewErrorSanitizer(security.DefaultDevelopmentErrorConfig())

	// Example 1: Standalone hex values show length
	err1 := fmt.Errorf("error with hex: 0x1234567890abcdef1234567890abcdef")
	sanitized1 := sanitizer.Sanitize(err1)
	fmt.Println("Development mode (standalone hex):", sanitized1.Error())

	// Example 2: Field values are redacted but field names preserved
	err2 := fmt.Errorf("hiding=0xabcdefabcdefabcdefabcdef")
	sanitized2 := sanitizer.Sanitize(err2)
	fmt.Println("Development mode (field):", sanitized2.Error())

	// Example 3: Session IDs are preserved in development
	err3 := fmt.Errorf("session abc-123-def failed")
	sanitized3 := sanitizer.Sanitize(err3)
	fmt.Println("Development mode (session):", sanitized3.Error())

	// Output:
	// Development mode (standalone hex): error with hex: [HEX:34]
	// Development mode (field): hiding=[REDACTED]
	// Development mode (session): session abc-123-def failed
}

// Example_errorSanitization_CommitmentError demonstrates sanitized commitment errors.
func Example_errorSanitization_CommitmentError() {
	sanitizer := security.NewErrorSanitizer(security.DefaultProductionErrorConfig())

	// Create a sanitized commitment error
	err := sanitizer.SanitizeCommitmentError("session-123", 42, security.ErrCommitmentReused)
	fmt.Println("Commitment error:", err.Error())

	// Output:
	// Commitment error: commitment validation failed for participant 42: commitment reused - CRITICAL security violation: commitment reused - CRITICAL security violation
}

// Example_errorSanitization_Global demonstrates using the global sanitizer.
func Example_errorSanitization_Global() {
	// Set global sanitizer to development mode
	security.SetGlobalSanitizer(security.NewErrorSanitizer(security.DefaultDevelopmentErrorConfig()))

	// Use the global SanitizeError function
	err := fmt.Errorf("error with data: 0x1234567890abcdef1234567890abcdef")
	sanitized := security.SanitizeError(err)
	fmt.Println("Global sanitizer:", sanitized.Error())

	// Reset to production mode (recommended for production environments)
	security.SetGlobalSanitizer(security.NewErrorSanitizer(security.DefaultProductionErrorConfig()))

	// Output:
	// Global sanitizer: error with data: [HEX:34]
}
