package ciphersuite

import (
	"errors"
	"strconv"
)

// Errors reported when a ciphersuite identifier cannot be resolved. They are
// sentinels so a caller can classify the failure with errors.Is without
// depending on whichever lookup produced it.
var (
	// ErrUnknownCiphersuite is returned when an identifier names no ciphersuite.
	ErrUnknownCiphersuite = errors.New("unknown ciphersuite")

	// ErrNotFIPSSelectable is returned for a suite this library withholds under GODEBUG=fips140=only; no FROST suite is FIPS-approved.
	ErrNotFIPSSelectable = errors.New("ciphersuite is not selectable under FIPS 140-3 enforcement")
)

// LookupError reports the unresolved ciphersuite identifier and wraps ErrUnknownCiphersuite or ErrNotFIPSSelectable.
type LookupError struct {
	// ID is the identifier or alias the caller supplied.
	ID string

	// Err is the reason the lookup failed.
	Err error
}

func (e *LookupError) Error() string {
	return "ciphersuite " + strconv.Quote(e.ID) + ": " + e.Err.Error()
}

func (e *LookupError) Unwrap() error {
	return e.Err
}

// NewLookupError creates a new LookupError for the given identifier.
func NewLookupError(id string, err error) *LookupError {
	return &LookupError{
		ID:  id,
		Err: err,
	}
}
