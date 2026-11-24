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

	// ErrNotFIPSSelectable is returned when a ciphersuite is selected while
	// the FIPS 140-3 module is enforcing approved-algorithm-only operation
	// (GODEBUG=fips140=only) and this library declines to hand that suite
	// over, because its underlying primitives are not the FIPS-approved ones.
	//
	// The converse does not hold: no FROST suite is FIPS-compliant, since
	// FROST is not an approved signature scheme. See suites.FIPSSelectable.
	ErrNotFIPSSelectable = errors.New("ciphersuite is not selectable under FIPS 140-3 enforcement")
)

// LookupError reports a failure to resolve a ciphersuite identifier. It keeps
// the identifier the caller supplied, which is the part worth reporting back
// when a configuration file or a command line names a suite that does not
// exist, and wraps the reason so errors.Is reaches ErrUnknownCiphersuite and
// ErrNotFIPSSelectable through it.
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
