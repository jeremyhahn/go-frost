// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package storage

import "errors"

// ErrNotFound is returned when a storage key is not found.
//
// Compatible with go-xkms's storage.ErrNotFound.
var ErrNotFound = errors.New("storage: key not found")

// ErrAlreadyExists is returned when attempting to create a key that already exists.
var ErrAlreadyExists = errors.New("storage: key already exists")

// ErrInvalidKey is returned when a storage key is invalid.
var ErrInvalidKey = errors.New("storage: invalid key")

// ErrPermissionDenied is returned when a storage operation is not permitted.
var ErrPermissionDenied = errors.New("storage: permission denied")

// ErrStorageClosed is returned when attempting to use a closed storage backend.
var ErrStorageClosed = errors.New("storage: backend is closed")
