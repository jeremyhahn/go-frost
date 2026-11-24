// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package storage provides thread-safe memory and file Backends compatible with go-xkms and go-objstore; the file backend writes atomically with 0600 files and rejects ".." in keys.
package storage
