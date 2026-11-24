// Copyright (c) 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package signer adapts software Ed25519, HSM, TPM, KMS and go-xkms keys to a crypto.Signer-compatible Signer; MultiSigner is not thread-safe.
package signer
