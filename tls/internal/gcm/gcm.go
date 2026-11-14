// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gcm replaces the TLS-specific constructors of
// crypto/internal/fips140/aes/gcm in this fork of crypto/tls.
//
// Upstream, NewGCMForTLS12 and NewGCMForTLS13 wrap AES-GCM with checks that
// the caller's nonces follow the TLS construction (RFC 5288 / RFC 8446),
// panicking otherwise. Those checks exist for FIPS 140-3 compliance and do
// not affect the output, so here both are plain cipher.NewGCM. The record
// layer in crypto/tls constructs the nonces itself.
package gcm

import "crypto/cipher"

// NewGCMForTLS12 returns AES-GCM for use as a TLS 1.2 record AEAD.
func NewGCMForTLS12(b cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(b)
}

// NewGCMForTLS13 returns AES-GCM for use as a TLS 1.3 record AEAD.
func NewGCMForTLS13(b cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(b)
}
