// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boring is a stub replacing crypto/internal/boring in this fork of
// crypto/tls. BoringCrypto is not supported: Enabled is always false, and the
// BoringCrypto-only entry points panic.
package boring

import "crypto/cipher"

// Enabled reports whether BoringCrypto is in use. It is always false.
const Enabled = false

// Unreachable marks code that should be unreachable when BoringCrypto is in
// use. It is a no-op without BoringCrypto.
func Unreachable() {}

func NewGCMTLS(cipher.Block) (cipher.AEAD, error)   { panic("boringcrypto: not available") }
func NewGCMTLS13(cipher.Block) (cipher.AEAD, error) { panic("boringcrypto: not available") }
