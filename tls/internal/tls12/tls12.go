// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls12 implements the TLS 1.2 PRF and extended master secret.
//
// This is a copy of crypto/internal/fips140/tls12 for the daneclient fork of
// crypto/tls, using the public crypto/hmac package. The FIPS 140-3 service
// indicator calls are dropped.
package tls12

import (
	"crypto/hmac"
	"hash"
)

// PRF implements the TLS 1.2 pseudo-random function, as defined in RFC 5246,
// Section 5 and allowed by SP 800-135, Revision 1, Section 4.2.2.
func PRF[H hash.Hash](hash func() H, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(hash, result, secret, labelAndSeed)
	return result
}

// pHash implements the P_hash function, as defined in RFC 5246, Section 5.
func pHash[H hash.Hash](hash func() H, result, secret, seed []byte) {
	h := hmac.New(asHashFunc(hash), secret)
	h.Write(seed)
	a := h.Sum(nil)

	for len(result) > 0 {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		n := copy(result, b)
		result = result[n:]

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// asHashFunc adapts a typed hash constructor to the func() hash.Hash form
// that the public crypto/hmac expects.
func asHashFunc[H hash.Hash](h func() H) func() hash.Hash {
	return func() hash.Hash { return h() }
}

const masterSecretLength = 48
const extendedMasterSecretLabel = "extended master secret"

// MasterSecret implements the TLS 1.2 extended master secret derivation, as
// defined in RFC 7627 and allowed by SP 800-135, Revision 1, Section 4.2.2.
func MasterSecret[H hash.Hash](hash func() H, preMasterSecret, transcript []byte) []byte {
	return PRF(hash, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}
