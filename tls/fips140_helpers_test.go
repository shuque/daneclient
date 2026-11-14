// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// isFIPSVersion is copied from upstream fips140_test.go, which the daneclient
// fork removes; tls_test.go still uses it.
func isFIPSVersion(v uint16) bool {
	return v == VersionTLS12 || v == VersionTLS13
}
