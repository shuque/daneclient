// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a stub replacing internal/godebug in this fork of
// crypto/tls. Every setting behaves as if unset: Value always returns "",
// so the code that reads it applies the upstream default. GODEBUG in the
// environment is ignored for the fork's own settings (tlsmlkem,
// tlssecpmlkem, tlssha1, tlsmaxrsasize, fips140ems).
package godebug

// A Setting is a single setting in the $GODEBUG environment variable.
type Setting struct {
	name string
}

// New returns a new Setting for the $GODEBUG setting with the given name.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Name returns the name of the setting.
func (s *Setting) Name() string {
	return s.name
}

// Value returns the current value for the GODEBUG setting s. It is always
// "", meaning unset.
func (s *Setting) Value() string {
	return ""
}

// IncNonDefault is a no-op. Upstream it increments a runtime/metrics
// counter for non-default behaviour.
func (s *Setting) IncNonDefault() {}
