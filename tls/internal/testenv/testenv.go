// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testenv is a minimal test-only stand-in for internal/testenv,
// providing just the helpers used by the upstream crypto/tls tests kept in
// this fork.
package testenv

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// forkGODEBUG lists the GODEBUG settings that the fork reads through its
// internal/godebug stub. That stub always reports them as unset, so a test
// that sets one cannot observe the change and is skipped.
var forkGODEBUG = map[string]bool{
	"tlsmlkem":      true,
	"tlssecpmlkem":  true,
	"tlssha1":       true,
	"tlsmaxrsasize": true,
	"fips140ems":    true,
}

// SetGODEBUG appends v to the GODEBUG environment variable for the duration
// of the test, as upstream does. Settings owned by the standard library (for
// example rsa1024min) still take effect. If v names a setting that the fork
// stubs out, the test is skipped instead.
func SetGODEBUG(t testing.TB, v string) {
	t.Helper()
	for kv := range strings.SplitSeq(v, ",") {
		name, _, _ := strings.Cut(kv, "=")
		if forkGODEBUG[name] {
			t.Skipf("skipping test: GODEBUG %s is not supported by the daneclient tls fork", name)
		}
	}
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+","+v)
}

// MustHaveSource is a no-op: the fork's sources are always present in the
// module. (Upstream checks that GOROOT/src is available.)
func MustHaveSource(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "ios" {
		t.Skip("skipping test: no source tree on " + runtime.GOOS)
	}
}

// MustHaveExternalNetwork checks that the current system can use
// external (non-localhost) networks.
// If not, MustHaveExternalNetwork calls t.Skip with an explanation.
func MustHaveExternalNetwork(t testing.TB) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Helper()
		t.Skipf("skipping test: no external network on %s", runtime.GOOS)
	}
	if testing.Short() {
		t.Helper()
		t.Skipf("skipping test: no external network in -short mode")
	}
}
