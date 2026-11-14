package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dane "github.com/shuque/dane/v2"
)

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return out.String()
}

func mustCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verify parses the printed line and checks the chain against it.
func verify(t *testing.T, line, name string, chain ...*x509.Certificate) {
	t.Helper()
	line, _, _ = strings.Cut(strings.TrimSpace(line), "\n") // line 1 is the record; a hint may follow
	owner, rest, ok := strings.Cut(line, " IN TLSA ")
	if !ok || owner != name+"." {
		t.Fatalf("bad line %q", line)
	}
	rec, err := dane.ParseTLSA(rest)
	if err != nil {
		t.Fatal(err)
	}
	rr := &dane.RRset{Qname: owner, Owner: owner, Records: []dane.TLSA{rec}}
	if _, err := dane.Verify(chain, rr, dane.VerifyOptions{Role: dane.RoleClient, Name: name}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestDanecertRoundTrip(t *testing.T) {
	dir := t.TempDir()

	eeDir := filepath.Join(dir, "ee")
	eeName := "dev1._device.example.com"
	line := runOK(t, "ee", "-name", eeName, "-out", eeDir)
	if !strings.Contains(line, " IN TLSA 3 1 1 ") {
		t.Fatalf("ee line %q", line)
	}
	verify(t, line, eeName, mustCert(t, filepath.Join(eeDir, "client.crt")))

	caDir := filepath.Join(dir, "ca")
	runOK(t, "ca", "-cn", "Test CA", "-out", caDir)
	isDir := filepath.Join(dir, "issued")
	name := "alice.example.com"
	line = runOK(t, "issue", "-ca", caDir, "-name", name, "-out", isDir)
	if !strings.Contains(line, " IN TLSA 2 0 1 ") {
		t.Fatalf("issue line %q", line)
	}
	verify(t, line, name, mustCert(t, filepath.Join(isDir, "client.crt")), mustCert(t, filepath.Join(caDir, "ca.crt")))

	// chain.pem is the leaf then the CA, and verifies by itself.
	chainPath := filepath.Join(isDir, "chain.pem")
	if out := runOK(t, "issue", "-ca", caDir, "-name", name, "-out", filepath.Join(dir, "issued2")); !strings.Contains(out, "hint: use "+filepath.Join(dir, "issued2", "chain.pem")+" as -cert for DANE-TA") {
		t.Errorf("no chain.pem hint in %q", out)
	}
	cb, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for rest := cb; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	if len(chain) != 2 {
		t.Fatalf("chain.pem has %d certs, want 2", len(chain))
	}
	verify(t, line, name, chain...)
	if fi, err := os.Stat(chainPath); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("chain.pem: %v %v", fi, err)
	}

	for _, p := range []string{filepath.Join(eeDir, "client.key"), filepath.Join(caDir, "ca.key"), filepath.Join(isDir, "client.key")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
}

func TestIssueUnderscore(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	runOK(t, "ca", "-cn", "Test CA", "-out", caDir)
	name := "_x._client.example.com"

	var out bytes.Buffer
	err := run([]string{"issue", "-ca", caDir, "-name", name, "-out", filepath.Join(dir, "a")}, &out)
	if err == nil || !strings.Contains(err.Error(), "-allow-underscore") {
		t.Fatalf("want refusal, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "a", "client.crt")); serr == nil {
		t.Error("cert written despite refusal")
	}

	out.Reset()
	b := filepath.Join(dir, "b")
	line := runOK(t, "issue", "-ca", caDir, "-name", name, "-out", b, "-allow-underscore")
	verify(t, line, name, mustCert(t, filepath.Join(b, "client.crt")), mustCert(t, filepath.Join(caDir, "ca.crt")))
}

func TestNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	args := []string{"ee", "-name", "a.example.com", "-out", dir}
	runOK(t, args...)
	var out bytes.Buffer
	if err := run(args, &out); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("want overwrite refusal, got %v", err)
	}
	runOK(t, append(args, "-force")...)
}

func TestUsage(t *testing.T) {
	var out bytes.Buffer
	for _, a := range [][]string{nil, {"bogus"}, {"ee"}, {"ca", "-out", t.TempDir()}, {"issue", "-name", "x"}} {
		if err := run(a, &out); err == nil {
			t.Errorf("run %v: want error", a)
		}
	}
}

func TestNameValidation(t *testing.T) {
	dir := t.TempDir()
	out := runOK(t, "ee", "-name", "a.example.com.", "-out", filepath.Join(dir, "ok"))
	if !strings.HasPrefix(out, "a.example.com. IN TLSA ") {
		t.Fatalf("owner = %q", out)
	}
	c := mustCert(t, filepath.Join(dir, "ok", "client.crt"))
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "a.example.com" || c.Subject.CommonName != "a.example.com" {
		t.Fatalf("SAN %v CN %q", c.DNSNames, c.Subject.CommonName)
	}

	caDir := filepath.Join(dir, "ca")
	runOK(t, "ca", "-cn", "Test CA", "-out", caDir)
	runOK(t, "issue", "-ca", caDir, "-name", "b.example.com.", "-out", filepath.Join(dir, "iss"))
	if c := mustCert(t, filepath.Join(dir, "iss", "client.crt")); len(c.DNSNames) != 1 || c.DNSNames[0] != "b.example.com" {
		t.Fatalf("issued SAN %v", c.DNSNames)
	}

	for _, bad := range []string{"..x.com", "a b.com", "*.example.com", "a..b", ".", "x.com..", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com"} {
		var o bytes.Buffer
		if err := run([]string{"ee", "-name", bad, "-out", filepath.Join(dir, "bad")}, &o); err == nil || !strings.Contains(err.Error(), "invalid name") {
			t.Errorf("name %q: err = %v", bad, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bad")); err == nil {
		t.Error("output dir created for a bad name")
	}
}

func TestForceReplacesFile(t *testing.T) {
	dir := t.TempDir()
	args := []string{"ee", "-name", "a.example.com", "-out", dir}
	runOK(t, args...)
	key := filepath.Join(dir, "client.key")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	runOK(t, append(args, "-force")...)
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key after -force: %v %v", fi, err)
	}

	// A symlink at the target is replaced, not followed.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(key)
	if err := os.Symlink(victim, key); err != nil {
		t.Fatal(err)
	}
	runOK(t, append(args, "-force")...)
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
	if fi, err := os.Lstat(key); err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key: %v %v", fi, err)
	}
}
