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
	line = strings.TrimSpace(line)
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("want exactly one line, got %q", line)
	}
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
