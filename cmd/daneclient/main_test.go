package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/shuque/dane/v2"
	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/daneauth"
	"github.com/shuque/daneclient/tls"
)

const clientName = "dev1._device.example.com"

func writePEM(t *testing.T, dir string, c *x509.Certificate, key any) (string, string) {
	t.Helper()
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cf, kf
}

func TestRunDANEClient(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cx, ck := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{clientName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	rec, err := dane.NewTLSA(dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, cx)
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv.Set(clientName, dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeSuccess, AD: true, Answer: []dns.RR{&dns.TLSA{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(clientName), Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage: uint8(rec.Usage), Selector: uint8(rec.Selector), MatchingType: uint8(rec.MatchingType),
		Certificate: fmt.Sprintf("%x", rec.Data),
	}}})
	sx, sk := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	s, err := daneauth.NewServer(daneauth.ServerOptions{
		Certificates: []tls.Certificate{{Certificate: [][]byte{sx.Raw}, PrivateKey: sk, Leaf: sx}},
		Resolver:     dane.NewResolver(dnsSrv.Addr),
		Policy:       daneauth.Optional,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		res := daneauth.RequestResult(r)
		if res != nil && res.Authenticated {
			fmt.Fprintf(w, "authenticated: yes\nclient_name: %s\n", res.ClientName)
			return
		}
		fmt.Fprintln(w, "authenticated: no")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.HTTPServer(mux)
	done := make(chan struct{})
	go func() { srv.Serve(s.NewListener(ln)); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })

	cf, kf := writePEM(t, t.TempDir(), cx, ck)
	url := "https://localhost:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port) + "/"
	var out, errb bytes.Buffer
	err = run([]string{"-cert", cf, "-key", kf, "-name", clientName, "-server-auth", "insecure", url}, &out, &errb)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, errb.String())
	}
	for _, want := range []string{"dane_clientid_requested: true", "authenticated: yes", "tls_version: TLS 1.3", "server_auth: insecure (not verified)", "200 OK"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRunBadArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"http://example.com/"}, "must be https"},
		{[]string{"-name", "x.example", "https://example.com/"}, "Certificate is nil"},
		{[]string{"-server-auth", "bogus", "https://example.com/"}, "invalid -server-auth"},
		{[]string{"-cert", "x", "https://example.com/"}, "must be given together"},
		{[]string{"https://example.com:0/"}, "bad port"},
		{[]string{}, "usage"},
	} {
		var out, errb bytes.Buffer
		err := run(tc.args, &out, &errb)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want substring %q", tc.args, err, tc.want)
		}
	}
}

func TestRunHelp(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"-h"}, &out, &errb); err != nil || !strings.Contains(errb.String(), "-server-auth") {
		t.Fatalf("err = %v, usage %q", err, errb.String())
	}
}

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		raw, host string
		port      int
	}{
		{"https://example.com/x", "example.com", 443},
		{"https://example.com:8443/", "example.com", 8443},
		{"https://[::1]:8443/", "::1", 8443},
		{"https://[::1]/", "::1", 443},
	} {
		_, host, port, err := parseTarget(tc.raw)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("%s = %q %d %v, want %q %d", tc.raw, host, port, err, tc.host, tc.port)
		}
	}
	for _, raw := range []string{"https://example.com:0/", "https://example.com:65536/", "https://example.com:99999/", "https:///path", "http://example.com/", "example.com", "https://example.com:x/"} {
		if _, _, _, err := parseTarget(raw); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

// A rejected client still prints the TLS state of its connection (TLS 1.3
// delivers the server's alert after the client handshake).
func TestRunRejectedPrintsState(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t) // no TLSA record: lookup fails, Required aborts
	cx, ck := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{clientName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	sx, sk := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	s, err := daneauth.NewServer(daneauth.ServerOptions{
		Certificates: []tls.Certificate{{Certificate: [][]byte{sx.Raw}, PrivateKey: sk, Leaf: sx}},
		Resolver:     dane.NewResolver(dnsSrv.Addr),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.HTTPServer(http.NewServeMux())
	done := make(chan struct{})
	go func() { srv.Serve(s.NewListener(ln)); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })

	cf, kf := writePEM(t, t.TempDir(), cx, ck)
	url := "https://localhost:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port) + "/"
	var out, errb bytes.Buffer
	err = run([]string{"-cert", cf, "-key", kf, "-name", clientName, "-server-auth", "insecure", url}, &out, &errb)
	if err == nil {
		t.Fatalf("run succeeded:\n%s", out.String())
	}
	for _, want := range []string{"tls_version: TLS 1.3", "dane_clientid_requested: true"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(errb.String(), "server sent TLS alert") {
		t.Errorf("stderr lacks alert line: %q", errb.String())
	}
}
