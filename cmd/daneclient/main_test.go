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
	os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600)
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
	for _, want := range []string{"dane_clientid_requested: true", "authenticated: yes", "tls_version: TLS 1.3", "server_auth: insecure ok", "200 OK"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRunBadArgs(t *testing.T) {
	for _, args := range [][]string{
		{"http://example.com/"},
		{"-name", "x.example", "https://example.com/"},
		{"-server-auth", "bogus", "https://example.com/"},
		{"-cert", "x", "https://example.com/"},
	} {
		var out, errb bytes.Buffer
		if err := run(args, &out, &errb); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
