package main

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/shuque/dane/v2"
	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/daneauth"
	"github.com/shuque/daneclient/tls"
)

const clientName = "dev1._device.example.com"

func newCert(t *testing.T, name string, eku x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	c, k := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{name}, ExtKeyUsage: []x509.ExtKeyUsage{eku}})
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}, c
}

// startMux serves newMux on loopback with a fake DNS publishing a DANE-EE
// record for clientName's certificate, and returns the address and the
// client certificate.
func startMux(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	dnsSrv := danetest.NewDNSServer(t)
	ccert, cx := newCert(t, clientName, x509.ExtKeyUsageClientAuth)
	rec, err := dane.NewTLSA(dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, cx)
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv.Set(clientName, dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeSuccess, AD: true, Answer: []dns.RR{&dns.TLSA{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(clientName), Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage: uint8(rec.Usage), Selector: uint8(rec.Selector), MatchingType: uint8(rec.MatchingType),
		Certificate: hexOf(rec.Data),
	}}})
	scert, _ := newCert(t, "server.example.net", x509.ExtKeyUsageServerAuth)
	s, err := daneauth.NewServer(daneauth.ServerOptions{
		Certificates: []tls.Certificate{scert},
		Resolver:     dane.NewResolver(dnsSrv.Addr),
		Policy:       daneauth.Optional,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.HTTPServer(newMux(s))
	done := make(chan struct{})
	go func() { srv.Serve(s.NewListener(ln)); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
	return ln.Addr().String(), ccert
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(h[c>>4])
		sb.WriteByte(h[c&15])
	}
	return sb.String()
}

func getBody(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestNewMuxWhoami(t *testing.T) {
	addr, ccert := startMux(t)
	cfg, err := daneauth.ClientConfig(daneauth.ClientOptions{
		Certificate: &ccert, ClientName: clientName, ServerName: "server.example.net",
		ServerAuth: daneauth.ServerAuthInsecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := daneauth.HTTPClient(cfg)

	code, body := getBody(t, c, "https://"+addr+"/whoami")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	var w whoami
	if err := json.Unmarshal([]byte(body), &w); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if !w.Authenticated || w.ClientName != clientName || w.Reason != "authenticated" {
		t.Fatalf("whoami = %+v", w)
	}
	if w.RRset == nil || w.RRset.Owner == "" || len(w.RRset.Records) != 1 {
		t.Fatalf("rrset = %+v", w.RRset)
	}
	if len(w.Results) != 1 || w.Results[0].Status != "matched" {
		t.Fatalf("results = %+v", w.Results)
	}
	for _, key := range []string{`"authenticated"`, `"client_name"`, `"reason"`, `"cached"`, `"rrset"`, `"results"`, `"owner"`, `"aliases"`, `"ttl"`, `"records"`, `"record"`, `"status"`, `"depth"`, `"detail"`} {
		if !strings.Contains(body, key) {
			t.Errorf("missing key %s in %s", key, body)
		}
	}

	if code, body := getBody(t, c, "https://"+addr+"/"); code != 200 || !strings.Contains(body, "authenticated: yes") || !strings.Contains(body, "client_name: "+clientName) {
		t.Fatalf("/ = %d %q", code, body)
	}
	if code, body := getBody(t, c, "https://"+addr+"/private"); code != 200 || !strings.Contains(body, clientName) {
		t.Fatalf("/private = %d %q", code, body)
	}
}

func TestNewMuxUnauthenticated(t *testing.T) {
	addr, _ := startMux(t)
	c := daneauth.HTTPClient(&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	code, body := getBody(t, c, "https://"+addr+"/whoami")
	var w whoami
	if code != 200 || json.Unmarshal([]byte(body), &w) != nil || w.Authenticated || w.Reason != "no dane_clientid" || w.RRset != nil {
		t.Fatalf("whoami = %d %s", code, body)
	}
	if code, _ := getBody(t, c, "https://"+addr+"/private"); code != 403 {
		t.Fatalf("/private = %d", code)
	}
}

func TestParseAllow(t *testing.T) {
	got := splitList([]string{"a.example, b.example ,,", " ", "c.example"})
	want := []string{"a.example", "b.example", "c.example"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestParseUsages(t *testing.T) {
	u, err := parseUsages("2, 3")
	if err != nil || len(u) != 2 || u[0] != dane.DANETA || u[1] != dane.DANEEE {
		t.Fatalf("%v %v", u, err)
	}
	if u, err := parseUsages(""); err != nil || u != nil {
		t.Fatalf("%v %v", u, err)
	}
	for _, bad := range []string{"4", "x", "-1", "2,,3"} {
		if _, err := parseUsages(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
