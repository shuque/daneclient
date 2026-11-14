package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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
func startMux(t *testing.T, pol daneauth.Policy) (string, tls.Certificate, *logBuf) {
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
		Policy:       pol,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuf{}
	srv := httpServer(s)
	done := make(chan struct{})
	go func() { srv.Serve(&logListener{Listener: s.NewListener(ln), logf: logs.logf}); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
	return ln.Addr().String(), ccert, logs
}

// logBuf is a goroutine-safe log capture.
type logBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *logBuf) logf(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fmt.Fprintf(&b.sb, format+"\n", args...)
}

func (b *logBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// waitLog waits for the log to contain want.
func (b *logBuf) waitLog(t *testing.T, want string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("log lacks %q:\n%s", want, b.String())
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
	addr, ccert, _ := startMux(t, daneauth.Optional)
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
	addr, _, _ := startMux(t, daneauth.Optional)
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

func TestSplitList(t *testing.T) {
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

func TestLogListenerAuthenticated(t *testing.T) {
	addr, ccert, logs := startMux(t, daneauth.Required)
	cfg, err := daneauth.ClientConfig(daneauth.ClientOptions{
		Certificate: &ccert, ClientName: clientName, ServerName: "server.example.net",
		ServerAuth: daneauth.ServerAuthInsecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := getBody(t, daneauth.HTTPClient(cfg), "https://"+addr+"/"); code != 200 {
		t.Fatalf("status %d", code)
	}
	logs.waitLog(t, `client_name="`+clientName+`" reason="authenticated"`)
}

func TestLogListenerRejected(t *testing.T) {
	addr, _, logs := startMux(t, daneauth.Required)
	c := daneauth.HTTPClient(&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if _, err := c.Get("https://" + addr + "/"); err == nil {
		t.Fatal("rejected client got a response")
	}
	logs.waitLog(t, "handshake failed")
	logs.waitLog(t, "no dane_clientid")
}

func TestRunFlags(t *testing.T) {
	for _, bad := range []string{"", ","} {
		var errb bytes.Buffer
		err := run([]string{"-allow", bad, "-cert", "x", "-key", "y"}, &errb)
		if err == nil || !strings.Contains(err.Error(), "-allow") {
			t.Errorf("-allow %q: err = %v", bad, err)
		}
	}
	var errb bytes.Buffer
	if err := run([]string{"-h"}, &errb); err != nil || !strings.Contains(errb.String(), "-listen") {
		t.Fatalf("-h: err = %v, output %q", err, errb.String())
	}
}
