package daneauth

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/shuque/dane/v2"
	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/tls"
)

const (
	eeName = "dev1._device.example.com"
	taName = "dev1.example.com"
)

var clientAuthEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

// tlsaRR builds a wire TLSA RR at owner for rec.
func tlsaRR(owner string, rec dane.TLSA, ttl uint32) dns.RR {
	return &dns.TLSA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeTLSA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Usage:        uint8(rec.Usage),
		Selector:     uint8(rec.Selector),
		MatchingType: uint8(rec.MatchingType),
		Certificate:  hex.EncodeToString(rec.Data),
	}
}

func mustTLSA(t *testing.T, u dane.Usage, s dane.Selector, m dane.MatchingType, c *x509.Certificate) dane.TLSA {
	t.Helper()
	rec, err := dane.NewTLSA(u, s, m, c)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// serveTLSA publishes recs at owner on dns with the given AD bit.
func serveTLSA(dnsSrv *danetest.DNSServer, owner string, ad bool, delay time.Duration, recs ...dane.TLSA) {
	var rrs []dns.RR
	for _, r := range recs {
		rrs = append(rrs, tlsaRR(owner, r, 300))
	}
	dnsSrv.Set(owner, dns.TypeTLSA, danetest.Answer{Rcode: dns.RcodeSuccess, AD: ad, Answer: rrs, Delay: delay})
}

func tlsCert(key crypto.Signer, chain ...*x509.Certificate) tls.Certificate {
	c := tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c
}

func serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	c, k := danetest.NewSelfSigned(t, danetest.CertOpts{
		DNSNames:    []string{"server.example.net"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return tlsCert(k, c)
}

// newTestServer returns a Server using dnsSrv; mod may adjust the options.
func newTestServer(t *testing.T, dnsSrv *danetest.DNSServer, mod func(*ServerOptions)) *Server {
	t.Helper()
	opts := ServerOptions{
		Certificates: []tls.Certificate{serverCert(t)},
		Resolver:     dane.NewResolver(dnsSrv.Addr),
		Logf:         t.Logf,
	}
	if mod != nil {
		mod(&opts)
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func clientConfig(name string, certs ...tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // server authentication is not under test
		ServerName:         "server.example.net",
		Certificates:       certs,
		DANEClientName:     name,
	}
}

// eeClient returns a self-signed client cert and its "3 1 1" record.
func eeClient(t *testing.T) (tls.Certificate, dane.TLSA) {
	t.Helper()
	c, k := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{eeName}, ExtKeyUsage: clientAuthEKU})
	return tlsCert(k, c), mustTLSA(t, dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, c)
}

// taClient returns a CA-issued client cert with SAN san (chain [leaf, ca])
// and the CA's "2 0 1" record.
func taClient(t *testing.T, san string) (tls.Certificate, dane.TLSA) {
	t.Helper()
	ca, caKey := danetest.NewCA(t, "Test Client CA")
	leaf, k := danetest.NewLeaf(t, ca, caKey, danetest.CertOpts{DNSNames: []string{san}, ExtKeyUsage: clientAuthEKU})
	return tlsCert(k, leaf, ca), mustTLSA(t, dane.DANETA, dane.SelectorCert, dane.MatchSHA256, ca)
}

type hsOutcome struct {
	clientErr  error     // first error from client Handshake, or the Read after it
	serverErr  error     // server Handshake error
	serverConn *tls.Conn // server side, for Result
	elapsed    time.Duration
}

// tcpPair returns a connected loopback TCP pair. Unlike net.Pipe it is
// buffered, so a peer writing an alert cannot deadlock against a peer
// still writing its flight.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a.err != nil {
		client.Close()
		t.Fatal(a.err)
	}
	return client, a.c
}

// handshake runs one connection: the server handshakes and, on success,
// writes one byte; the client handshakes and then reads. In TLS 1.3 the
// client finishes before the server has judged its certificate, so a
// server alert may show up only on that Read (ruling R2). Deadlines on
// both ends bound the test; the server end stays open until the client
// is done, so an alert is never lost to a TCP reset.
func handshake(t *testing.T, s *Server, ccfg *tls.Config) hsOutcome {
	t.Helper()
	return handshakeWith(t, s.Server, ccfg)
}

// handshakeWith is handshake with the server conn made by mk.
func handshakeWith(t *testing.T, mk func(net.Conn) *tls.Conn, ccfg *tls.Config) hsOutcome {
	t.Helper()
	cRaw, sRaw := tcpPair(t)
	deadline := time.Now().Add(10 * time.Second)
	cRaw.SetDeadline(deadline)
	sRaw.SetDeadline(deadline)

	sconn := mk(sRaw)
	clientDone := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		err := sconn.Handshake()
		if err == nil {
			_, err = sconn.Write([]byte{'k'})
		}
		serverErr <- err
		<-clientDone
		sRaw.Close()
	}()

	start := time.Now()
	cconn := tls.Client(cRaw, ccfg)
	err := cconn.Handshake()
	if err == nil {
		var b [1]byte
		_, err = io.ReadFull(cconn, b[:])
	}
	elapsed := time.Since(start)
	cRaw.Close()
	close(clientDone)
	return hsOutcome{clientErr: err, serverErr: <-serverErr, serverConn: sconn, elapsed: elapsed}
}

func wantOK(t *testing.T, o hsOutcome) *AuthResult {
	t.Helper()
	if o.clientErr != nil || o.serverErr != nil {
		t.Fatalf("handshake failed: client %v; server %v", o.clientErr, o.serverErr)
	}
	res := Result(o.serverConn)
	if res == nil {
		t.Fatal("Result is nil after a successful handshake")
	}
	return res
}

// wantAlert checks that the client saw alert a from the server (R2).
func wantAlert(t *testing.T, o hsOutcome, a tls.AlertError) {
	t.Helper()
	if o.clientErr == nil {
		t.Fatalf("client saw no error; server err %v", o.serverErr)
	}
	got, ok := tls.RemoteAlert(o.clientErr)
	if !ok || got != a {
		t.Fatalf("RemoteAlert(%v) = %d, %v; want %d", o.clientErr, got, ok, a)
	}
	if o.serverErr == nil {
		t.Fatal("server handshake succeeded")
	}
	if Result(o.serverConn) != nil {
		t.Fatal("Result non-nil after a failed handshake")
	}
}

func wantUnauth(t *testing.T, res *AuthResult, reason string) {
	t.Helper()
	if res.Authenticated {
		t.Fatalf("Authenticated = true, want false (%+v)", res)
	}
	if res.Reason != reason {
		t.Fatalf("Reason = %q, want %q (err %v)", res.Reason, reason, res.Err)
	}
}

func optional(o *ServerOptions) { o.Policy = Optional }

func TestServerDANEEE(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	res := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
	if !res.Authenticated || res.ClientName != eeName || res.Reason != "authenticated" || res.Err != nil {
		t.Fatalf("result = %+v", res)
	}
	if res.Verify == nil || res.Verify.Matched == nil || !reflect.DeepEqual(res.Verify.Matched.Record, rec) {
		t.Fatalf("Verify.Matched = %+v, want record %v", res.Verify, rec)
	}
	if res.RRset == nil || res.Cached {
		t.Fatalf("RRset = %v, Cached = %v", res.RRset, res.Cached)
	}
}

func TestServerDANETA(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := taClient(t, taName)
	serveTLSA(dnsSrv, taName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	res := wantOK(t, handshake(t, s, clientConfig(taName, cert)))
	if !res.Authenticated || res.ClientName != taName || res.Reason != "authenticated" {
		t.Fatalf("result = %+v", res)
	}
}

// otherKeyRecord is a "3 1 1" record for a key the client does not hold.
func otherKeyRecord(t *testing.T) dane.TLSA {
	t.Helper()
	c, _ := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{eeName}})
	return mustTLSA(t, dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, c)
}

func TestServerNoMatchRequired(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, _ := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, otherKeyRecord(t))
	s := newTestServer(t, dnsSrv, nil)

	wantAlert(t, handshake(t, s, clientConfig(eeName, cert)), 40)
}

// A step 4 failure logs one line per TLSA record, and the abort error
// names the client.
func TestServerNoMatchLogsRecords(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, _ := eeClient(t)
	rec := otherKeyRecord(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	var logs logCapture
	s := newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Logf = logs.Logf })
	o := handshake(t, s, clientConfig(eeName, cert))
	wantAlert(t, o, 40)
	if want := fmt.Sprintf("client %q: no matching tlsa", eeName); !strings.Contains(o.serverErr.Error(), want) {
		t.Fatalf("server error %q lacks %q", o.serverErr, want)
	}
	if !logs.contains("step 4: record " + rec.String()) {
		t.Fatalf("no per-record log line for %v in %q", rec, logs.lines)
	}
}

func TestServerNoMatchOptional(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, _ := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, otherKeyRecord(t))
	s := newTestServer(t, dnsSrv, optional)

	res := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
	wantUnauth(t, res, "no matching tlsa")
	if !errors.Is(res.Err, dane.ErrNotAuthenticated) || res.Verify == nil || res.RRset == nil {
		t.Fatalf("result = %+v", res)
	}
}

func TestServerInsecure(t *testing.T) {
	t.Run("Required", func(t *testing.T) {
		dnsSrv := danetest.NewDNSServer(t)
		cert, rec := eeClient(t)
		serveTLSA(dnsSrv, eeName, false, 0, rec)
		s := newTestServer(t, dnsSrv, nil)
		wantAlert(t, handshake(t, s, clientConfig(eeName, cert)), 40)
	})
	t.Run("Optional", func(t *testing.T) {
		dnsSrv := danetest.NewDNSServer(t)
		cert, rec := eeClient(t)
		serveTLSA(dnsSrv, eeName, false, 0, rec)
		s := newTestServer(t, dnsSrv, optional)
		res := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
		if res.Authenticated || !strings.HasPrefix(res.Reason, "tlsa lookup: ") || !errors.Is(res.Err, dane.ErrInsecure) {
			t.Fatalf("result = %+v", res)
		}
		if want := "tlsa lookup: " + dane.ErrInsecure.Error(); res.Reason != want {
			t.Fatalf("Reason = %q, want %q", res.Reason, want)
		}
		if res.RRset != nil || res.Verify != nil {
			t.Fatalf("RRset/Verify set after a failed lookup: %+v", res)
		}
	})
}

// A failed TLSA lookup is reported with its sentinel under Optional and
// aborts with handshake_failure under Required.
func TestServerLookupFailures(t *testing.T) {
	cases := []struct {
		name     string
		ans      danetest.Answer
		sentinel error
	}{
		{"NXDOMAIN", danetest.Answer{Rcode: dns.RcodeNameError, AD: true}, dane.ErrNXDOMAIN},
		{"NODATA", danetest.Answer{Rcode: dns.RcodeSuccess, AD: true}, dane.ErrNoData},
		{"ServFail", danetest.Answer{Rcode: dns.RcodeServerFailure}, dane.ErrServFail},
	}
	for _, c := range cases {
		t.Run(c.name+"/Optional", func(t *testing.T) {
			dnsSrv := danetest.NewDNSServer(t)
			cert, _ := eeClient(t)
			dnsSrv.Set(eeName, dns.TypeTLSA, c.ans)
			s := newTestServer(t, dnsSrv, optional)
			res := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
			wantUnauth(t, res, "tlsa lookup: "+c.sentinel.Error())
			if !errors.Is(res.Err, c.sentinel) {
				t.Fatalf("Err = %v, want %v", res.Err, c.sentinel)
			}
		})
		t.Run(c.name+"/Required", func(t *testing.T) {
			dnsSrv := danetest.NewDNSServer(t)
			cert, _ := eeClient(t)
			dnsSrv.Set(eeName, dns.TypeTLSA, c.ans)
			s := newTestServer(t, dnsSrv, nil)
			wantAlert(t, handshake(t, s, clientConfig(eeName, cert)), 40)
		})
	}
}

// Session tickets are disabled, so a second connection from a client with
// a session cache does a full handshake and is authenticated again.
func TestServerNoResumption(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)
	ccfg := clientConfig(eeName, cert)
	ccfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := 0; i < 2; i++ {
		o := handshake(t, s, ccfg)
		res := wantOK(t, o)
		if !res.Authenticated {
			t.Fatalf("connection %d: result = %+v", i, res)
		}
		if o.serverConn.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed", i)
		}
	}
}

func TestServerAllowlistBeforeLookup(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	al, err := ParseAllowlist([]string{".example.org"})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Allowlist = al })

	wantAlert(t, handshake(t, s, clientConfig(eeName, cert)), 40)
	if n := dnsSrv.Queries(); n != 0 {
		t.Fatalf("DNS queries = %d, want 0", n)
	}

	// Under Optional the reason is visible.
	s = newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Allowlist = al; o.Policy = Optional })
	wantUnauth(t, wantOK(t, handshake(t, s, clientConfig(eeName, cert))), "name not allowed")
	if n := dnsSrv.Queries(); n != 0 {
		t.Fatalf("DNS queries = %d, want 0", n)
	}
}

func TestServerLookupTimeout(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 2*time.Second, rec)
	timeout := func(o *ServerOptions) { o.LookupTimeout = 200 * time.Millisecond }

	s := newTestServer(t, dnsSrv, timeout)
	o := handshake(t, s, clientConfig(eeName, cert))
	wantAlert(t, o, 40)
	if o.elapsed >= time.Second {
		t.Fatalf("alert after %v, want < 1s", o.elapsed)
	}

	s = newTestServer(t, dnsSrv, func(o *ServerOptions) { timeout(o); o.Policy = Optional })
	o = handshake(t, s, clientConfig(eeName, cert))
	res := wantOK(t, o)
	if res.Authenticated || !errors.Is(res.Err, dane.ErrTimeout) {
		t.Fatalf("result = %+v", res)
	}
	if want := "tlsa lookup: " + dane.ErrTimeout.Error(); res.Reason != want {
		t.Fatalf("Reason = %q, want %q", res.Reason, want)
	}
	if o.elapsed >= time.Second {
		t.Fatalf("handshake took %v, want < 1s", o.elapsed)
	}
}

func TestServerCacheHit(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	first := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
	second := wantOK(t, handshake(t, s, clientConfig(eeName, cert)))
	if n := dnsSrv.Queries(); n != 1 {
		t.Fatalf("DNS queries = %d, want 1", n)
	}
	if first.Cached || !second.Cached || !second.Authenticated {
		t.Fatalf("first.Cached = %v, second = %+v", first.Cached, second)
	}
}

func TestOptionalNoCert(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	s := newTestServer(t, dnsSrv, optional)

	res := wantOK(t, handshake(t, s, clientConfig("")))
	wantUnauth(t, res, "no dane_clientid")
	if res.ClientName != "" || dnsSrv.Queries() != 0 {
		t.Fatalf("result = %+v, queries = %d", res, dnsSrv.Queries())
	}
}

// A client that sends no certificate under Required reaches step 1 and
// gets handshake_failure (draft 8.2 step 3), not certificate_required.
func TestRequiredNoCert(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	s := newTestServer(t, dnsSrv, nil)
	o := handshake(t, s, clientConfig(""))
	wantAlert(t, o, 40)
	if res := o.serverConn.NetConn().(*resultConn).res.Load(); res == nil || res.Reason != "no dane_clientid" {
		t.Fatalf("stored result = %+v", res)
	}
	if n := dnsSrv.Queries(); n != 0 {
		t.Fatalf("DNS queries = %d, want 0", n)
	}
}

func TestRequiredNoName(t *testing.T) {
	// A certificate but no dane_clientid: draft 8.2 step 3, the server
	// requires DANE client authentication, so handshake_failure.
	dnsSrv := danetest.NewDNSServer(t)
	cert, _ := eeClient(t)
	s := newTestServer(t, dnsSrv, nil)
	wantAlert(t, handshake(t, s, clientConfig("", cert)), 40)
}

// logCapture collects Logf lines.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

// A ClientName absent from the certificate's dNSNames aborts the
// connection under either policy (draft 8.2, after step 6).
func TestServerNameMismatch(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := taClient(t, "other.example.com")
	serveTLSA(dnsSrv, taName, true, 0, rec)

	for _, p := range []Policy{Required, Optional} {
		var logs logCapture
		s := newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Policy = p; o.Logf = logs.Logf })
		o := handshake(t, s, clientConfig(taName, cert))
		wantAlert(t, o, 40)
		if want := fmt.Sprintf("client %q: name mismatch", taName); !strings.Contains(o.serverErr.Error(), want) {
			t.Fatalf("policy %d: server error %q lacks %q", p, o.serverErr, want)
		}
		res := o.serverConn.NetConn().(*resultConn).res.Load()
		if res == nil || res.Authenticated || res.Reason != "name mismatch" || !errors.Is(res.Err, dane.ErrNameMismatch) {
			t.Fatalf("policy %d: stored result = %+v", p, res)
		}
		if !logs.contains("step 4: name mismatch") {
			logs.mu.Lock()
			lines := append([]string(nil), logs.lines...)
			logs.mu.Unlock()
			t.Fatalf("policy %d: no name mismatch log line in %q", p, lines)
		}
	}
}

func TestResultOnlyAfterHandshake(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	_, wrongKey := danetest.NewSelfSigned(t, danetest.CertOpts{})
	bad := cert
	bad.PrivateKey = wrongKey // CertificateVerify will not verify

	for _, p := range []Policy{Required, Optional} {
		s := newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Policy = p })
		ccfg := clientConfig(eeName)
		ccfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &bad, nil }
		o := handshake(t, s, ccfg)
		if o.serverErr == nil || o.clientErr == nil {
			t.Fatalf("policy %d: handshake succeeded: client %v, server %v", p, o.clientErr, o.serverErr)
		}
		// VerifyConnection ran (before CertificateVerify) and found a
		// matching record, but the connection is not authenticated.
		if got := o.serverConn.NetConn().(*resultConn).res.Load(); got == nil || !got.Authenticated {
			t.Fatalf("policy %d: stored result = %+v, want the pre-CertificateVerify success", p, got)
		}
		if res := Result(o.serverConn); res != nil {
			t.Fatalf("policy %d: Result = %+v after a failed handshake, want nil", p, res)
		}
	}
}

func TestServerConfigInvariants(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	for _, p := range []Policy{Required, Optional} {
		s := newTestServer(t, dnsSrv, func(o *ServerOptions) { o.Policy = p })
		cfg := s.TLSConfig()
		if cfg.MinVersion != tls.VersionTLS13 || !cfg.SessionTicketsDisabled || !cfg.DANEClientAuth {
			t.Fatalf("policy %d: MinVersion %x, SessionTicketsDisabled %v, DANEClientAuth %v",
				p, cfg.MinVersion, cfg.SessionTicketsDisabled, cfg.DANEClientAuth)
		}
		if cfg.ClientAuth != tls.RequestClientCert || cfg.GetConfigForClient == nil || len(cfg.Certificates) != 1 {
			t.Fatalf("policy %d: ClientAuth %v, GetConfigForClient set %v, %d certs",
				p, cfg.ClientAuth, cfg.GetConfigForClient != nil, len(cfg.Certificates))
		}
		if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
			t.Fatalf("policy %d: base VerifyConnection accepted a connection", p)
		} else if a, ok := errors.AsType[tls.AlertError](err); !ok || a != 40 {
			t.Fatalf("policy %d: base VerifyConnection error %v does not wrap AlertError(40)", p, err)
		}
	}
	var zero ServerOptions
	if zero.Policy != Required {
		t.Fatal("zero Policy is not Required")
	}
}

// TLSConfig used directly: DANE is still enforced (Result is nil, as the
// conn is not a resultConn); with GetConfigForClient removed, every
// connection is rejected.
func TestTLSConfigDirect(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	direct := func(c net.Conn) *tls.Conn { return tls.Server(c, s.TLSConfig()) }
	o := handshakeWith(t, direct, clientConfig(eeName, cert))
	if o.clientErr != nil || o.serverErr != nil {
		t.Fatalf("direct: client %v; server %v", o.clientErr, o.serverErr)
	}
	if Result(o.serverConn) != nil {
		t.Fatal("direct: Result non-nil for a conn not made by Server")
	}
	other, _ := eeClient(t) // key not in DNS
	wantAlert(t, handshakeWith(t, direct, clientConfig(eeName, other)), 40)

	stripped := func(c net.Conn) *tls.Conn {
		cfg := s.TLSConfig()
		cfg.GetConfigForClient = nil
		return tls.Server(c, cfg)
	}
	wantAlert(t, handshakeWith(t, stripped, clientConfig(eeName, cert)), 40)
}

func TestNewServerErrors(t *testing.T) {
	r := dane.NewResolver("127.0.0.1:53")
	certs := []tls.Certificate{serverCert(t)}
	for name, opts := range map[string]ServerOptions{
		"no resolver":    {Certificates: certs},
		"no certs":       {Resolver: r},
		"invalid policy": {Certificates: certs, Resolver: r, Policy: Policy(7)},
	} {
		if s, err := NewServer(opts); err == nil || s != nil || !strings.HasPrefix(err.Error(), "daneauth: ") {
			t.Errorf("%s: NewServer = %v, %v", name, s, err)
		}
	}
}

func TestServerListener(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := s.NewListener(inner)
	defer ln.Close()
	type out struct {
		res *AuthResult
		err error
	}
	ch := make(chan out, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- out{nil, err}
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			ch <- out{nil, err}
			return
		}
		_, err = tc.Write([]byte{'k'})
		ch <- out{Result(tc), err}
	}()
	// The accept goroutine always sends on ch (its handshake is bounded
	// by a deadline, and closing ln ends Accept), so waiting on ch before
	// any t.Fatal keeps server-side Logf calls inside the test.
	raw, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		ln.Close()
		<-ch
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	cc := tls.Client(raw, clientConfig(eeName, cert))
	var b [1]byte
	_, rerr := io.ReadFull(cc, b[:])
	raw.Close()
	o := <-ch
	if rerr != nil {
		t.Fatalf("client: %v (server: %v)", rerr, o.err)
	}
	if o.err != nil || o.res == nil || !o.res.Authenticated {
		t.Fatalf("listener result = %+v, %v", o.res, o.err)
	}
}
