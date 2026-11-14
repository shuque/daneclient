package daneauth

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/shuque/dane/v2"
	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/tls"
)

// Live tests run against real DNSSEC-signed TLSA records. They are off
// unless DANECLIENT_LIVE=1, and then touch the network. See
// docs/testing.md for the variables:
//
//	DANECLIENT_LIVE_RESOLVER           validating resolver, host:port
//	DANECLIENT_LIVE_EE_{NAME,CERT,KEY} a DANE-EE identity
//	DANECLIENT_LIVE_TA_{NAME,CERT,KEY,CHAIN} a DANE-TA identity (CHAIN is a
//	                                   PEM file with the CA certificate)

// liveResolver returns the live resolver, skipping unless live tests are
// enabled and failing if they are enabled without a resolver.
func liveResolver(t *testing.T) *dane.Resolver {
	t.Helper()
	if os.Getenv("DANECLIENT_LIVE") != "1" {
		t.Skip("set DANECLIENT_LIVE=1 to run live tests")
	}
	addr := os.Getenv("DANECLIENT_LIVE_RESOLVER")
	if addr == "" {
		t.Fatal("DANECLIENT_LIVE=1 but DANECLIENT_LIVE_RESOLVER is not set")
	}
	return dane.NewResolver(addr)
}

func liveEnv(t *testing.T, names ...string) []string {
	t.Helper()
	vals := make([]string, len(names))
	for i, n := range names {
		vals[i] = os.Getenv("DANECLIENT_LIVE_" + n)
		if vals[i] == "" {
			t.Skipf("DANECLIENT_LIVE_%s not set", n)
		}
	}
	return vals
}

func liveServer(t *testing.T, res *dane.Resolver) *Server {
	t.Helper()
	s, err := NewServer(ServerOptions{
		Certificates: []tls.Certificate{serverCert(t)},
		Resolver:     res,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// loadChainFile appends the certificates in a PEM file to c.
func loadChainFile(t *testing.T, c *tls.Certificate, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			c.Certificate = append(c.Certificate, blk.Bytes)
			n++
		}
	}
	if n == 0 {
		t.Fatalf("%s: no certificates", path)
	}
}

func liveAuth(t *testing.T, res *dane.Resolver, name string, cert tls.Certificate) {
	t.Helper()
	o := handshake(t, liveServer(t, res), clientConfig(name, cert))
	r := wantOK(t, o)
	if !r.Authenticated || r.ClientName != name {
		t.Fatalf("result = %+v", r)
	}
	t.Logf("authenticated %s (cached=%v, reason=%s)", r.ClientName, r.Cached, r.Reason)
}

func TestLiveDANEEE(t *testing.T) {
	res := liveResolver(t)
	v := liveEnv(t, "EE_NAME", "EE_CERT", "EE_KEY")
	cert, err := tls.LoadX509KeyPair(v[1], v[2])
	if err != nil {
		t.Fatal(err)
	}
	liveAuth(t, res, v[0], cert)
}

func TestLiveDANETA(t *testing.T) {
	res := liveResolver(t)
	v := liveEnv(t, "TA_NAME", "TA_CERT", "TA_KEY", "TA_CHAIN")
	cert, err := tls.LoadX509KeyPair(v[1], v[2])
	if err != nil {
		t.Fatal(err)
	}
	loadChainFile(t, &cert, v[3])
	liveAuth(t, res, v[0], cert)
}

// TestLiveWrongKey presents the EE name with a freshly generated key,
// which must not match the published record.
func TestLiveWrongKey(t *testing.T) {
	res := liveResolver(t)
	v := liveEnv(t, "EE_NAME")
	c, k := danetest.NewSelfSigned(t, danetest.CertOpts{
		DNSNames:    []string{v[0]},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	o := handshake(t, liveServer(t, res), clientConfig(v[0], tlsCert(k, c)))
	wantAlert(t, o, tls.AlertError(40))
	r := o.serverConn.NetConn().(*resultConn).res.Load()
	if r == nil || r.Reason != "no matching tlsa" {
		var reason string
		var err error
		if r != nil {
			reason, err = r.Reason, r.Err
		}
		t.Fatalf("stored reason = %q (err %v), want %q", reason, err, "no matching tlsa")
	}
}
