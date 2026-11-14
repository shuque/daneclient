package daneauth

import (
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/shuque/dane/v2"
	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/tls"
)

func TestClientConfigInvariants(t *testing.T) {
	cert, _ := eeClient(t)
	cfg, err := ClientConfig(ClientOptions{
		Certificate: &cert,
		ClientName:  eeName,
		ServerName:  "server.example.net",
		ServerAuth:  ServerAuthInsecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x", cfg.MinVersion)
	}
	if cfg.ClientSessionCache != nil {
		t.Fatal("ClientSessionCache is set")
	}
	if cfg.DANEClientName != eeName {
		t.Fatalf("DANEClientName = %q", cfg.DANEClientName)
	}
	if len(cfg.Certificates) != 1 || cfg.ServerName != "server.example.net" || !cfg.InsecureSkipVerify {
		t.Fatalf("config = %+v", cfg)
	}

	roots := x509.NewCertPool()
	cfg, err = ClientConfig(ClientOptions{ServerName: "a.example.net", Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs != roots || cfg.ServerName != "a.example.net" || len(cfg.Certificates) != 0 || cfg.DANEClientName != "" {
		t.Fatalf("PKIX config = %+v", cfg)
	}
}

func TestClientConfigErrors(t *testing.T) {
	cert, _ := eeClient(t)
	r := dane.NewResolver("127.0.0.1:1")
	tests := []struct {
		name string
		opts ClientOptions
	}{
		{"name without cert", ClientOptions{ClientName: eeName, ServerAuth: ServerAuthInsecure}},
		{"DANE nil resolver", ClientOptions{Certificate: &cert, ServerName: "s.example.com", ServerAuth: ServerAuthDANE}},
		{"DANE empty server name", ClientOptions{Resolver: r, ServerAuth: ServerAuthDANE}},
		{"unknown mode", ClientOptions{ServerAuth: ServerAuthMode(99)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ClientConfig(tc.opts)
			if err == nil || cfg != nil {
				t.Fatalf("got %v, %v; want error", cfg, err)
			}
			if !strings.HasPrefix(err.Error(), "daneauth:") {
				t.Fatalf("error %q lacks daneauth: prefix", err)
			}
		})
	}
}

// daneServerAuth runs one handshake against a plain fork tls.Server and
// returns the client's error.
func daneServerAuth(t *testing.T, rec dane.TLSA, srvCert tls.Certificate) error {
	t.Helper()
	dnsSrv := danetest.NewDNSServer(t)
	serveTLSA(dnsSrv, "_8443._tcp.srv.example.com", true, 0, rec)
	cfg, err := ClientConfig(ClientOptions{
		ServerName: "srv.example.com",
		ServerAuth: ServerAuthDANE,
		Port:       8443,
		Resolver:   dane.NewResolver(dnsSrv.Addr),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatalf("DANE config = %+v", cfg)
	}
	o := handshakeWith(t, func(c net.Conn) *tls.Conn {
		return tls.Server(c, &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS13})
	}, cfg)
	if o.clientErr == nil && o.serverErr != nil {
		t.Fatalf("server error without client error: %v", o.serverErr)
	}
	return o.clientErr
}

func TestClientDANEServerAuth(t *testing.T) {
	c, k := danetest.NewSelfSigned(t, danetest.CertOpts{
		DNSNames:    []string{"srv.example.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	srvCert := tlsCert(k, c)

	t.Run("match", func(t *testing.T) {
		if err := daneServerAuth(t, mustTLSA(t, dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, c), srvCert); err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	})
	t.Run("wrong record", func(t *testing.T) {
		other, _ := danetest.NewSelfSigned(t, danetest.CertOpts{DNSNames: []string{"srv.example.com"}})
		err := daneServerAuth(t, mustTLSA(t, dane.DANEEE, dane.SelectorSPKI, dane.MatchSHA256, other), srvCert)
		if err == nil {
			t.Fatal("handshake succeeded with a wrong TLSA record")
		}
		t.Logf("error: %v", err)
	})
}
