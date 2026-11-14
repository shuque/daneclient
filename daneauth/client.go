package daneauth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/shuque/dane/v2"
	"github.com/shuque/daneclient/tls"
)

// ServerAuthMode says how the client authenticates the server.
type ServerAuthMode int

const (
	// ServerAuthPKIX verifies the server with the PKIX roots (the default).
	ServerAuthPKIX ServerAuthMode = iota
	// ServerAuthDANE verifies the server by DANE (TLSA at
	// _port._tcp.ServerName). There is no PKIX fallback.
	ServerAuthDANE
	// ServerAuthInsecure performs no server verification.
	ServerAuthInsecure
)

// ClientOptions configures ClientConfig. ServerName and Port are fixed in
// the resulting config, so a config (and any HTTPClient built on it)
// serves one origin: disable redirects, or build a client for each host.
type ClientOptions struct {
	Certificate *tls.Certificate // nil = no client cert
	ClientName  string           // DANE ClientName; "" = don't send
	ServerName  string           // SNI and reference identity
	ServerAuth  ServerAuthMode
	Port        int            // for DANE server auth: _port._tcp.ServerName; 0 = 443
	Resolver    *dane.Resolver // required for ServerAuthDANE
	Roots       *x509.CertPool // PKIX roots; nil = system
}

const serverLookupTimeout = 5 * time.Second

// ClientConfig returns a TLS client config for DANE client authentication.
// Session resumption is never enabled (ClientSessionCache is nil).
func ClientConfig(opts ClientOptions) (*tls.Config, error) {
	if opts.ClientName != "" && opts.Certificate == nil {
		return nil, errors.New("daneauth: ClientName is set but Certificate is nil")
	}
	cfg := &tls.Config{
		ServerName:         opts.ServerName,
		DANEClientName:     opts.ClientName,
		ClientSessionCache: nil,
	}
	if opts.Certificate != nil {
		cfg.Certificates = []tls.Certificate{*opts.Certificate}
	}
	if opts.ClientName != "" {
		cfg.MinVersion = tls.VersionTLS13
	}
	switch opts.ServerAuth {
	case ServerAuthPKIX:
		cfg.RootCAs = opts.Roots
	case ServerAuthInsecure:
		cfg.InsecureSkipVerify = true
	case ServerAuthDANE:
		if opts.Resolver == nil {
			return nil, errors.New("daneauth: ServerAuthDANE requires a Resolver")
		}
		if opts.ServerName == "" {
			return nil, errors.New("daneauth: ServerAuthDANE requires a ServerName")
		}
		cfg.InsecureSkipVerify = true // replaced by the DANE check below
		cfg.VerifyConnection = daneServerVerifier(opts)
	default:
		return nil, fmt.Errorf("daneauth: unknown ServerAuthMode %d", opts.ServerAuth)
	}
	return cfg, nil
}

// daneServerVerifier returns a VerifyConnection that authenticates the
// server by DANE and fails closed.
func daneServerVerifier(opts ClientOptions) func(tls.ConnectionState) error {
	port := opts.Port
	if port == 0 {
		port = 443
	}
	qname := dane.ServiceName(port, "tcp", opts.ServerName)
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("daneauth: server sent no certificate")
		}
		// VerifyConnection has no dialer context, so bound the lookup here.
		ctx, cancel := context.WithTimeout(context.Background(), serverLookupTimeout)
		defer cancel()
		rrset, err := opts.Resolver.LookupTLSA(ctx, qname)
		if err != nil {
			return fmt.Errorf("daneauth: server TLSA lookup %s: %w", qname, err)
		}
		if _, err := dane.Verify(cs.PeerCertificates, rrset, dane.VerifyOptions{
			Role:  dane.RoleServer,
			Name:  opts.ServerName,
			Roots: opts.Roots,
		}); err != nil {
			return fmt.Errorf("daneauth: server DANE verification of %s: %w", opts.ServerName, err)
		}
		return nil
	}
}
