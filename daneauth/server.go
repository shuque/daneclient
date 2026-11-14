package daneauth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/shuque/dane/v2"
	"github.com/shuque/daneclient/tls"
)

// Policy says what the server does with a client that is not
// authenticated by DANE.
type Policy int

const (
	// Required aborts the handshake with handshake_failure (the default).
	Required Policy = iota
	// Optional completes the handshake; the client is unauthenticated.
	Optional
)

const (
	defaultLookupTimeout  = 5 * time.Second
	alertHandshakeFailure = tls.AlertError(40)
)

// ServerOptions configures a Server.
type ServerOptions struct {
	Certificates  []tls.Certificate                // server's own certs
	Resolver      *dane.Resolver                   // required
	Allowlist     *Allowlist                       // nil = any name
	Policy        Policy                           // zero value = Required
	LookupTimeout time.Duration                    // 0 = 5s
	AllowedUsages []dane.Usage                     // nil = all
	Roots         *x509.CertPool                   // for PKIX-TA/EE; nil = system
	Logf          func(format string, args ...any) // nil = no logging
}

// AuthResult is the outcome of DANE client authentication on one
// connection.
type AuthResult struct {
	Authenticated bool
	ClientName    string       // as sent; "" if none
	Verify        *dane.Result // nil if verification never ran
	RRset         *dane.RRset  // nil if lookup failed or never ran; shared, read-only
	Cached        bool         // TLSA answer came from cache
	Reason        string       // short, stable reason
	Err           error
}

// Server authenticates TLS clients by DANE (draft-ietf-dance-client-auth
// section 8.2). It is safe for concurrent use.
type Server struct {
	opts  ServerOptions
	cache *tlsaCache
	base  *tls.Config
}

// NewServer returns a Server. opts.Resolver must be set and
// opts.Certificates must not be empty.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Resolver == nil {
		return nil, errors.New("daneauth: ServerOptions.Resolver is required")
	}
	if len(opts.Certificates) == 0 {
		return nil, errors.New("daneauth: ServerOptions.Certificates is empty")
	}
	clientAuth := tls.RequireAnyClientCert
	switch opts.Policy {
	case Required:
	case Optional:
		clientAuth = tls.RequestClientCert
	default:
		return nil, fmt.Errorf("daneauth: invalid policy %d", opts.Policy)
	}
	if opts.LookupTimeout <= 0 {
		opts.LookupTimeout = defaultLookupTimeout
	}
	s := &Server{opts: opts, cache: newTLSACache(opts.Resolver.LookupTLSA, 0, nil)}
	s.base = &tls.Config{
		Certificates:           opts.Certificates,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true, // a resumed connection carries no ClientName
		DANEClientAuth:         true,
		ClientAuth:             clientAuth,
		GetConfigForClient:     s.configForClient,
	}
	return s, nil
}

// TLSConfig returns a copy of the server's base TLS config. Its
// GetConfigForClient installs the DANE check, so DANE authentication is
// enforced on any connection that uses it; but Result works only for
// connections made by Server or NewListener. Changes to the copy are not
// seen by GetConfigForClient, which derives from the base config.
func (s *Server) TLSConfig() *tls.Config {
	return s.base.Clone()
}

// resultConn carries the AuthResult of a connection from VerifyConnection
// to Result.
type resultConn struct {
	net.Conn
	res atomic.Pointer[AuthResult]
}

// Server returns a TLS server connection over conn.
func (s *Server) Server(conn net.Conn) *tls.Conn {
	return tls.Server(&resultConn{Conn: conn}, s.base)
}

type listener struct {
	net.Listener
	s *Server
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.s.Server(c), nil
}

// NewListener returns a listener whose Accept returns s.Server(c), as a
// *tls.Conn.
func (s *Server) NewListener(inner net.Listener) net.Listener {
	return &listener{Listener: inner, s: s}
}

// Result returns the AuthResult of c, or nil unless c's handshake has
// completed and c was made by Server or NewListener. VerifyConnection runs
// before the client's CertificateVerify is checked, so a result is only
// meaningful once the handshake has succeeded. Result blocks while a
// handshake on c is in progress.
func Result(c *tls.Conn) *AuthResult {
	if c == nil || !c.ConnectionState().HandshakeComplete {
		return nil
	}
	rc, ok := c.NetConn().(*resultConn)
	if !ok {
		return nil
	}
	return rc.res.Load()
}

// configForClient clones the base config and adds a VerifyConnection that
// runs the DANE check and stores its result on the connection.
func (s *Server) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	rc, _ := hello.Conn.(*resultConn)
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := s.base.Clone()
	cfg.GetConfigForClient = nil
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		res := s.verify(ctx, cs)
		if rc != nil {
			rc.res.Store(res)
		}
		if res.Authenticated || s.opts.Policy == Optional {
			return nil
		}
		return fmt.Errorf("daneauth: %s: %w", res.Reason, alertHandshakeFailure)
	}
	return cfg, nil
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// fail records an unauthenticated outcome at step.
func (s *Server) fail(res *AuthResult, step int, reason string, err error) *AuthResult {
	res.Reason, res.Err = reason, err
	if err != nil {
		s.logf("daneauth: client %q: step %d: %s: %v", res.ClientName, step, reason, err)
	} else {
		s.logf("daneauth: client %q: step %d: %s", res.ClientName, step, reason)
	}
	return res
}

var lookupSentinels = []error{dane.ErrInsecure, dane.ErrNXDOMAIN, dane.ErrNoData, dane.ErrServFail, dane.ErrTimeout}

func lookupReason(err error) string {
	for _, e := range lookupSentinels {
		if errors.Is(err, e) {
			return "tlsa lookup: " + e.Error()
		}
	}
	return "tlsa lookup: " + err.Error()
}

// verify runs the steps of draft section 8.2 on a connection whose client
// Certificate has been received (see doc.go for the mapping).
func (s *Server) verify(ctx context.Context, cs tls.ConnectionState) *AuthResult {
	name := cs.DANEClientName
	res := &AuthResult{ClientName: name}

	// Step 1: the client must have sent dane_clientid.
	if name == "" {
		return s.fail(res, 1, "no dane_clientid", nil)
	}
	s.logf("daneauth: client %q: step 1: dane_clientid received", name)

	// Step 2: allowlist, before any DNS query.
	if !s.opts.Allowlist.Allows(name) {
		return s.fail(res, 2, "name not allowed", nil)
	}
	s.logf("daneauth: client %q: step 2: name allowed", name)

	// Step 3: DNSSEC-validated TLSA lookup at the ClientName, bounded and cached.
	lctx, cancel := context.WithTimeout(ctx, s.opts.LookupTimeout)
	rrset, cached, err := s.cache.Lookup(lctx, name)
	cancel()
	res.Cached = cached
	if err != nil {
		return s.fail(res, 3, lookupReason(err), err)
	}
	res.RRset = rrset
	s.logf("daneauth: client %q: step 3: %d TLSA records (cached %v)", name, len(rrset.Records), cached)

	// Step 4: match the presented chain against the records.
	vres, err := dane.Verify(cs.PeerCertificates, rrset, dane.VerifyOptions{
		Role:          dane.RoleClient,
		Name:          name,
		AllowedUsages: s.opts.AllowedUsages,
		Roots:         s.opts.Roots,
	})
	res.Verify = vres
	if err != nil {
		reason := "no matching tlsa"
		if errors.Is(err, dane.ErrNameMismatch) {
			reason = "name mismatch"
		}
		return s.fail(res, 4, reason, err)
	}

	// Step 5: authenticated.
	res.Authenticated, res.Reason = true, "authenticated"
	m := vres.Matched.Record
	s.logf("daneauth: client %q: step 5: authenticated by TLSA %d %d %d", name, m.Usage, m.Selector, m.MatchingType)
	return res
}
