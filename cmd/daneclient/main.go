// Command daneclient is an HTTPS demo client that authenticates to a server
// with a DANE client identity (draft-ietf-dance-client-auth).
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/shuque/dane/v2"
	"github.com/shuque/daneclient/daneauth"
	"github.com/shuque/daneclient/tls"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "daneclient:", err)
		os.Exit(1)
	}
}

// parseTarget parses the https URL, returning it with its host and port
// (443 if absent).
func parseTarget(raw string) (u *url.URL, host string, port int, err error) {
	if u, err = url.Parse(raw); err != nil {
		return nil, "", 0, err
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return nil, "", 0, errors.New("the URL must be https://host[:port]/...")
	}
	port = 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return nil, "", 0, fmt.Errorf("bad port %q (want 1-65535)", p)
		}
	}
	return u, u.Hostname(), port, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("daneclient", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certFile := fs.String("cert", "", "client certificate chain (PEM)")
	keyFile := fs.String("key", "", "client private key (PEM)")
	name := fs.String("name", "", "DANE ClientName to send in dane_clientid (needs -cert)")
	mode := fs.String("server-auth", "pkix", "how to authenticate the server: pkix|dane|insecure")
	resolver := fs.String("resolver", "", "DNS resolver host:port for -server-auth dane; must be DNSSEC-validating (answers need the AD bit); default from /etc/resolv.conf")
	cafile := fs.String("cafile", "", "PEM file of PKIX root CAs (default: system roots)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: daneclient [flags] https://host[:port]/path")
	}
	u, host, port, err := parseTarget(fs.Arg(0))
	if err != nil {
		return err
	}

	opts := daneauth.ClientOptions{ClientName: *name, ServerName: host, Port: port}
	switch *mode {
	case "pkix":
		opts.ServerAuth = daneauth.ServerAuthPKIX
	case "dane":
		opts.ServerAuth = daneauth.ServerAuthDANE
		if *resolver == "" {
			if opts.Resolver, err = dane.ResolverFromConf("/etc/resolv.conf"); err != nil {
				return err
			}
		} else {
			opts.Resolver = dane.NewResolver(*resolver)
		}
	case "insecure":
		opts.ServerAuth = daneauth.ServerAuthInsecure
	default:
		return fmt.Errorf("invalid -server-auth %q", *mode)
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("-cert and -key must be given together")
	}
	if *certFile != "" {
		c, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		opts.Certificate = &c
	}
	if *cafile != "" {
		pem, err := os.ReadFile(*cafile)
		if err != nil {
			return err
		}
		opts.Roots = x509.NewCertPool()
		if !opts.Roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates in %s", *cafile)
		}
	}
	cfg, err := daneauth.ClientConfig(opts)
	if err != nil {
		return err
	}

	// Capture the *tls.Conn by wrapping the transport's dialer.
	client := daneauth.HTTPClient(cfg)
	client.Timeout = 30 * time.Second
	// Do not follow redirects: the printed TLS state is of the one connection used.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	tr := client.Transport.(*http.Transport)
	inner := tr.DialTLSContext
	var mu sync.Mutex
	var conn *tls.Conn
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := inner(ctx, network, addr)
		if tc, ok := c.(*tls.Conn); ok {
			mu.Lock()
			conn = tc
			mu.Unlock()
		}
		return c, err
	}
	defer tr.CloseIdleConnections()

	resp, err := client.Get(u.String())
	if err != nil {
		if a, ok := tls.RemoteAlert(err); ok {
			fmt.Fprintf(stderr, "server sent TLS alert: %v\n", a)
		}
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if a, ok := tls.RemoteAlert(err); ok {
			fmt.Fprintf(stderr, "server sent TLS alert: %v\n", a)
		}
		return err
	}
	mu.Lock()
	tc := conn
	mu.Unlock()
	if tc != nil {
		st := tc.ConnectionState()
		fmt.Fprintf(stdout, "tls_version: %s\n", tls.VersionName(st.Version))
		fmt.Fprintf(stdout, "cipher_suite: %s\n", tls.CipherSuiteName(st.CipherSuite))
		fmt.Fprintf(stdout, "dane_clientid_requested: %v\n", st.DANEClientIDRequested)
	}
	fmt.Fprintf(stdout, "server_auth: %s ok\n", *mode)
	fmt.Fprintf(stdout, "%s\n\n%s", resp.Status, body)
	return nil
}
