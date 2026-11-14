// Command daneserver is an HTTPS demo server that authenticates clients by
// DANE (draft-ietf-dance-client-auth).
//
// Routes: / (public page), /whoami (JSON), /private (requires DANE).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shuque/dane/v2"
	"github.com/shuque/daneclient/daneauth"
	"github.com/shuque/daneclient/tls"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "daneserver:", err)
		os.Exit(1)
	}
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// splitList splits each value on commas, trims whitespace and drops empty
// entries.
func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

// parseUsages parses a comma list of certificate usages 0-3; "" means all.
func parseUsages(s string) ([]dane.Usage, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []dane.Usage
	for _, e := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(e))
		if err != nil || n < 0 || n > 3 {
			return nil, fmt.Errorf("invalid usage %q (want 0-3)", e)
		}
		out = append(out, dane.Usage(n))
	}
	return out, nil
}

// newResolver returns a resolver for host:port, or one from resolv.conf.
func newResolver(spec string) (*dane.Resolver, error) {
	if spec == "" {
		return dane.ResolverFromConf("/etc/resolv.conf")
	}
	return dane.NewResolver(spec), nil
}

func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("daneserver", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "listen address")
	certFile := fs.String("cert", "", "server certificate chain (PEM)")
	keyFile := fs.String("key", "", "server private key (PEM)")
	var allow listFlag
	fs.Var(&allow, "allow", "allowed ClientName (\"name\" exact, \".domain\" for the domain and below); repeatable or comma-separated; default: any")
	policy := fs.String("policy", "required", "required|optional: what to do with clients not authenticated by DANE")
	resolver := fs.String("resolver", "", "DNS resolver host:port; must be DNSSEC-validating (answers need the AD bit); default from /etc/resolv.conf")
	timeout := fs.Duration("timeout", 5*time.Second, "TLSA lookup timeout")
	usages := fs.String("usages", "", "allowed certificate usages, comma list of 0-3; default all")
	verbose := fs.Bool("v", false, "log each verification step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("-cert and -key are required")
	}
	var pol daneauth.Policy
	switch *policy {
	case "required":
		pol = daneauth.Required
	case "optional":
		pol = daneauth.Optional
	default:
		return fmt.Errorf("invalid -policy %q", *policy)
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	res, err := newResolver(*resolver)
	if err != nil {
		return err
	}
	us, err := parseUsages(*usages)
	if err != nil {
		return err
	}
	var al *daneauth.Allowlist
	if names := splitList(allow); len(names) > 0 {
		if al, err = daneauth.ParseAllowlist(names); err != nil {
			return err
		}
	}
	opts := daneauth.ServerOptions{
		Certificates:  []tls.Certificate{cert},
		Resolver:      res,
		Allowlist:     al,
		Policy:        pol,
		LookupTimeout: *timeout,
		AllowedUsages: us,
	}
	if *verbose {
		opts.Logf = log.Printf
	}
	s, err := daneauth.NewServer(opts)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Printf("daneserver: listening on %s (policy %s)", ln.Addr(), *policy)
	srv := httpServer(s)
	return srv.Serve(s.NewListener(ln))
}

// httpServer returns the demo http.Server, logging one line per connection.
func httpServer(s *daneauth.Server) *http.Server {
	srv := s.HTTPServer(newMux(s))
	srv.ReadHeaderTimeout = 10 * time.Second
	var mu sync.Mutex
	seen := map[net.Conn]bool{}
	srv.ConnState = func(c net.Conn, st http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		switch st {
		case http.StateActive:
			if seen[c] {
				return
			}
			seen[c] = true
			// net/http has read a request, so the handshake is done.
			name, reason := "", "-"
			if tc, ok := c.(*tls.Conn); ok {
				if r := daneauth.Result(tc); r != nil {
					name, reason = r.ClientName, r.Reason
				}
			}
			log.Printf("conn %s client_name=%q reason=%q", c.RemoteAddr(), name, reason)
		case http.StateClosed, http.StateHijacked:
			delete(seen, c)
		}
	}
	return srv
}

type rrsetJSON struct {
	Owner   string   `json:"owner"`
	Aliases []string `json:"aliases"`
	TTL     uint32   `json:"ttl"`
	Records []string `json:"records"`
}

type resultJSON struct {
	Record string `json:"record"`
	Status string `json:"status"`
	Depth  int    `json:"depth"`
	Detail string `json:"detail"`
}

type whoami struct {
	Authenticated bool         `json:"authenticated"`
	ClientName    string       `json:"client_name"`
	Reason        string       `json:"reason"`
	Cached        bool         `json:"cached"`
	Error         string       `json:"error,omitempty"`
	RRset         *rrsetJSON   `json:"rrset"`
	Results       []resultJSON `json:"results"`
}

func makeWhoami(res *daneauth.AuthResult) whoami {
	w := whoami{Reason: "-", Results: []resultJSON{}}
	if res == nil {
		return w
	}
	w.Authenticated, w.ClientName, w.Reason, w.Cached = res.Authenticated, res.ClientName, res.Reason, res.Cached
	if res.Err != nil {
		w.Error = res.Err.Error()
	}
	if res.RRset != nil {
		rj := &rrsetJSON{Owner: res.RRset.Owner, Aliases: []string{}, TTL: res.RRset.TTL, Records: []string{}}
		rj.Aliases = append(rj.Aliases, res.RRset.Aliases...)
		for _, r := range res.RRset.Records {
			rj.Records = append(rj.Records, r.String())
		}
		w.RRset = rj
	}
	if res.Verify != nil {
		for _, r := range res.Verify.Records {
			w.Results = append(w.Results, resultJSON{Record: r.Record.String(), Status: r.Status.String(), Depth: r.Depth, Detail: r.Detail})
		}
	}
	return w
}

// newMux returns the demo routes.
func newMux(*daneauth.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		res := daneauth.RequestResult(r)
		auth, reason, name := "no", "-", ""
		if res != nil {
			if res.Authenticated {
				auth = "yes"
			}
			reason, name = res.Reason, res.ClientName
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "authenticated: %s\nreason: %s\nclient_name: %s\n", auth, reason, name)
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(makeWhoami(daneauth.RequestResult(r)))
	})
	mux.Handle("/private", daneauth.RequireDANE(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "hello, %s\n", daneauth.RequestResult(r).ClientName)
	})))
	return mux
}
