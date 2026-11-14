package daneauth

import (
	"context"
	"net"
	"net/http"

	"github.com/shuque/daneclient/tls"
)

type connKey struct{}

// HTTPServer returns an http.Server for h whose handlers can call
// RequestResult. Its TLSConfig is nil: TLS comes only from serving on
// NewListener. HTTP/1.1 only, so r.TLS is nil in handlers.
func (s *Server) HTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				return context.WithValue(ctx, connKey{}, tc)
			}
			return ctx
		},
	}
}

// ListenAndServe listens on addr and serves h over DANE-authenticated TLS.
func (s *Server) ListenAndServe(addr string, h http.Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.HTTPServer(h).Serve(s.NewListener(l))
}

// RequestResult returns the AuthResult of the connection carrying r, or
// nil if not available.
func RequestResult(r *http.Request) *AuthResult {
	tc, _ := r.Context().Value(connKey{}).(*tls.Conn)
	if tc == nil {
		return nil
	}
	return Result(tc)
}

// RequireDANE wraps h, answering 403 unless the client was authenticated.
func RequireDANE(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if res := RequestResult(r); res == nil || !res.Authenticated {
			http.Error(w, "DANE client authentication required", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// HTTPClient returns an HTTP/1.1 client that dials TLS with cfg.
func HTTPClient(cfg *tls.Config) *http.Client {
	d := &tls.Dialer{Config: cfg}
	return &http.Client{Transport: &http.Transport{
		DialTLSContext:    d.DialContext,
		ForceAttemptHTTP2: false,
		DisableKeepAlives: false,
	}}
}
