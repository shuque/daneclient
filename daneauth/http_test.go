package daneauth

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shuque/dane/v2/danetest"
	"github.com/shuque/daneclient/tls"
)

// countListener counts Accepts.
type countListener struct {
	net.Listener
	n atomic.Int32
}

func (l *countListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// startHTTP serves h from s on loopback and returns the address.
func startHTTP(t *testing.T, s *Server, h http.Handler) (string, *countListener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countListener{Listener: ln}
	srv := s.HTTPServer(h)
	done := make(chan struct{})
	go func() { srv.Serve(s.NewListener(cl)); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
	return ln.Addr().String(), cl
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func httpMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		res := RequestResult(r)
		if res == nil {
			http.Error(w, "no result", 500)
			return
		}
		io.WriteString(w, res.Reason+" "+res.ClientName)
	})
	mux.Handle("/private", RequireDANE(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secret")
	})))
	return mux
}

func TestHTTPPublicAndPrivate(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, optional)
	addr, _ := startHTTP(t, s, httpMux())

	cfg, err := ClientConfig(ClientOptions{Certificate: &cert, ClientName: eeName, ServerName: "server.example.net", ServerAuth: ServerAuthInsecure})
	if err != nil {
		t.Fatal(err)
	}
	dc := HTTPClient(cfg)
	if code, body := get(t, dc, "https://"+addr+"/private"); code != 200 || body != "secret" {
		t.Fatalf("DANE /private = %d %q", code, body)
	}
	if code, body := get(t, dc, "https://"+addr+"/"); code != 200 || body != "authenticated "+eeName {
		t.Fatalf("DANE / = %d %q", code, body)
	}

	plain := HTTPClient(&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if code, body := get(t, plain, "https://"+addr+"/"); code != 200 || body != "no dane_clientid " {
		t.Fatalf("plain / = %d %q", code, body)
	}
	if code, body := get(t, plain, "https://"+addr+"/private"); code != 403 || body != "DANE client authentication required\n" {
		t.Fatalf("plain /private = %d %q", code, body)
	}
}

func TestHTTPKeepAliveSameResult(t *testing.T) {
	dnsSrv := danetest.NewDNSServer(t)
	cert, rec := eeClient(t)
	serveTLSA(dnsSrv, eeName, true, 0, rec)
	s := newTestServer(t, dnsSrv, nil)

	var mu sync.Mutex
	var addrs []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		addrs = append(addrs, r.RemoteAddr)
		mu.Unlock()
		res := RequestResult(r)
		if res == nil || !res.Authenticated {
			http.Error(w, "unauthenticated", 500)
			return
		}
		io.WriteString(w, res.ClientName)
	})
	addr, cl := startHTTP(t, s, mux)

	cfg, err := ClientConfig(ClientOptions{Certificate: &cert, ClientName: eeName, ServerName: "server.example.net", ServerAuth: ServerAuthInsecure})
	if err != nil {
		t.Fatal(err)
	}
	c := HTTPClient(cfg)
	for i := 0; i < 3; i++ {
		if code, body := get(t, c, "https://"+addr+"/"); code != 200 || body != eeName {
			t.Fatalf("GET %d = %d %q", i, code, body)
		}
	}
	if n := cl.n.Load(); n != 1 {
		t.Fatalf("accepts = %d, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) != 3 || addrs[0] != addrs[1] || addrs[1] != addrs[2] {
		t.Fatalf("RemoteAddrs = %v", addrs)
	}
	if n := dnsSrv.Queries(); n != 1 {
		t.Fatalf("DNS queries = %d, want 1", n)
	}
}

func TestRequestResultMissing(t *testing.T) {
	r, _ := http.NewRequestWithContext(context.Background(), "GET", "http://x/", nil)
	if RequestResult(r) != nil {
		t.Fatal("RequestResult non-nil without a connection")
	}
}
