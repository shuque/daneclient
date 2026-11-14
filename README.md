# daneclient

A Go reference implementation of
[draft-ietf-dance-client-auth](https://datatracker.ietf.org/doc/draft-ietf-dance-client-auth/),
TLS client authentication with DANE.

It is a prototype, built to check conformance with the specification and
to run interop tests. It is not a production library.

## What it does

In ordinary TLS client authentication, the server needs a CA it trusts to
vouch for the client. DANE client authentication replaces that with DNS:

1. The client publishes a TLSA record in a DNSSEC-signed zone, at a DNS
   name that identifies it (its *ClientName*). For example
   `dev1._device.example.com`.
2. When the server's CertificateRequest includes the `dane_clientid`
   extension (TLS ExtensionType 63), the client puts its ClientName in
   the same extension in its Certificate message.
3. The server looks up the TLSA record at that name and checks that the
   answer is DNSSEC-authenticated. It then checks that the client's
   certificate chain matches one of the records. If it does, the client
   is authenticated as that name.

This repository provides:

- **A modified TLS stack** that can send and receive `dane_clientid`.
- **A library** (`daneauth`) that implements the server's verification
  steps from draft section 8.2:
  - a ClientName allowlist
  - a TTL-respecting TLSA cache
  - Required and Optional policies
  - client-side configuration, optionally with DANE authentication of
    the server
  - `net/http` adapters
- **Command-line tools:**
  - generate test keys, certificates and TLSA records
  - an HTTPS demo server and client

Scope and limits:

- TLS 1.3 only.
- All four TLSA certificate usages are supported: DANE-EE (3), DANE-TA (2),
  PKIX-EE (1) and PKIX-TA (0). Interop testing so far uses DANE-EE and
  DANE-TA.
- Session resumption is disabled, so every connection does a full
  handshake and a full DANE check.
- HTTP/1.1 only in the HTTP adapters.
- Out of scope: raw public keys (RFC 7250) and DTLS.

## Repository layout

| Path | Contents |
|---|---|
| `tls/` | A fork of Go 1.27.4 `crypto/tls`. It replaces the standard library's internal imports with local shims and adds `dane_clientid`. See [tls/UPSTREAM.md](tls/UPSTREAM.md). Import it as `github.com/shuque/daneclient/tls`. |
| `daneauth/` | The glue between the fork and the DANE library: server verification, allowlist, TLSA cache, client config and HTTP helpers. The package documentation (`go doc ./daneauth`) maps each step of draft section 8.2 to the code. |
| `cmd/danecert/` | Generates client keys and certificates, and prints the TLSA record to publish. |
| `cmd/daneserver/` | HTTPS demo server that authenticates clients by DANE. |
| `cmd/daneclient/` | HTTPS demo client that presents a ClientName. |
| `docs/testing.md` | A runbook for live and interop testing against real DNSSEC-signed TLSA records. |

## Dependencies

- **Go 1.27 or later.** This is the module's `go` directive. The fork is
  based on Go 1.27.4 and builds outside GOROOT.
- **[github.com/shuque/dane/v2](https://github.com/shuque/dane)** does
  the TLSA lookups (with DNSSEC AD-bit checking) and matches TLSA records
  against certificate chains.
  - Until `v2.0.0` is tagged, `go.mod` contains
    `replace github.com/shuque/dane/v2 => ../dane/v2`. You need the
    `dane` repository checked out next to this one, on its `v2` branch.
- **[github.com/miekg/dns](https://github.com/miekg/dns)**,
  **golang.org/x/crypto** and **golang.org/x/sys**. These are fetched
  automatically by `go build`.

For real use (but not for the unit tests) you also need:

- A **DNSSEC-validating resolver** that sets the AD bit in its answers.
  The server treats any TLSA answer without AD as a lookup failure.
- A **DNSSEC-signed zone** to publish the client TLSA records in.

## Installation

Clone this repository and the `dane` repository side by side:

    git clone https://github.com/shuque/daneclient
    git clone https://github.com/shuque/dane
    git -C dane checkout v2
    cd daneclient

Build everything, and put the three programs in `bin/`:

    go build ./...
    go build -o bin/ ./cmd/danecert ./cmd/daneserver ./cmd/daneclient

Or install them into `$GOBIN`:

    go install ./cmd/...

## Running the tests

The unit tests need no network access and no DNS setup. DNS is served
by an in-process fake (`dane/v2/danetest`) and TLS runs over loopback
TCP.

    go test ./...                       # everything, including the TLS fork
    go test -race ./daneauth/ ./cmd/... # the glue and tools, with the race detector
    go vet ./...

The `tls/` package includes the upstream `crypto/tls` test suite, plus
tests for the `dane_clientid` encoding and handshake behaviour.

The **live tests** in `daneauth/live_test.go` run against real published
TLSA records through a real validating resolver. They are skipped unless
`DANECLIENT_LIVE=1` is set. For example:

    DANECLIENT_LIVE=1 DANECLIENT_LIVE_RESOLVER=127.0.0.1:53 \
    DANECLIENT_LIVE_EE_NAME=dev1._device.example.com \
    DANECLIENT_LIVE_EE_CERT=ee/client.crt DANECLIENT_LIVE_EE_KEY=ee/client.key \
    go test ./daneauth/ -run Live -v

See [docs/testing.md](docs/testing.md#3-live-go-tests) for the full list
of variables, including the ones for a DANE-TA identity.

## Demo programs

The usual sequence is:

1. Generate a client identity.
2. Publish its TLSA record.
3. Run the server.
4. Connect with the client.

[docs/testing.md](docs/testing.md) covers each step in more detail,
including the failure scenarios to try.

### `danecert`: generate test material

    danecert ee    -name <ClientName> -out <dir> [-force]
    danecert ca    -cn <CA name> -out <dir> [-force]
    danecert issue -ca <dir> -name <ClientName> -out <dir> [-allow-underscore] [-force]

The subcommands:

- **`ee`** makes a self-signed client certificate for **DANE-EE**. It
  writes `client.key` and `client.crt`, and prints a `3 1 1` record
  (SHA-256 of the public key):

      $ danecert ee -name dev1._device.example.com -out ee
      dev1._device.example.com. IN TLSA 3 1 1 <hex>

- **`ca`** then **`issue`** make a private CA and a client certificate
  signed by it, for **DANE-TA**.
  - The client certificate carries the ClientName as a SAN dNSName and
    has the clientAuth EKU.
  - `issue` writes `client.key`, `client.crt` and `chain.pem` (the leaf
    followed by the CA). It prints a `2 0 1` record, the SHA-256 of the
    CA certificate.

      $ danecert ca -cn "Test Client CA" -out ca
      $ danecert issue -ca ca -name dev1.dane-test.example.com -out ta
      dev1.dane-test.example.com. IN TLSA 2 0 1 <hex>

  - By default `issue` refuses a ClientName with an underscore label.
    RFC 5280 doesn't allow underscores in a dNSName (see draft section
    10). Pass `-allow-underscore` to override this for a private CA, or
    use a name without underscores.

Keys are PKCS#8 PEM with mode 0600. Existing files are never overwritten
unless you pass `-force`.

Add the printed record to your signed zone. Then check that your
resolver returns it with the `ad` flag set:

    dig +dnssec TLSA dev1._device.example.com @127.0.0.1

### `daneserver`: HTTPS server

    daneserver -cert server.crt -key server.key -resolver 127.0.0.1:53 -v

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8443` | listen address |
| `-cert`, `-key` | (required) | the server's certificate chain and private key (PEM) |
| `-policy` | `required` | `required`: an unauthenticated client is rejected with alert 40 (handshake_failure). `optional`: the handshake completes and the client is unauthenticated. |
| `-allow` | any name | allowed ClientNames. `name` matches exactly; `.domain` matches that domain and everything below it. Repeat the flag or use a comma-separated list. |
| `-resolver` | `/etc/resolv.conf` | DNSSEC-validating resolver, as `host:port` |
| `-timeout` | `5s` | TLSA lookup timeout |
| `-usages` | all | allowed certificate usages, as a comma list of 0–3 |
| `-v` | off | log each verification step |

The server logs one line per connection. A rejected handshake is logged
with its reason, such as `no dane_clientid`, `name not allowed`,
`tlsa lookup: ...`, `no matching tlsa` or `name mismatch`.

It serves three routes:

- `/`: plain-text authentication status.
- `/whoami`: JSON with the ClientName, the reason, whether the answer was
  cached, the TLSA RRset, and the result for each record.
- `/private`: returns 403 unless the client was authenticated by DANE.

For a throwaway server certificate:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout server.key -out server.crt -subj /CN=localhost -days 30 \
      -addext subjectAltName=DNS:localhost

### `daneclient`: HTTPS client

    # DANE-EE
    daneclient -cafile server.crt -cert ee/client.crt -key ee/client.key \
      -name dev1._device.example.com https://localhost:8443/whoami

    # DANE-TA: send the chain, leaf followed by CA
    daneclient -cafile server.crt -cert ta/chain.pem -key ta/client.key \
      -name dev1.dane-test.example.com https://localhost:8443/whoami

| Flag | Default | Meaning |
|---|---|---|
| `-cert`, `-key` | none | client certificate chain and private key (PEM) |
| `-name` | none | the ClientName to send in `dane_clientid`. Needs `-cert`. |
| `-server-auth` | `pkix` | how to authenticate the server. `pkix`: CA roots. `dane`: TLSA at `_port._tcp.<host>`, with no PKIX fallback. `insecure`: no check. |
| `-cafile` | system roots | PKIX root CAs for `-server-auth pkix` |
| `-resolver` | `/etc/resolv.conf` | validating resolver for `-server-auth dane` |

The client prints:

- the negotiated TLS version and cipher suite
- whether the server asked for `dane_clientid`
- the server-authentication outcome
- the HTTP status and body

If the server rejects the client, the client prints the TLS alert it
received. In TLS 1.3 this alert may arrive on the first read rather than
during the handshake, because the client finishes its side of the
handshake before the server has checked the client's certificate.

## Using the library

### Server

    import (
        "log"

        "github.com/shuque/dane/v2"
        "github.com/shuque/daneclient/daneauth"
        "github.com/shuque/daneclient/tls"
    )

    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    // ...
    srv, err := daneauth.NewServer(daneauth.ServerOptions{
        Certificates: []tls.Certificate{cert},
        Resolver:     dane.NewResolver("127.0.0.1:53"),
        Policy:       daneauth.Required, // or daneauth.Optional
        Logf:         log.Printf,
    })
    // ...
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if res := daneauth.RequestResult(r); res != nil && res.Authenticated {
            fmt.Fprintf(w, "hello, %s\n", res.ClientName)
        }
    })
    mux.Handle("/private", daneauth.RequireDANE(privateHandler))
    log.Fatal(srv.ListenAndServe(":8443", mux))

For something other than HTTP, use `srv.NewListener(l)` or
`srv.Server(conn)`, and read the outcome with `daneauth.Result(tlsConn)`
once the handshake has completed. `Result` returns nil until then.

Points to know:

- Serve connections through `Server`, `NewListener` or `ListenAndServe`.
  A connection made directly from `srv.TLSConfig()` is still checked,
  but it has no result attached.
- In HTTP handlers `r.TLS` is nil, because `net/http` doesn't know the
  forked TLS type. Use `daneauth.RequestResult(r)` instead.
- Allowlist entries are created with `daneauth.ParseAllowlist`. A nil
  `*Allowlist` means any name is allowed.
- A ClientName that matches the TLSA data but doesn't match the
  certificate's SAN dNSName always aborts the handshake, even under
  `Optional`. Draft section 8.2 requires this.

### Client

    cert, err := tls.LoadX509KeyPair("ee/client.crt", "ee/client.key")
    // ...
    cfg, err := daneauth.ClientConfig(daneauth.ClientOptions{
        Certificate: &cert,
        ClientName:  "dev1._device.example.com",
        ServerName:  "server.example.com",
        ServerAuth:  daneauth.ServerAuthPKIX, // or ServerAuthDANE with Resolver and Port
    })
    // ...
    resp, err := daneauth.HTTPClient(cfg).Get("https://server.example.com/")

A config fixes ServerName, and Port for DANE server authentication. So
each config serves one origin. To talk to several hosts, build a client
per host, and disable redirects.

To use the fork directly, without `daneauth`:

- On the server, set `Config.DANEClientAuth` and read
  `ConnectionState().DANEClientName`.
- On the client, set `Config.DANEClientName`.
- To get the code of a TLS alert the peer sent, call
  `tls.RemoteAlert(err)`.

## Status

The `dane_clientid` codepoint (63) is assigned by IANA. Open
specification questions, such as how session resumption should interact
with `dane_clientid`, are tracked by the draft authors.

## License

MIT; see [LICENSE](LICENSE). The exception is `tls/`, which is derived
from Go's `crypto/tls` and stays under Go's BSD-style license; see
[tls/LICENSE](tls/LICENSE).
