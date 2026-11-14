# daneclient

A Go reference prototype of
[draft-ietf-dance-client-auth](https://datatracker.ietf.org/doc/draft-ietf-dance-client-auth/),
TLS client authentication with DANE. A client names itself in the
`dane_clientid` TLS extension (ExtensionType 63), and the server
authenticates it against a DNSSEC-signed TLSA record published at that
name.

It exists for checking RFC conformance and running interop tests. It is
not a production library. TLS 1.3 only. Out of scope: raw public keys
(RFC 7250) and DTLS.

## Layout

- `tls/`: a fork of Go 1.27.4 `crypto/tls` that adds `dane_clientid` to
  CertificateRequest and Certificate. See `tls/UPSTREAM.md`.
- `daneauth/`: server and client configuration on top of the fork and
  `github.com/shuque/dane/v2`: the draft section 8.2 server checks, an
  allowlist, a TLSA cache, and `net/http` adapters. See the package
  documentation.
- `cmd/danecert`: generate client keys and certificates and print the TLSA
  record to publish.
- `cmd/daneserver`: HTTPS demo server that authenticates clients by DANE.
- `cmd/daneclient`: HTTPS demo client.

## Building

`go.mod` has `replace github.com/shuque/dane/v2 => ../dane/v2` until
`dane/v2` is tagged. Check out the dane repo next to this one, on its `v2`
branch:

    git clone https://github.com/shuque/dane ../dane
    git -C ../dane checkout v2

Then:

    go build ./...
    go test ./...

## Quick start

    go build -o bin/ ./cmd/danecert ./cmd/daneserver ./cmd/daneclient
    bin/danecert ee -name dev1._device.example.com -out ee

Publish the printed `TLSA 3 1 1` line in a DNSSEC-signed zone, then run the
server (needs a certificate and key, and a DNSSEC-validating resolver) and
the client:

    bin/daneserver -cert server.crt -key server.key -resolver 127.0.0.1:53
    bin/daneclient -cafile server.crt -cert ee/client.crt -key ee/client.key \
      -name dev1._device.example.com https://localhost:8443/whoami

See [docs/testing.md](docs/testing.md) for the full procedure, including
DANE-TA, the live tests and the failure scenarios.
