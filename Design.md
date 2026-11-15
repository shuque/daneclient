# Design

This document describes how daneclient is put together. daneclient is a
Go reference implementation of
[draft-ietf-dance-client-auth](https://datatracker.ietf.org/doc/draft-ietf-dance-client-auth/),
TLS client authentication with DANE. For installation and usage, see
[README.md](README.md). For live and interop testing, see
[docs/testing.md](docs/testing.md).

## Purpose and scope

- **Purpose:** a reference prototype for checking conformance with the
  specification and for running interop tests. It is not intended to be
  a production library. Correctness and readability are priorities, and
  the code tries to make it obvious how each normative requirement of the
  draft is met.
- **In scope:**
  - the client and server sides of the protocol
  - server-side allowlisting of client names
  - demo programs: an HTTPS server and client, and a tool that generates
    test credentials
- **Out of scope:**
  - raw public keys (RFC 7250)
  - DTLS 1.3
  - TLS 1.2 (DANE client authentication requires TLS 1.3)
  - HTTP/2 (because Go's `net/http` negotiates HTTP/2 only with the
    standard `crypto/tls`)

## Protocol summary

- A server asks for DANE client authentication by including the
  `dane_clientid` extension in its TLS 1.3 CertificateRequest.
  `dane_clientid` is TLS ExtensionType **63**, assigned by IANA. In the
  CertificateRequest the extension is always empty: a zero-length
  ClientName.
- The client answers by putting `dane_clientid` on the end-entity (first)
  CertificateEntry of its Certificate message. There it carries the
  client's ClientName, a DNS name.
- The wire encoding in both messages is `opaque ClientName<0..2^8-1>`: a
  1-byte length, then the name.
- The ClientName is the owner name of the client's TLSA records. The
  server queries it exactly as sent and builds no name of its own. It
  then requires a DNSSEC-validated answer, and checks the client's
  certificate chain against the TLSA records (RFC 6698, RFC 7671).

## Components

```
cmd/daneserver, cmd/daneclient, cmd/danecert    demo programs and tools
        │
daneauth/  (glue)                     server and client config helpers,
        │                             allowlist, policy, TLSA cache, HTTP
        ├──────────────────┐
tls/  (fork)            github.com/shuque/dane/v2  (separate module)
dane_clientid           TLSA lookup, the DNSSEC AD bit, and
                        RFC 6698/7671 matching
```

### `tls/`: the crypto/tls fork

Go's standard `crypto/tls` has no API for adding extensions to
CertificateRequest or Certificate, so the TLS stack has to be modified.
`tls/` is a fork of Go 1.27.4 `crypto/tls`, imported as
`github.com/shuque/daneclient/tls`.

As of Go 1.27, `crypto/tls` imports standard-library internal packages
that code outside GOROOT cannot import. These are:

- `crypto/internal/fips140/{tls13,tls12,aes,aes/gcm}`
- `crypto/internal/boring`
- `internal/godebug`
- `internal/byteorder`
- `internal/cpu`

The fork was built in three commits, so that the DANE changes can be
reviewed apart from the mechanical ones:

1. An unmodified copy of upstream `crypto/tls`.
2. De-internalization only. Local shims under `tls/internal/` replace
   the internal imports. BoringCrypto support and the `//go:linkname`
   directives are removed. There are no feature changes, and the
   upstream tests pass.
3. The `dane_clientid` feature. Most of it is in `tls/dane.go`, with
   small hooks in the upstream files.

[tls/UPSTREAM.md](tls/UPSTREAM.md) records the base version, every shim,
the removed files, the tests that are skipped, and every deliberate
departure from upstream.

Public API added by the fork:

| API | Side | Meaning |
|---|---|---|
| `Config.DANEClientAuth` | server | Adds an empty `dane_clientid` to the TLS 1.3 CertificateRequest when a client certificate is requested. |
| `Config.DANEClientName` | client | The ClientName to send. It is sent only when the CertificateRequest advertised the extension and the client is sending a certificate. |
| `ConnectionState.DANEClientName` | server | The ClientName received, or `""`. It is set before `VerifyConnection` runs. |
| `ConnectionState.DANEClientIDRequested` | client | Whether the server's CertificateRequest carried the extension. |
| `RemoteAlert(err)` | both | Returns the code of a TLS alert received from the peer. |

The fork does no DNS work and makes no policy decisions. It enforces
only the protocol rules:

| Condition | Alert |
|---|---|
| `dane_clientid` in a client Certificate when our CertificateRequest didn't advertise it | `unsupported_extension` |
| `dane_clientid` in the server's Certificate | `unsupported_extension` |
| `dane_clientid` in ClientHello (including a second ClientHello after HRR), ServerHello, HelloRetryRequest, EncryptedExtensions or NewSessionTicket | `illegal_parameter` |
| A zero-length ClientName in the client's Certificate | `handshake_failure` (draft §8.2 step 3) |
| A syntactically invalid ClientName in the client's Certificate | `handshake_failure` |
| A duplicate `dane_clientid` on the leaf CertificateEntry | `decode_error` |
| A non-empty ClientName in a CertificateRequest | `decode_error` |

What counts as a valid ClientName:
- ASCII letters, digits, hyphens and underscores only.
- At most 253 octets.
- Valid label lengths, and no trailing dot.

The server checks the name before `VerifyConnection` runs, so a bad name
never causes a DNS query. The client does not validate the name it
sends, apart from the 255-octet wire limit, so that interop tests can
send malformed names on purpose.

The fork also changes upstream's `VerifyConnection` error handling. An
error that wraps an `AlertError` selects the alert that is sent; upstream
always sends `bad_certificate`. Non-fatal values (close_notify,
user_canceled, no_renegotiation) still fall back to `bad_certificate`.
This change applies to TLS 1.2 as well.

### `daneauth/`: the glue

`daneauth` connects the fork to `dane/v2`, and gives servers and clients
ready-made configurations.

**Server** (`NewServer`, in `server.go`). The base config sets:
- `MinVersion` TLS 1.3
- `DANEClientAuth`
- `SessionTicketsDisabled`
- `ClientAuth = RequestClientCert` under both policies

`VerifyConnection` then runs the checks of draft section 8.2. The
mapping is also in the package documentation (`doc.go`):

| Step in `Server.verify` | Check | Reason logged on failure |
|---|---|---|
| 1 | The client sent a `dane_clientid`. This also covers a client that sent no certificate. | `no dane_clientid` |
| 2 | The ClientName is on the allowlist. This runs before any DNS query. | `name not allowed` |
| 3 | TLSA lookup at the ClientName. It is limited by `LookupTimeout` (default 5s), served from the cache when possible, and requires AD=1. | `tlsa lookup: ...` |
| 4 | `dane.Verify` with `RoleClient`: at least one record must match the chain. | `no matching tlsa` or `name mismatch` |
| 5 | Authenticated. | n/a |

Policies:
- **`Required`** is the default. Every failure aborts the handshake with
  `handshake_failure` (40).
- **`Optional`**: the handshake completes, and the client is recorded as
  unauthenticated along with the reason. The exception is a name
  mismatch (`dane.ErrNameMismatch`), which aborts with 40 under both
  policies. That happens when the TLSA data matches but the ClientName
  isn't a SAN dNSName of the certificate. The draft's MUST here has no
  policy escape.
- Failures that the fork itself detects, such as a malformed
  `dane_clientid` or a bad CertificateVerify, send the fork's own alerts.

Per-connection results:
- `Server()` and `NewListener()` wrap each connection in a `resultConn`.
  It holds an `atomic.Pointer[AuthResult]`.
- `GetConfigForClient` clones the base config and installs a
  `VerifyConnection` closure that stores the result into that pointer.
- `Result(c)` returns nil until the handshake has completed. This
  is because `VerifyConnection` runs before the client's
  CertificateVerify is checked (upstream's ordering), so a result must
  never be visible before then.
- `TLSConfig()` returns a copy of the base config. The copy's own
  `VerifyConnection` rejects every connection, so if a caller removes
  `GetConfigForClient`, the server fails closed rather than skipping
  DANE.
- `AuthResult` carries:
  - `Authenticated` and `ClientName` (as sent)
  - the `dane.Result` with per-record results
  - the `RRset`
  - `Cached`, `Reason` and `Err`

TLSA cache (`cache.go`):
- Entries are keyed on the query name, compared case-insensitively.
- Positive answers are cached for the RRset TTL, capped at 3600s.
- Negative answers (NXDOMAIN, NODATA) are cached for the SOA negative
  TTL, or 30s if there isn't one.
- ServFail and Timeout are never cached.
- The cache holds at most 10000 entries. There is no singleflight:
  concurrent lookups of the same uncached name may each send a query.

Allowlist (`allowlist.go`):
- An entry `name` matches that name exactly.
- An entry `.domain` matches that domain and every name below it.
- Matching is label-aware and ASCII case-insensitive.
- A nil `*Allowlist` allows any name.

**Client** (`ClientConfig`, in `client.go`):
- It builds a TLS 1.3 config from a certificate, a key and a ClientName.
- Session resumption is never enabled.
- Server authentication is one of:
  - `ServerAuthPKIX`, the default
  - `ServerAuthDANE`: TLSA at `_port._tcp.ServerName`, with no PKIX
    fallback
  - `ServerAuthInsecure`
- `ServerName` and `Port` are fixed in the config, so each config serves
  one origin.

**HTTP** (`http.go`):
- HTTP/1.1 only. Go's `net/http` negotiates HTTP/2 only with the
  standard `crypto/tls`.
- The server serves through `NewListener`, and `http.Server.TLSConfig`
  is nil. So `r.TLS` is nil in handlers; use `RequestResult(r)` instead.
- `RequireDANE(h)` returns 403 to unauthenticated clients.
- `HTTPClient(cfg)` dials with the fork.

### `github.com/shuque/dane/v2`: DANE lookup and verification

[dane/v2](https://github.com/shuque/dane/tree/master/v2) is a separate
module, pinned at `v2.0.0` in `go.mod`. It is an application-neutral
rewrite of the v1 `dane` library. It never makes connections; it only
looks up TLSA records and verifies certificate chains. Because it takes
a `[]*x509.Certificate`, it depends on neither this fork nor any
particular TLS version. See its
[README](https://github.com/shuque/dane/blob/master/v2/README.md).

Important Details:

- **Trust model:** it trusts the AD bit from a validating resolver, so
  the path to that resolver must be secure, ideally loopback. It does no
  DNSSEC validation of its own.
- **Lookup classification:** a lookup is classified in this order:
  1. rcode
  2. question-section match
  3. AD bit
  4. NXDOMAIN or NODATA

  An unauthenticated denial is `ErrInsecure`, never `ErrNXDOMAIN` or
  `ErrNoData`. CNAMEs are followed for up to 8 hops; a loop or a longer
  chain gives `ErrServFail`.
- **`RoleClient` name check:**
  - A SAN dNSName must equal the ClientName exactly.
  - Case is folded for ASCII only, and no wildcards are allowed.
  - The name may contain only the characters `[A-Za-z0-9_.-]`.
  - DANE-EE (usage 3) does no name check and no expiry check, as RFC
    7671 §5.1 says.
- **`Role` default:** the zero value of `Role` is `RoleServer`, so
  client-authentication callers must set `RoleClient`.
- **Coverage:** all four usages, both selectors and all three matching
  types are supported, as is digest algorithm agility (RFC 7671 §9).
  The cause of each record's failure is in `RecordResult.Err`.

### Demo programs

- **`cmd/danecert`** generates test credentials. It writes keys and
  certificates, and prints the TLSA record to publish.
  - `ee`: a self-signed certificate for DANE-EE, and a `3 1 1` record.
  - `ca` and `issue`: a private CA, and a client certificate it signs
    for DANE-TA, with a `2 0 1` record. `issue` refuses ClientNames with
    underscore labels unless given `-allow-underscore`, because RFC 5280
    doesn't allow underscores in a dNSName.
- **`cmd/daneserver`** is an HTTPS server with three routes:
  - `/`: plain-text status
  - `/whoami`: JSON detail of the result
  - `/private`: wrapped in `RequireDANE`

  It logs one line per connection, and with `-v` one line per
  verification step.
- **`cmd/daneclient`** is an HTTPS client. It prints:
  - the TLS version and cipher suite
  - whether the server asked for `dane_clientid`
  - the server-authentication outcome
  - the HTTP response, or the TLS alert it received

## Repository layout

| Path | Contents |
|---|---|
| `tls/` | The `crypto/tls` fork with `dane_clientid`. The DANE code is in `dane.go` and `dane_test.go`. The shims are in `internal/`, and `UPSTREAM.md` describes the fork. |
| `daneauth/allowlist.go` | ClientName allowlist |
| `daneauth/cache.go` | TLSA cache |
| `daneauth/server.go` | `NewServer` and the §8.2 steps |
| `daneauth/client.go` | `ClientConfig` and DANE server authentication |
| `daneauth/http.go` | `net/http` adapters |
| `daneauth/doc.go` | Package documentation that maps the §8.2 steps to the code |
| `daneauth/live_test.go` | Opt-in tests against real TLSA records |
| `cmd/danecert/` | Test-credential generator |
| `cmd/daneserver/` | Demo HTTPS server |
| `cmd/daneclient/` | Demo HTTPS client |
| `docs/testing.md` | Live-test and interop guide |

## Design decisions

- **Alerts for a misplaced `dane_clientid`** follow the general TLS
  rules (RFC 9846 §4.3):
  - `illegal_parameter` when extension 63 appears in a message it is
    not specified for. IANA lists 63 for CertificateRequest and
    Certificate only.
  - `unsupported_extension` when it appears in a response that nobody
    requested.
- **A client with no certificate under `Required` gets
  `handshake_failure` (40)**, as draft §8.2 step 3 says, rather than
  `certificate_required` (116). That's why the server uses
  `RequestClientCert` instead of `RequireAnyClientCert`. Either alert
  would be defensible, but using 116 would need a change to the spec.
- **A name mismatch aborts even under `Optional`,** while a lookup or
  match failure can fall back to unauthenticated. The asymmetry comes
  from §8.2 and is probably unintended, but it is harmless:
  - Under `Required`, the result is the same either way.
  - A local policy may still choose to accept a failed TLSA data match.
- **A CertificateRequest with a non-empty ClientName is rejected with
  `decode_error`.** The draft defines only the empty form there, but
  doesn't say explicitly that anything else is an error.
- **The fork lives in this repository** as a subpackage, so the project
  is self-contained. It could move to its own module if other projects
  need it.
- **Session resumption is disabled.** On a resumed TLS 1.3 handshake the
  client sends no Certificate message, so no ClientName arrives. On such
  a connection the fork reports `DANEClientName == ""` and
  `DidResume == true`. The glue therefore disables session tickets on
  the server, and leaves the client session cache unset.

## Open questions

- **Session resumption.** The draft doesn't say how resumption interacts
  with `dane_clientid`. The options are:
  - carry the authenticated ClientName in the session ticket
  - re-check TLSA on resumption
  - disallow resumption

  The prototype will be revisited once the spec settles this.

## Known limitations

These come from the fork. See [tls/UPSTREAM.md](tls/UPSTREAM.md) for
details.

- The GODEBUG settings owned by `crypto/tls` (`tlsmlkem`, `tlssecpmlkem`,
  `tlssha1`, `tlsmaxrsasize`, `fips140ems`) are ignored, so upstream
  defaults always apply.
- BoringCrypto and `crypto/tls/fipsonly` are not supported.
- Under `GODEBUG=fips140=only`, the AES-GCM cipher suites panic.

## Testing

- **Unit tests** (`go test ./...`) need no network access.
  - DNS is served by an in-process fake (`dane/v2/danetest`), and TLS
    runs over loopback.
  - The fork keeps the upstream `crypto/tls` test suite.
  - The fork adds tests for the `dane_clientid` encoding and for each
    row of the protocol-error table above.
  - The `daneauth` tests cover:
    - both policies
    - the allowlist rejecting a name with no DNS query sent
    - lookup timeouts
    - cache hits
- **Live tests** (`daneauth/live_test.go`) use real published TLSA
  records and a real validating resolver.
  - They run only with `DANECLIENT_LIVE=1`, and then
    `DANECLIENT_LIVE_RESOLVER` (`host:port`) must also be set.
  - The identities come from `DANECLIENT_LIVE_EE_{NAME,CERT,KEY}` and
    `DANECLIENT_LIVE_TA_{NAME,CERT,KEY,CHAIN}`.
  - File paths must be absolute.
  - See [docs/testing.md](docs/testing.md).
- **Usage coverage:** live and interop testing concentrates on DANE-EE
  and DANE-TA, using self-signed certificates or a private CA. This
  sidesteps public-CA problems: the clientAuth EKU being phased out,
  and underscore names. PKIX-TA and PKIX-EE are covered by unit tests
  only.
