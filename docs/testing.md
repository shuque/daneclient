# Testing guide

This is a runbook for exercising the prototype against real DNSSEC-signed
TLSA records. The unit tests (`go test ./...`) need no network. Everything
below is for live, interop-style testing.

The owner names used here (`dev1._device.huque.com`,
`dev1.dane-test.huque.com`) are suggestions. Substitute whatever names you
publish under.

## Prerequisites

- A DNSSEC-validating resolver that sets the AD bit in answers to you. The
  server requires AD on every TLSA answer and treats anything else as a
  lookup failure. Pass it as `host:port` (for example `127.0.0.1:53`).
- Binaries (from the repository root):

      go build -o /tmp/dc/ ./cmd/danecert ./cmd/daneserver ./cmd/daneclient

  This needs the `dane` repo checked out next to this one, on its `v2`
  branch (see the README).
- A TLS certificate for the demo server. The client authenticates it with
  PKIX by default, so for a throwaway server make a self-signed one and
  pass it to the client with `-cafile`:

      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout server.key -out server.crt -subj /CN=localhost -days 30 \
        -addext subjectAltName=DNS:localhost

## 1. Generate client material

`danecert` writes `client.key` and `client.crt` (and `ca.key`/`ca.crt` for
a CA) into the `-out` directory, and prints the TLSA record to publish on
stdout.

DANE-EE (usage 3, self-signed client certificate; the name need not appear
in the certificate, so an underscore name is fine):

    danecert ee -name dev1._device.huque.com -out ee

prints a line like

    dev1._device.huque.com. IN TLSA 3 1 1 <sha256 of the SPKI>

DANE-TA (usage 2, certificate issued by a private CA):

    danecert ca -cn "Test Client CA" -out ca
    danecert issue -ca ca -name dev1.dane-test.huque.com -out ta

prints a line like

    dev1.dane-test.huque.com. IN TLSA 2 0 1 <sha256 of the CA certificate>

The DANE-TA example uses a Format 3 (non-underscore) name because the
client certificate must carry the name as a SAN dNSName, and `issue`
refuses a name with an underscore label unless you pass
`-allow-underscore`. That flag is fine for a private CA.

## 2. Publish and check

Add the printed lines to the DNSSEC-signed zone, re-sign, then check
through the same resolver the tests will use:

    dig +dnssec TLSA dev1._device.huque.com @127.0.0.1
    dig +dnssec TLSA dev1.dane-test.huque.com @127.0.0.1

The header flags must include `ad`, and the answer must contain your
record. If `ad` is missing, the server will reject the client with
"tlsa lookup: ..." however good the record is.

## 3. Live Go tests

The live tests run an in-process `daneauth.Server` (policy Required) and a
client over loopback TCP, with your real resolver. They do nothing, and
touch no network, unless `DANECLIENT_LIVE=1`.

| Variable | Meaning |
|---|---|
| `DANECLIENT_LIVE` | `1` enables the tests |
| `DANECLIENT_LIVE_RESOLVER` | validating resolver `host:port`; required when enabled (the tests fail without it) |
| `DANECLIENT_LIVE_EE_NAME`, `_EE_CERT`, `_EE_KEY` | the DANE-EE name, `ee/client.crt`, `ee/client.key` |
| `DANECLIENT_LIVE_TA_NAME`, `_TA_CERT`, `_TA_KEY` | the DANE-TA name, `ta/client.crt`, `ta/client.key` |
| `DANECLIENT_LIVE_TA_CHAIN` | PEM file with the CA certificate to send (`ca/ca.crt`) |

Each identity is optional: its test skips if its variables are unset.
`TestLiveWrongKey` needs only the resolver and `EE_NAME`.

    DANECLIENT_LIVE=1 DANECLIENT_LIVE_RESOLVER=127.0.0.1:53 \
    DANECLIENT_LIVE_EE_NAME=dev1._device.huque.com \
    DANECLIENT_LIVE_EE_CERT=ee/client.crt DANECLIENT_LIVE_EE_KEY=ee/client.key \
    DANECLIENT_LIVE_TA_NAME=dev1.dane-test.huque.com \
    DANECLIENT_LIVE_TA_CERT=ta/client.crt DANECLIENT_LIVE_TA_KEY=ta/client.key \
    DANECLIENT_LIVE_TA_CHAIN=ca/ca.crt \
    go test ./daneauth/ -run Live -v

Expected: `TestLiveDANEEE` and `TestLiveDANETA` pass, with a logged
"authenticated <name>". `TestLiveWrongKey` presents the EE name with a
fresh key and passes when the client sees TLS alert 40
(handshake_failure). Without the variables you see SKIP lines and PASS.

## 4. Demo server and client

Start the server (here the resolver is local; `-v` logs each
verification step):

    daneserver -listen 127.0.0.1:8443 -cert server.crt -key server.key \
      -resolver 127.0.0.1:53 -v

Routes: `/` (plain text status), `/whoami` (JSON detail of the
authentication result) and `/private` (403 unless DANE-authenticated).

Client, DANE-EE:

    daneclient -cafile server.crt -cert ee/client.crt -key ee/client.key \
      -name dev1._device.huque.com https://localhost:8443/whoami

Client, DANE-TA: send the leaf and CA in one chain file, since `-cert`
takes a chain:

    cat ta/client.crt ca/ca.crt > ta/chain.pem
    daneclient -cafile server.crt -cert ta/chain.pem -key ta/client.key \
      -name dev1.dane-test.huque.com https://localhost:8443/whoami

The client prints the TLS version, cipher suite, whether the server sent
`dane_clientid` in its CertificateRequest, then the HTTP status and body.
`-server-auth` chooses how the server is authenticated: `pkix` (default),
`dane` (TLSA lookup at `_port._tcp.<host>` through `-resolver`) or
`insecure`.

### What to expect

- Success: `/whoami` shows `"authenticated": true`, your `client_name`,
  `"reason": "authenticated"`, the TLSA `rrset` and a per-record
  `results` list. A second request within the TLSA TTL shows
  `"cached": true`. `/private` returns `hello, <name>`.
  With `-v` the server log has `step 1` to `step 5` lines per
  connection ending `authenticated by TLSA 3 1 1`, followed by
  `conn ... client_name="..." reason="authenticated"`.
- Failure under the default `-policy required`: every DANE failure,
  including no certificate and no `dane_clientid`, aborts the handshake
  with alert 40. The client prints `server sent TLS alert: ...` and exits
  non-zero. The server logs `conn ... handshake failed: ...` and the
  failing step (`no dane_clientid`, `name not allowed`, `tlsa lookup: ...`,
  `no matching tlsa`, `name mismatch`).
- Because TLS 1.3 clients finish their handshake before the server judges
  their certificate, the alert can surface on the first read rather than
  on connect. That is normal.

### Scenarios

1. **Wrong key.** Generate a second identity for the same name, with
   `-out ee2`, and do not publish its record. Connect with it. Expect
   alert 40 and `no matching tlsa` in the server log.
2. **Optional vs Required.** Restart the server with `-policy optional`.
   A client with no certificate, or whose DANE check fails, now completes
   the handshake: `/` shows `authenticated: no` with the reason, and
   `/private` returns 403. The exception is a ClientName that does not
   match a SAN dNSName of the certificate (draft section 8.2): that
   aborts with alert 40 under both policies. Test it by publishing the
   same CA record at a second name, then sending that second name with
   `-name` while using the DANE-TA certificate issued for the first.
3. **Allowlist.** Add `-allow dev1.dane-test.huque.com` (exact name) or
   `-allow .huque.com` (that domain and everything below). A
   ClientName outside the list is rejected with `name not allowed`
   before any DNS query is made, which you can confirm by pointing
   `-resolver` at an address with nothing listening.
4. **Usages.** `-usages 2` accepts only DANE-TA records, so the EE
   identity should then fail with `no matching tlsa`.

## Notes and limits

- HTTP/1.1 only. In handlers `r.TLS` is nil because of the TLS fork; use
  `daneauth.RequestResult(r)`.
- Session tickets are disabled, so there is no resumption. A resumed
  connection would carry no ClientName.
- The server accepts TLS 1.3 only.
