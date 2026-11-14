# Upstream

## Base version
go1.27.4 darwin/arm64

## Source path
/usr/local/go/src/crypto/tls

## Commit history

1. Pristine copy of `crypto/tls` (plus `internal/fips140tls` and
   `testdata/`) from go1.27.4. Does not build outside GOROOT.
2. De-internalization: std-internal imports replaced with local shims (below),
   `//go:linkname` directives removed, BoringCrypto support removed. No
   feature changes. Builds outside GOROOT; upstream tests pass.

## Shims

All shims live under `tls/internal/` (module path
`github.com/shuque/daneclient/tls/internal/...`).

| Upstream import | Replacement | Reason |
|---|---|---|
| `crypto/internal/fips140/tls13` | `internal/tls13` | Copy of upstream, using public `crypto/hkdf` (panics on its error return, which cannot occur for crypto/tls inputs) and `encoding/binary` |
| `crypto/internal/fips140/tls12` | `internal/tls12` | Copy of upstream, using public `crypto/hmac`; FIPS 140-3 service-indicator (`RecordNonApproved`) calls dropped |
| `crypto/internal/fips140/aes/gcm` | `internal/gcm` | `NewGCMForTLS12`/`NewGCMForTLS13` are `cipher.NewGCM`; upstream's extra nonce-sequence checks are FIPS-only and do not change output |
| `crypto/internal/fips140/aes` (`fipsaes`) | (removed) | `cipher_suites.go` passes the `cipher.Block` from `aes.NewCipher` directly instead of `aes.(*fipsaes.Block)` |
| `crypto/internal/boring` | `internal/boring` | Stub: `const Enabled = false`, `Unreachable()` no-op, `NewGCMTLS`/`NewGCMTLS13` panic. BoringCrypto is not supported |
| `internal/godebug` | `internal/godebug` | Stub: `Value()` always returns `""` (unset, so upstream defaults apply); `IncNonDefault()` no-op. Affects `tlsmlkem`, `tlssecpmlkem`, `tlssha1`, `tlsmaxrsasize`, `fips140ems` |
| `internal/byteorder` | `internal/byteorder` | `BEUint16`, `LEUint32`, `LEPutUint64` over `encoding/binary` |
| `internal/cpu` | `golang.org/x/sys/cpu` (imported as `cpu`) | Same field names (`X86.HasAES`, `ARM64.HasPMULL`, `S390X.HasAESCTR`, ...) |
| `crypto/tls/internal/fips140tls` | `internal/fips140tls` | Verbatim copy; uses only public APIs, so `GODEBUG=fips140=on` behaves as upstream |
| `vendor/golang.org/x/crypto/...` | `golang.org/x/crypto/...` v0.59.0 | Ordinary module dependency (`cryptobyte`, `chacha20poly1305`) |
| `internal/testenv` (tests) | `internal/testenv` | Test-only: `SetGODEBUG` (as upstream, but skips the test if it sets one of the fork's stubbed godebug settings), `MustHaveSource` (no-op except on ios), `MustHaveExternalNetwork` (as upstream) |
| `crypto/internal/cryptotest` (tests) | `internal/cryptotest` | Test-only: `MustMinimumFIPS140ModuleVersion`, as upstream but using public `crypto/fips140.Version` |
| `crypto/internal/rand` (tests) | (removed) | Only used by `benchmarkHandshakeServer` to install a deterministic rand source; that benchmark now `b.Skip`s |

`//go:linkname` directives removed (with their `_ "unsafe"` imports):
`cipherSuitesTLS13`, `aeadAESGCMTLS13` (cipher_suites.go),
`errNoCertificates` (common.go), `defaultCipherSuitesTLS13`,
`defaultCipherSuitesTLS13NoAES` (defaults.go). The "hall of shame" comments
above them are kept.

## Removed files

Removed in commit 1:
- `fipsonly/` (Go+BoringCrypto FIPS-only mode)

Removed in commit 2:
- `bogo_shim_test.go`, `bogo_shim_unix_test.go`, `bogo_shim_notunix_test.go`,
  `bogo_config.json` (BoGo shim; needs internal packages and an external
  BoringSSL checkout). The `-bogo-*` flags and the `bogoMode` branch in
  `TestMain` (handshake_test.go) went with them.
- `fips140_test.go` (FIPS 140-3 / BoringCrypto policy tests; needs
  `crypto/internal/boring`, `RerunWithFIPS140Enabled` and other internal test
  helpers). Its `isFIPSVersion` helper, still used by tls_test.go, is copied
  to the new `fips140_helpers_test.go`; the `testConfigFIPS140.KeyLogWriter`
  line in `runMain` is removed.
- `link_test.go` (linker dead-code test; builds programs against GOROOT
  `crypto/tls`, meaningless for the fork)
- `defaults_boring.go` (`//go:build boringcrypto` policy lists; BoringCrypto
  is not supported). The `//go:build !boringcrypto` constraint is dropped from
  `defaults_fips140.go`, so it is always built.

## Skipped tests

- `TestSignatureSelection` subtests 1, 8, 16, 17 (auth_test.go): set
  `GODEBUG=tlssha1=1`, which the godebug stub ignores.
- `TestHandshakeMLKEM/GODEBUG_tlsmlkem=0`,
  `TestHandshakeMLKEM/GODEBUG_tlssecpmlkem=0`,
  `TestHandshakeMLKEM/CurvePreferences_override_GODEBUG` (tls_test.go): set
  `tlsmlkem=0` / `tlssecpmlkem=0`, which the godebug stub ignores.
- `BenchmarkHandshakeServer` (handshake_server_test.go): needs
  `crypto/internal/rand.SetTestingReader` for a deterministic server.

These skips come from the `testenv.SetGODEBUG` stub, except the benchmark.
All recorded-transcript tests (`TestHandshakeClient*`,
`TestHandshakeServer*` replaying `testdata/`) run and pass.

## Departures

None beyond the de-internalization above.

## Known limitations

- GODEBUG settings owned by crypto/tls (`tlsmlkem`, `tlssecpmlkem`,
  `tlssha1`, `tlsmaxrsasize`, `fips140ems`) are ignored; upstream defaults
  always apply. Settings owned by other std packages (e.g. `rsa1024min`)
  still work.
- BoringCrypto (`GOEXPERIMENT=boringcrypto`) and `crypto/tls/fipsonly` are
  not supported.
- `certificates_test.go` is left as upstream, which is not gofmt-clean
  (`TestGenerateCertificates` compares it byte-for-byte with generated
  output).
