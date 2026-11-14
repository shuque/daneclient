package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDANECertificateRequestRoundTrip(t *testing.T) {
	m := &certificateRequestMsgTLS13{daneClientID: true}
	data := mustMarshal(t, m)
	if !bytes.Contains(data, []byte{0x00, 0x3f, 0x00, 0x01, 0x00}) {
		t.Fatalf("missing dane_clientid bytes in %x", data)
	}
	var got certificateRequestMsgTLS13
	if !got.unmarshal(data) || !got.daneClientID {
		t.Fatalf("unmarshal failed or flag not set: %+v", got)
	}
}

func TestDANECertificateRequestNonEmptyRejected(t *testing.T) {
	// type, len24, ctx len 0, extensions len 8, ext 63, len 4, data 03 'abc'
	data := []byte{typeCertificateRequest, 0, 0, 11, 0, 0, 8, 0x00, 0x3f, 0x00, 0x04, 3, 'a', 'b', 'c'}
	var got certificateRequestMsgTLS13
	if got.unmarshal(data) {
		t.Fatal("non-empty ClientName in CertificateRequest accepted")
	}
}

func TestDANECertificateRoundTrip(t *testing.T) {
	const name = "_smtp._client.mta1.example.com"
	m := &certificateMsgTLS13{daneClientID: true, daneClientName: name}
	m.certificate.Certificate = [][]byte{{1, 2, 3}, {4, 5, 6}}
	data := mustMarshal(t, m)
	ext := append([]byte{0x00, 0x3f, 0x00, byte(len(name) + 1), byte(len(name))}, name...)
	if n := bytes.Count(data, ext); n != 1 {
		t.Fatalf("ext appears %d times, want 1", n)
	}
	// Entry 0: cert(3+3) then extensions length 2 bytes; ext must follow it.
	// Offsets: 4 hdr + 1 ctx + 3 list len + 3 cert len + 3 cert = 14.
	if !bytes.HasPrefix(data[14:], append([]byte{0, byte(len(ext))}, ext...)) {
		t.Fatalf("ext not in entry 0: %x", data)
	}
	var got certificateMsgTLS13
	if !got.unmarshal(data) {
		t.Fatal("unmarshal failed")
	}
	if !got.daneClientID || got.daneClientName != name || len(got.certificate.Certificate) != 2 {
		t.Fatalf("bad round trip: %+v", got)
	}
}

func daneCertBytes(extData []byte) []byte {
	ext := append([]byte{0x00, 0x3f, 0x00, byte(len(extData))}, extData...)
	// one entry: cert (len24=1, 0x09), extensions (len16, ext)
	entry := append([]byte{0, 0, 1, 9, 0, byte(len(ext))}, ext...)
	// ctx(1) + cert list (len24, entry)
	msg := append([]byte{0, 0, byte(len(entry))}, entry...)
	msg = append([]byte{0}, msg...)
	return append([]byte{typeCertificate, 0, 0, byte(len(msg))}, msg...)
}

func TestDANECertificateZeroLength(t *testing.T) {
	var got certificateMsgTLS13
	if !got.unmarshal(daneCertBytes([]byte{0})) {
		t.Fatal("unmarshal failed")
	}
	if !got.daneClientID || got.daneClientName != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestDANECertificateMalformed(t *testing.T) {
	for _, d := range [][]byte{{5, 'a'}, {1, 'a', 'b'}, {}} {
		var got certificateMsgTLS13
		if got.unmarshal(daneCertBytes(d)) {
			t.Errorf("accepted malformed %x", d)
		}
	}
}

func TestDANEClientNameTooLong(t *testing.T) {
	m := &certificateMsgTLS13{daneClientID: true, daneClientName: strings.Repeat("a", 256)}
	m.certificate.Certificate = [][]byte{{1}}
	if _, err := m.marshal(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDANEClientHelloFlag(t *testing.T) {
	m := &clientHelloMsg{
		vers: VersionTLS12, random: make([]byte, 32),
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{0},
		serverName: "example.com",
	}
	base := mustMarshal(t, m)
	// Walk to the extensions length: 4 hdr, 2 vers, 32 random, sid, suites, comp.
	off := 4 + 2 + 32
	off += 1 + int(base[off])
	off += 2 + (int(base[off])<<8 | int(base[off+1]))
	off += 1 + int(base[off])
	out := append(append([]byte{}, base...), 0x00, 0x3f, 0x00, 0x01, 0x00)
	el := len(out) - off - 2
	out[off], out[off+1] = byte(el>>8), byte(el)
	n := len(out) - 4
	out[1], out[2], out[3] = byte(n>>16), byte(n>>8), byte(n)
	var got clientHelloMsg
	if !got.unmarshal(out) {
		t.Fatal("unmarshal failed")
	}
	if !got.daneClientIDInCH {
		t.Fatal("flag not set")
	}
	if !got.unmarshal(base) || got.daneClientIDInCH {
		t.Fatal("flag set without extension")
	}
}

func TestValidClientName(t *testing.T) {
	label := func(n int) string { return strings.Repeat("a", n) }
	// 253 octets: 3 labels of 63 + 1 of 61 with dots = 63*3+61+3 = 253
	long253 := label(63) + "." + label(63) + "." + label(63) + "." + label(61)
	long254 := label(63) + "." + label(63) + "." + label(63) + "." + label(62)
	valid := []string{"a.example.com", "_smtp._client.mta1.example.com", "sensor7._device.example.com", long253, "xn--bcher-kva.example"}
	invalid := []string{"", "a.example.com.", "a..b", label(64) + ".com", long254, "a b.com", "a\\.b.com", "bücher.example"}
	if len(long253) != 253 || len(long254) != 254 {
		t.Fatal("bad test data")
	}
	for _, n := range valid {
		if !validClientName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range invalid {
		if validClientName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestDANECertificateDuplicateRejected(t *testing.T) {
	one := []byte{0x00, 0x3f, 0x00, 0x02, 0x01, 'a'}
	ext := append(append([]byte{}, one...), one...)
	entry := append([]byte{0, 0, 1, 9, 0, byte(len(ext))}, ext...)
	msg := append([]byte{0, 0, byte(len(entry))}, entry...)
	msg = append([]byte{0}, msg...)
	data := append([]byte{typeCertificate, 0, 0, byte(len(msg))}, msg...)
	var got certificateMsgTLS13
	if got.unmarshal(data) {
		t.Fatal("duplicate dane_clientid in leaf entry accepted")
	}
}

// --- handshake behaviour ---

func daneTestCert(t *testing.T) Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dane test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type daneResult struct {
	serverState, clientState ConnectionState
	serverErr, clientErr     error
}

// runDANE does a handshake over a local TCP pipe. clientErr includes any
// alert the client received after its handshake finished.
func runDANE(t *testing.T, cli, srv *Config) daneResult {
	t.Helper()
	var r daneResult
	c, s := localPipe(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		cc := Client(c, cli)
		if err := cc.Handshake(); err != nil {
			r.clientErr = err
			c.Close()
			return
		}
		r.clientState = cc.ConnectionState()
		_, err := io.ReadAll(cc)
		r.clientErr = err
		c.Close()
	}()
	sc := Server(s, srv)
	r.serverErr = sc.Handshake()
	if r.serverErr == nil {
		r.serverState = sc.ConnectionState()
		sc.Close()
	}
	s.Close()
	<-done
	return r
}

func daneConfigs(t *testing.T) (cli, srv *Config) {
	cert := daneTestCert(t)
	cli = &Config{InsecureSkipVerify: true, MinVersion: VersionTLS13, Certificates: []Certificate{cert}}
	srv = &Config{Certificates: []Certificate{daneTestCert(t)}, MinVersion: VersionTLS13, ClientAuth: RequireAnyClientCert}
	return
}

func wantAlert(t *testing.T, err error, want alert) {
	t.Helper()
	a, ok := errors.AsType[alert](err)
	if !ok || a != want {
		t.Fatalf("got error %v, want alert %d", err, want)
	}
}

func TestDANEHappyPath(t *testing.T) {
	const name = "dev1._device.example.com"
	cli, srv := daneConfigs(t)
	srv.DANEClientAuth = true
	cli.DANEClientName = name
	var seen string
	srv.VerifyConnection = func(cs ConnectionState) error { seen = cs.DANEClientName; return nil }
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil {
		t.Fatalf("server %v, client %v", r.serverErr, r.clientErr)
	}
	if seen != name || r.serverState.DANEClientName != name {
		t.Fatalf("VerifyConnection saw %q, final state %q", seen, r.serverState.DANEClientName)
	}
	if !r.clientState.DANEClientIDRequested {
		t.Fatal("client DANEClientIDRequested false")
	}
}

func TestDANEServerNotAdvertising(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.DANEClientName = "dev1._device.example.com"
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil {
		t.Fatalf("server %v, client %v", r.serverErr, r.clientErr)
	}
	if r.serverState.DANEClientName != "" || r.clientState.DANEClientIDRequested {
		t.Fatalf("name %q requested %v", r.serverState.DANEClientName, r.clientState.DANEClientIDRequested)
	}
}

func TestDANEUnsolicited(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.DANEClientName = "dev1._device.example.com"
	cli.testingForceDANEExt = true
	r := runDANE(t, cli, srv)
	if r.serverErr == nil || !strings.Contains(r.serverErr.Error(), "unsupported extension") {
		t.Fatalf("server error %v", r.serverErr)
	}
	wantAlert(t, r.clientErr, alertUnsupportedExtension)
}

func TestDANEZeroLengthName(t *testing.T) {
	cli, srv := daneConfigs(t)
	srv.DANEClientAuth = true
	cli.testingForceDANEExt = true // name ""
	r := runDANE(t, cli, srv)
	if r.serverErr == nil {
		t.Fatal("server accepted zero-length name")
	}
	wantAlert(t, r.clientErr, alertHandshakeFailure)
}

func TestDANEInvalidName(t *testing.T) {
	cli, srv := daneConfigs(t)
	srv.DANEClientAuth = true
	cli.DANEClientName = "a..example.com"
	calls := 0
	srv.VerifyConnection = func(ConnectionState) error { calls++; return nil }
	r := runDANE(t, cli, srv)
	if r.serverErr == nil {
		t.Fatal("server accepted invalid name")
	}
	wantAlert(t, r.clientErr, alertHandshakeFailure)
	if calls != 0 {
		t.Fatalf("VerifyConnection called %d times", calls)
	}
}

func TestDANEInClientHello(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.testingDANEInCH = true
	r := runDANE(t, cli, srv)
	if r.serverErr == nil {
		t.Fatal("server accepted dane_clientid in ClientHello")
	}
	wantAlert(t, r.clientErr, alertIllegalParameter)
}

func TestDANEClientNoCert(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.Certificates = nil
	cli.DANEClientName = "dev1._device.example.com"
	srv.ClientAuth = RequestClientCert
	srv.DANEClientAuth = true
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil {
		t.Fatalf("server %v, client %v", r.serverErr, r.clientErr)
	}
	if r.serverState.DANEClientName != "" {
		t.Fatalf("server saw %q", r.serverState.DANEClientName)
	}
}

func TestDANENoCertRequest(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.DANEClientName = "dev1._device.example.com"
	srv.ClientAuth = NoClientCert
	srv.DANEClientAuth = true
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil {
		t.Fatalf("server %v, client %v", r.serverErr, r.clientErr)
	}
	if r.clientState.DANEClientIDRequested || r.serverState.DANEClientName != "" {
		t.Fatal("unexpected DANE state")
	}
}

func TestDANETLS12Ignored(t *testing.T) {
	cli, srv := daneConfigs(t)
	cli.MinVersion, cli.MaxVersion = VersionTLS12, VersionTLS12
	srv.MinVersion, srv.MaxVersion = VersionTLS12, VersionTLS12
	srv.DANEClientAuth = true
	cli.DANEClientName = "dev1._device.example.com"
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil {
		t.Fatalf("server %v, client %v", r.serverErr, r.clientErr)
	}
	if r.serverState.DANEClientName != "" || r.clientState.DANEClientIDRequested {
		t.Fatal("DANE state set on TLS 1.2")
	}
}

func TestDANEServerCertCarries63(t *testing.T) {
	// A server that (wrongly) sends dane_clientid in its Certificate must be
	// rejected by the client with unsupported_extension. Exercise the helper
	// that the client handshake uses.
	cp, sp := net.Pipe()
	got := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(sp); got <- b }()
	c := Client(cp, &Config{})
	if err := c.checkDANEServerCert(&certificateMsgTLS13{daneClientID: true}); err == nil {
		t.Fatal("no error for dane_clientid in server Certificate")
	}
	cp.Close()
	if b := <-got; len(b) < 7 || b[0] != byte(recordTypeAlert) || b[len(b)-2] != alertLevelError || b[len(b)-1] != byte(alertUnsupportedExtension) {
		t.Fatalf("alert 110 not sent: %x", b)
	}
	if err := c.checkDANEServerCert(&certificateMsgTLS13{}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyConnectionAlertError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		want   alert
		client bool // VerifyConnection on the client; the server sees the alert
		tls12  bool
	}{
		{name: "server alert", err: fmt.Errorf("no: %w", AlertError(alertHandshakeFailure)), want: alertHandshakeFailure},
		{name: "server plain", err: errors.New("no"), want: alertBadCertificate},
		{name: "server close_notify", err: AlertError(alertCloseNotify), want: alertBadCertificate},
		{name: "server user_canceled", err: AlertError(alertUserCanceled), want: alertBadCertificate},
		{name: "server no_renegotiation", err: AlertError(alertNoRenegotiation), want: alertBadCertificate},
		{name: "client alert", err: AlertError(alertHandshakeFailure), want: alertHandshakeFailure, client: true},
		{name: "tls12 server alert", err: AlertError(alertHandshakeFailure), want: alertHandshakeFailure, tls12: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := daneConfigs(t)
			if tc.tls12 {
				cli.MinVersion, cli.MaxVersion = VersionTLS12, VersionTLS12
				srv.MinVersion, srv.MaxVersion = VersionTLS12, VersionTLS12
			}
			fail := func(ConnectionState) error { return tc.err }
			if tc.client {
				cli.VerifyConnection = fail
			} else {
				srv.VerifyConnection = fail
			}
			r := runDANE(t, cli, srv)
			if tc.client {
				if r.clientErr == nil {
					t.Fatal("client accepted")
				}
				wantAlert(t, r.serverErr, tc.want)
				return
			}
			if r.serverErr == nil {
				t.Fatal("server accepted")
			}
			wantAlert(t, r.clientErr, tc.want)
		})
	}
}

func TestDANEInSecondClientHello(t *testing.T) {
	cli, srv := daneConfigs(t)
	// Force a HelloRetryRequest: the client's first key share is not
	// acceptable to the server.
	cli.CurvePreferences = []CurveID{CurveP256, CurveP384}
	srv.CurvePreferences = []CurveID{CurveP384}
	r := runDANE(t, cli, srv)
	if r.serverErr != nil || r.clientErr != nil || !r.serverState.HelloRetryRequest {
		t.Fatalf("baseline: HRR %v, server %v, client %v", r.serverState.HelloRetryRequest, r.serverErr, r.clientErr)
	}
	cli.testingDANEInCH2 = true
	r = runDANE(t, cli, srv)
	if r.serverErr == nil {
		t.Fatal("server accepted dane_clientid in second ClientHello")
	}
	wantAlert(t, r.clientErr, alertIllegalParameter)
}

func TestDANESetClientIDEmptyCert(t *testing.T) {
	m := &certificateMsgTLS13{}
	m.setDANEClientID(&Config{DANEClientName: "dev1._device.example.com"}, true)
	if m.daneClientID {
		t.Fatal("extension set on empty Certificate")
	}
	m.certificate.Certificate = [][]byte{{1}}
	m.setDANEClientID(&Config{DANEClientName: "dev1._device.example.com"}, true)
	if !m.daneClientID || m.daneClientName != "dev1._device.example.com" {
		t.Fatalf("extension not set: %+v", m)
	}
}

func TestDANEConfigClone(t *testing.T) {
	c := &Config{DANEClientAuth: true, DANEClientName: "x._y.example.com", testingForceDANEExt: true, testingDANEInCH: true, testingDANEInCH2: true}
	d := c.Clone()
	if !d.DANEClientAuth || d.DANEClientName != c.DANEClientName || !d.testingForceDANEExt || !d.testingDANEInCH || !d.testingDANEInCH2 {
		t.Fatalf("clone lost fields: %+v", d)
	}
}
