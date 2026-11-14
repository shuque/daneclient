package tls

import (
	"bytes"
	"strings"
	"testing"
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
