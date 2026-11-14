// DANE client authentication (draft-ietf-dance-client-auth): wire encoding
// of the dane_clientid extension. This file holds the helpers; the hooks in
// handshake_messages.go are kept as small as possible.

package tls

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// daneExt carries the dane_clientid extension state for a Certificate
// message's leaf entry.
type daneExt struct {
	present bool
	name    string
}

var errDANEClientNameTooLong = errors.New("tls: dane_clientid ClientName longer than 255 octets")

// validClientName reports whether name is a valid ClientName: 1..253 octets,
// no trailing dot, each dot-separated label 1..63 octets of [A-Za-z0-9_-].
func validClientName(name string) bool {
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// addDANEClientID appends a dane_clientid extension carrying name (which may
// be empty) to b. The caller must have checked len(name) <= 255.
func addDANEClientID(b *cryptobyte.Builder, name string) {
	b.AddUint16(extensionDANEClientID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(name))
		})
	})
}

// readDANEClientName parses dane_clientid extension_data: a one-byte length
// and that many bytes, with nothing trailing. If emptyOnly is set, only the
// zero-length form is accepted (CertificateRequest).
func readDANEClientName(extData *cryptobyte.String, name *string, emptyOnly bool) bool {
	var n cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&n) || !extData.Empty() {
		return false
	}
	if emptyOnly && !n.Empty() {
		return false
	}
	*name = string(n)
	return true
}

// alertFromVerifyErr chooses the alert to send when Config.VerifyConnection
// fails: the alert wrapped by err (as an AlertError), else bad_certificate.
// Non-fatal alerts (close_notify, user_canceled, no_renegotiation) are not
// honoured, so the peer always sees a fatal alert.
func alertFromVerifyErr(err error) alert {
	if a, ok := errors.AsType[AlertError](err); ok {
		switch alert(a) {
		case alertCloseNotify, alertUserCanceled, alertNoRenegotiation:
		default:
			return alert(a)
		}
	}
	return alertBadCertificate
}

// checkDANEClientHello rejects a ClientHello carrying dane_clientid, which is
// only allowed in CertificateRequest and Certificate.
func (c *Conn) checkDANEClientHello(hello *clientHelloMsg) error {
	if hello.daneClientIDInCH {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client sent dane_clientid in ClientHello")
	}
	return nil
}

// checkDANEClientCert validates the dane_clientid extension of a TLS 1.3
// client Certificate message, and records the ClientName. It runs before any
// certificate or VerifyConnection processing, so a bad name triggers no
// further work. A message without the extension (including an empty
// Certificate) leaves the name empty.
func (c *Conn) checkDANEClientCert(m *certificateMsgTLS13, advertised bool) error {
	if !m.daneClientID {
		return nil
	}
	if !advertised {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: client Certificate carries unsupported extension dane_clientid (not requested)")
	}
	if m.daneClientName == "" {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: dane_clientid ClientName is empty")
	}
	if !validClientName(m.daneClientName) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: dane_clientid ClientName is not a valid DNS name")
	}
	c.daneClientName = m.daneClientName
	return nil
}

// checkDANEServerCert rejects a server Certificate carrying dane_clientid.
func (c *Conn) checkDANEServerCert(m *certificateMsgTLS13) error {
	if m.daneClientID {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server Certificate carries unsupported extension dane_clientid")
	}
	return nil
}

// setDANEClientID fills in the dane_clientid extension of a client's
// Certificate message. crAdvertised is whether the server's CertificateRequest
// carried the extension.
func (m *certificateMsgTLS13) setDANEClientID(cfg *Config, crAdvertised bool) {
	if cfg.testingForceDANEExt ||
		(crAdvertised && cfg.DANEClientName != "" && len(m.certificate.Certificate) > 0) {
		m.daneClientID, m.daneClientName = true, cfg.DANEClientName
	}
}

// Server-side test hooks (Config.testingDANEServerExt bits): the server puts
// a dane_clientid extension in the named message, where it is not allowed.
const (
	daneHookServerHello uint8 = 1 << iota
	daneHookHRR
	daneHookEncryptedExtensions
	daneHookNewSessionTicket
	daneHookCertificate
)

// checkDANEMisplaced rejects dane_clientid in a server message it is not
// defined for (RFC 8446 section 4.2): illegal_parameter.
func (c *Conn) checkDANEMisplaced(present bool, msg string) error {
	if present {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent dane_clientid in " + msg)
	}
	return nil
}

// RemoteAlert returns the TLS alert that the peer sent, if err is the error
// this package returns when it receives an alert (a *net.OpError with Op
// "remote error"). It also accepts an error wrapping an [AlertError], which
// is how QUIC connections report alerts. Note that the latter also matches an
// AlertError that a local VerifyConnection returned, so use it on the error
// from the peer's side of the connection.
func RemoteAlert(err error) (AlertError, bool) {
	if oe, ok := errors.AsType[*net.OpError](err); ok && oe.Op == "remote error" {
		if a, ok := oe.Err.(alert); ok {
			return AlertError(a), true
		}
	}
	if a, ok := errors.AsType[AlertError](err); ok {
		return a, true
	}
	return 0, false
}
