// DANE client authentication (draft-ietf-dance-client-auth): wire encoding
// of the dane_clientid extension. This file holds the helpers; the hooks in
// handshake_messages.go are kept as small as possible.

package tls

import (
	"errors"
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
