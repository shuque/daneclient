// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package byteorder replaces internal/byteorder in this fork of crypto/tls,
// using encoding/binary.
package byteorder

import "encoding/binary"

func BEUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func LEUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func LEPutUint64(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}
