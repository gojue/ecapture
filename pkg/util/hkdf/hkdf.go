// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hkdf

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Mostly derived from golang.org/x/crypto/hkdf, but with an exposed
// Extract API.
//
// HKDF is a cryptographic key derivation function (KDF) with the goal of
// expanding limited input keying material into one or more cryptographically
// strong secret keys.
//
// RFC 5869: https://tools.ietf.org/html/rfc5869

import (
	"crypto"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const (
	ResumptionBinderLabel         = "res binder"
	ClientHandshakeTrafficLabel   = "c hs traffic"
	ServerHandshakeTrafficLabel   = "s hs traffic"
	ClientApplicationTrafficLabel = "c ap traffic"
	ServerApplicationTrafficLabel = "s ap traffic"
	ExporterLabel                 = "exp master"
	ResumptionLabel               = "res master"
	TrafficUpdateLabel            = "traffic upd"
)

const (
	KeyLogLabelTLS12                   = "CLIENT_RANDOM"
	KeyLogLabelClientHandshake         = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelServerHandshake         = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelClientTraffic           = "CLIENT_TRAFFIC_SECRET_0"
	KeyLogLabelServerTraffic           = "SERVER_TRAFFIC_SECRET_0"
	KeyLogLabelExporterSecret          = "EXPORTER_SECRET"
	KeyLogLabelClientEarlyTafficSecret = "CLIENT_EARLY_TRAFFIC_SECRET"
)

// crypto/tls/cipher_suites.go line 678
// TLS 1.3 cipher suites.
const (
	TlsAes128GcmSha256        uint16 = 0x1301
	TlsAes256GcmSha384        uint16 = 0x1302
	TlsChacha20Poly1305Sha256 uint16 = 0x1303
)

// ExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func ExpandLabel(secret []byte, label string, context []byte, length int, transcript crypto.Hash) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context[:length])
	})
	out := make([]byte, length)

	n, err := hkdf.Expand(transcript.New, secret[:length], hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
