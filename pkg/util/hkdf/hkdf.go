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
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
	"hash"
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
	KeyLogLabelTLS12           = "CLIENT_RANDOM"
	KeyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	KeyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
	KeyLogLabelExporterSecret  = "EXPORTER_SECRET"
)

const (
	// crypto/tls/cipher_suites.go line 678
	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func expandLabel(secret []byte, label string, context []byte, length int, cipherId uint32) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)

	var transcript crypto.Hash
	switch uint16(cipherId & 0x0000FFFF) {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		transcript = crypto.SHA256
	case TLS_AES_256_GCM_SHA384:
		transcript = crypto.SHA384
	default:
		panic(fmt.Sprintf("Unknown cipher: %d", cipherId))
	}
	n, err := hkdf.Expand(transcript.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// from crypto/tls/key_schedule.go line 35
// DeriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func DeriveSecret(secret []byte, label string, transcript hash.Hash, cipherId uint32) []byte {
	return expandLabel(secret, label, transcript.Sum(nil), transcript.Size(), cipherId)
}
