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
	KeyLogLabelTLS12           = "CLIENT_RANDOM"
	KeyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	KeyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

// from crypto/tls/key_schedule.go line 35
//ExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
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
	hash := crypto.SHA256 // TODO  fixme : use cipher_id argument
	n, err := hkdf.Expand(hash.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
