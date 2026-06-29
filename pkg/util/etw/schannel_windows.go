//go:build windows
// +build windows

// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package etw

import (
	"encoding/binary"
	"unicode/utf16"
	"unsafe"

	"github.com/gojue/ecapture/internal/errors"
)

// SchannelEventIds defines well-known Schannel ETW event IDs.
// These correspond to TLS/SSL events from the Microsoft-Windows-Schannel provider.
const (
	// SchannelEventHandshakeComplete fires after a TLS handshake completes
	SchannelEventHandshakeComplete uint16 = 1
	// SchannelEventHandshakeFailure fires when a TLS handshake fails
	SchannelEventHandshakeFailure uint16 = 2
	// SchannelEventHandshakeLogExtended fires with extended handshake info
	SchannelEventHandshakeLogExtended uint16 = 3
	// SchannelEventSslLogEvent for general SSL events
	SchannelEventSslLogEvent uint16 = 4
	// SchannelEventAlertReceived fires on TLS alert reception
	SchannelEventAlertReceived uint16 = 5
	// SchannelEventAlertSent fires on TLS alert transmission
	SchannelEventAlertSent uint16 = 6
	// SchannelEventClientAuthKeyExchange fires during client key exchange
	SchannelEventClientAuthKeyExchange uint16 = 10
	// SchannelEventServerAuthKeyExchange fires during server key exchange
	SchannelEventServerAuthKeyExchange uint16 = 11
	// SchannelEventSessionTicketReceived for TLS session tickets
	SchannelEventSessionTicketReceived uint16 = 12
)

// SchannelProperties defines known property names in Schannel ETW events.
const (
	PropProtocol        = "Protocol"
	PropCipherSuite     = "CipherSuite"
	PropKeyLength       = "KeyLength"
	PropHashAlgorithm   = "HashAlgorithm"
	PropClientRandom    = "ClientRandom"
	PropServerRandom    = "ServerRandom"
	PropMasterSecret    = "MasterSecret"
	PropPeerCertIssuer  = "PeerCertificateIssuer"
	PropPeerCertSubject = "PeerCertificateSubject"
	PropTargetName      = "TargetName"
	PropRemoteAddress   = "RemoteAddress"
	PropRemotePort      = "RemotePort"
	PropProcessName     = "ProcessName"
	PropConnectionId    = "ConnectionId"
	PropAlertLevel      = "AlertLevel"
	PropAlertDesc       = "AlertDescription"
)

// TLS Protocol constants used in Schannel events.
const (
	ProtocolTLS10 uint32 = 0x000000C0
	ProtocolTLS11 uint32 = 0x00000300
	ProtocolTLS12 uint32 = 0x00000C00
	ProtocolTLS13 uint32 = 0x00003000
	ProtocolSSL30 uint32 = 0x00000030
)

// ProtocolName returns a human-readable name for a TLS protocol version.
func ProtocolName(protocol uint32) string {
	switch protocol {
	case ProtocolTLS13:
		return "TLS 1.3"
	case ProtocolTLS12:
		return "TLS 1.2"
	case ProtocolTLS11:
		return "TLS 1.1"
	case ProtocolTLS10:
		return "TLS 1.0"
	case ProtocolSSL30:
		return "SSL 3.0"
	default:
		return "Unknown"
	}
}

// Well-known cipher suite IDs.
const (
	CipherSuiteTLS_AES_128_GCM_SHA256       uint16 = 0x1301
	CipherSuiteTLS_AES_256_GCM_SHA384       uint16 = 0x1302
	CipherSuiteTLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	CipherSuiteTLS_ECDHE_RSA_AES256_GCM     uint16 = 0xC030
	CipherSuiteTLS_ECDHE_RSA_AES128_GCM     uint16 = 0xC02F
)

// SchannelEvent is the parsed representation of a Schannel ETW event.
type SchannelEvent struct {
	EventId      uint16
	Protocol     uint32
	CipherSuite  uint16
	KeyLength    uint32
	HashAlg      uint32
	ExchangeAlg  uint32
	ClientRandom []byte
	ServerRandom []byte
	MasterSecret []byte
	TargetName   string
	RemoteAddr   string
	RemotePort   uint16
	AlertLevel   uint8
	AlertDesc    uint8
	Raw          []byte
}

// ParseSchannelEvent parses the UserData of a Schannel ETW event and fills
// Properties on the supplied EventRecord.
func ParseSchannelEvent(event *EventRecord) *SchannelEvent {
	if event == nil || len(event.UserData) == 0 {
		return nil
	}

	parsed := &SchannelEvent{
		EventId: event.EventId,
		Raw:     append([]byte(nil), event.UserData...),
	}

	// Schannel manifest payloads vary by event ID. The parsers below handle
	// the most common fixed-layout fields; unknown layouts keep the raw bytes.
	switch event.EventId {
	case SchannelEventHandshakeComplete:
		parseHandshakeComplete(event.UserData, parsed)
	case SchannelEventHandshakeFailure:
		parseHandshakeFailure(event.UserData, parsed)
	case SchannelEventHandshakeLogExtended:
		parseHandshakeLogExtended(event.UserData, parsed)
	case SchannelEventSslLogEvent:
		parseSslLogEvent(event.UserData, parsed)
	case SchannelEventAlertReceived, SchannelEventAlertSent:
		parseAlertEvent(event.UserData, parsed)
	}

	// Mirror parsed fields into the generic Properties map so downstream handlers
	// can consume them uniformly.
	if parsed.Protocol != 0 {
		event.Properties[PropProtocol] = parsed.Protocol
	}
	if parsed.CipherSuite != 0 {
		event.Properties[PropCipherSuite] = parsed.CipherSuite
	}
	if parsed.KeyLength != 0 {
		event.Properties[PropKeyLength] = parsed.KeyLength
	}
	if parsed.TargetName != "" {
		event.Properties[PropTargetName] = parsed.TargetName
	}
	if parsed.RemoteAddr != "" {
		event.Properties[PropRemoteAddress] = parsed.RemoteAddr
	}
	if parsed.RemotePort != 0 {
		event.Properties[PropRemotePort] = parsed.RemotePort
	}
	if len(parsed.ClientRandom) > 0 {
		event.Properties[PropClientRandom] = parsed.ClientRandom
	}
	if len(parsed.ServerRandom) > 0 {
		event.Properties[PropServerRandom] = parsed.ServerRandom
	}
	if len(parsed.MasterSecret) > 0 {
		event.Properties[PropMasterSecret] = parsed.MasterSecret
	}
	if parsed.AlertLevel != 0 || parsed.AlertDesc != 0 {
		event.Properties[PropAlertLevel] = parsed.AlertLevel
		event.Properties[PropAlertDesc] = parsed.AlertDesc
	}

	return parsed
}

func parseHandshakeComplete(data []byte, ev *SchannelEvent) {
	if len(data) < 12 {
		return
	}
	ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
	ev.CipherSuite = binary.LittleEndian.Uint16(data[4:6])
	ev.KeyLength = binary.LittleEndian.Uint32(data[8:12])
	if len(data) >= 16 {
		ev.HashAlg = binary.LittleEndian.Uint32(data[12:16])
	}
}

func parseHandshakeFailure(data []byte, ev *SchannelEvent) {
	if len(data) >= 4 {
		ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
	}
	if len(data) >= 8 {
		ev.AlertLevel = data[4]
		ev.AlertDesc = data[5]
	}
}

func parseHandshakeLogExtended(data []byte, ev *SchannelEvent) {
	// Extended handshake events typically carry random values and target name.
	if len(data) < 64 {
		return
	}
	ev.ClientRandom = append([]byte(nil), data[0:32]...)
	ev.ServerRandom = append([]byte(nil), data[32:64]...)
	if len(data) > 64 {
		// Remaining payload may contain target name as a length-prefixed UTF-16LE string.
		if name, ok := readCountedUTF16(data[64:]); ok {
			ev.TargetName = name
		}
	}
}

func parseSslLogEvent(data []byte, ev *SchannelEvent) {
	if len(data) < 4 {
		return
	}
	ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
}

func parseAlertEvent(data []byte, ev *SchannelEvent) {
	if len(data) >= 2 {
		ev.AlertLevel = data[0]
		ev.AlertDesc = data[1]
	}
}

// readCountedUTF16 reads a uint16 length followed by a UTF-16LE string.
func readCountedUTF16(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	length := binary.LittleEndian.Uint16(data[0:2])
	if int(length)*2+2 > len(data) {
		return "", false
	}
	// Copy to an aligned buffer to avoid unaligned pointer issues.
	buf := make([]byte, int(length)*2)
	copy(buf, data[2:2+int(length)*2])
	s, err := decodeUTF16(buf)
	return s, err == nil
}

// decodeUTF16 converts a UTF-16LE byte slice to a Go string.
func decodeUTF16(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", errors.New(errors.ErrCodeUnknown, "invalid utf16 length")
	}
	chars := make([]uint16, len(data)/2)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(chars)), nil
}

// readPtrUTF16 reads a null-terminated UTF-16LE string from a pointer stored in data.
func readPtrUTF16(data []byte) (string, bool) {
	if len(data) < int(unsafe.Sizeof(uintptr(0))) {
		return "", false
	}
	ptr := *(*uintptr)(unsafe.Pointer(&data[0]))
	if ptr == 0 {
		return "", false
	}
	return utf16PtrToString(ptr), true
}

func utf16PtrToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	p := (*[1 << 20]uint16)(unsafe.Pointer(ptr))
	length := 0
	for p[length] != 0 {
		length++
	}
	return string(utf16.Decode(p[:length]))
}
