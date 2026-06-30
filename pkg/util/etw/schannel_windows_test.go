//go:build windows
// +build windows

package etw

import (
	"encoding/binary"
	"testing"
)

func TestProtocolName(t *testing.T) {
	cases := []struct {
		proto uint32
		want  string
	}{
		{ProtocolTLS13, "TLS 1.3"},
		{ProtocolTLS12, "TLS 1.2"},
		{ProtocolTLS11, "TLS 1.1"},
		{ProtocolTLS10, "TLS 1.0"},
		{ProtocolSSL30, "SSL 3.0"},
		{0x12345678, "Unknown"},
	}
	for _, c := range cases {
		got := ProtocolName(c.proto)
		if got != c.want {
			t.Errorf("ProtocolName(0x%08X) = %q, want %q", c.proto, got, c.want)
		}
	}
}

func TestParseSchannelEventHandshakeComplete(t *testing.T) {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint32(payload[0:4], ProtocolTLS12)
	binary.LittleEndian.PutUint16(payload[4:6], CipherSuiteTLS_ECDHE_RSA_AES256_GCM)
	binary.LittleEndian.PutUint32(payload[8:12], 32)
	binary.LittleEndian.PutUint32(payload[12:16], 0x0000800c)

	ev := &EventRecord{
		EventId:    SchannelEventHandshakeComplete,
		UserData:   payload,
		Properties: make(map[string]any),
	}
	parsed := ParseSchannelEvent(ev)
	if parsed == nil {
		t.Fatal("ParseSchannelEvent returned nil")
	}
	if parsed.EventId != SchannelEventHandshakeComplete {
		t.Errorf("EventId = %d, want %d", parsed.EventId, SchannelEventHandshakeComplete)
	}
	if parsed.Protocol != ProtocolTLS12 {
		t.Errorf("Protocol = 0x%x, want 0x%x", parsed.Protocol, ProtocolTLS12)
	}
	if parsed.CipherSuite != CipherSuiteTLS_ECDHE_RSA_AES256_GCM {
		t.Errorf("CipherSuite = 0x%x, want 0x%x", parsed.CipherSuite, CipherSuiteTLS_ECDHE_RSA_AES256_GCM)
	}
	if ev.Properties[PropProtocol] != ProtocolTLS12 {
		t.Errorf("Properties[%q] = %v, want %v", PropProtocol, ev.Properties[PropProtocol], ProtocolTLS12)
	}
	if ev.Properties[PropCipherSuite] != CipherSuiteTLS_ECDHE_RSA_AES256_GCM {
		t.Errorf("Properties[%q] = %v, want %v", PropCipherSuite, ev.Properties[PropCipherSuite], CipherSuiteTLS_ECDHE_RSA_AES256_GCM)
	}
}

func TestParseSchannelEventAlert(t *testing.T) {
	payload := []byte{0x02, 0x28} // fatal, handshake_failure
	ev := &EventRecord{
		EventId:    SchannelEventAlertReceived,
		UserData:   payload,
		Properties: make(map[string]any),
	}
	parsed := ParseSchannelEvent(ev)
	if parsed == nil {
		t.Fatal("ParseSchannelEvent returned nil")
	}
	if parsed.AlertLevel != 0x02 {
		t.Errorf("AlertLevel = 0x%x, want 0x02", parsed.AlertLevel)
	}
	if parsed.AlertDesc != 0x28 {
		t.Errorf("AlertDesc = 0x%x, want 0x28", parsed.AlertDesc)
	}
	if ev.Properties[PropAlertLevel] != uint8(0x02) {
		t.Errorf("Properties[%q] = %v, want %v", PropAlertLevel, ev.Properties[PropAlertLevel], uint8(0x02))
	}
}

func TestParseSchannelEventEmpty(t *testing.T) {
	if ParseSchannelEvent(nil) != nil {
		t.Error("ParseSchannelEvent(nil) should return nil")
	}
	ev := &EventRecord{EventId: SchannelEventHandshakeComplete, Properties: make(map[string]any)}
	if ParseSchannelEvent(ev) != nil {
		t.Error("ParseSchannelEvent with empty UserData should return nil")
	}
}
