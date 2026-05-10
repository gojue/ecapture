package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
)

// mockOpenSSLKeyEvent implements MasterSecretEvent only.
type mockOpenSSLKeyEvent struct {
	version                int32
	clientRandom           []byte
	masterKey              []byte
	clientAppTrafficSecret []byte
	serverAppTrafficSecret []byte
	exporterMasterSecret   []byte
	handshakeSecret        []byte
}

func (m *mockOpenSSLKeyEvent) DecodeFromBytes([]byte) error      { return nil }
func (m *mockOpenSSLKeyEvent) Validate() error                    { return nil }
func (m *mockOpenSSLKeyEvent) String() string                     { return "" }
func (m *mockOpenSSLKeyEvent) StringHex() string                  { return "" }
func (m *mockOpenSSLKeyEvent) Clone() domain.Event                { return m }
func (m *mockOpenSSLKeyEvent) Type() domain.EventType             { return domain.EventTypeOutput }
func (m *mockOpenSSLKeyEvent) UUID() string                       { return "" }
func (m *mockOpenSSLKeyEvent) IsCustomHandler() bool              { return false }
func (m *mockOpenSSLKeyEvent) GetVersion() int32                  { return m.version }
func (m *mockOpenSSLKeyEvent) GetClientRandom() []byte            { return m.clientRandom }
func (m *mockOpenSSLKeyEvent) GetMasterKey() []byte               { return m.masterKey }
func (m *mockOpenSSLKeyEvent) GetHandshakeSecret() []byte         { return m.handshakeSecret }
func (m *mockOpenSSLKeyEvent) GetClientAppTrafficSecret() []byte  { return m.clientAppTrafficSecret }
func (m *mockOpenSSLKeyEvent) GetServerAppTrafficSecret() []byte  { return m.serverAppTrafficSecret }
func (m *mockOpenSSLKeyEvent) GetExporterMasterSecret() []byte    { return m.exporterMasterSecret }

// mockGoTLSKeyEvent implements GoTLSMasterSecretEvent only.
type mockGoTLSKeyEvent struct {
	label        string
	clientRandom []byte
	secret       []byte
}

func (m *mockGoTLSKeyEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockGoTLSKeyEvent) Validate() error               { return nil }
func (m *mockGoTLSKeyEvent) String() string                { return "" }
func (m *mockGoTLSKeyEvent) StringHex() string             { return "" }
func (m *mockGoTLSKeyEvent) Clone() domain.Event           { return m }
func (m *mockGoTLSKeyEvent) Type() domain.EventType        { return domain.EventTypeOutput }
func (m *mockGoTLSKeyEvent) UUID() string                  { return "" }
func (m *mockGoTLSKeyEvent) IsCustomHandler() bool         { return false }
func (m *mockGoTLSKeyEvent) GetLabel() string              { return m.label }
func (m *mockGoTLSKeyEvent) GetClientRandom() []byte       { return m.clientRandom }
func (m *mockGoTLSKeyEvent) GetSecret() []byte             { return m.secret }

// nonKeyEvent does not implement any keylog interface.
type nonKeyEvent struct{}

func (m *nonKeyEvent) DecodeFromBytes([]byte) error { return nil }
func (m *nonKeyEvent) Validate() error               { return nil }
func (m *nonKeyEvent) String() string                { return "" }
func (m *nonKeyEvent) StringHex() string             { return "" }
func (m *nonKeyEvent) Clone() domain.Event           { return m }
func (m *nonKeyEvent) Type() domain.EventType        { return domain.EventTypeOutput }
func (m *nonKeyEvent) UUID() string                  { return "" }
func (m *nonKeyEvent) IsCustomHandler() bool         { return false }

func makeCR(data byte) []byte {
	b := make([]byte, Ssl3RandomSize)
	b[0] = data
	return b
}

func makeMK(data byte) []byte {
	b := make([]byte, MasterSecretMaxLen)
	b[0] = data
	return b
}

func TestKeylogEncoder_TLS12(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&mockOpenSSLKeyEvent{
		version:      0x0303,
		clientRandom: makeCR(0xaa),
		masterKey:    makeMK(0xbb),
	})
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "CLIENT_RANDOM") {
		t.Fatalf("expected CLIENT_RANDOM line, got: %q", out)
	}
}

func TestKeylogEncoder_ZeroKeySkipped(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&mockOpenSSLKeyEvent{
		version:      0x0303,
		clientRandom: makeCR(0xaa),
		masterKey:    make([]byte, MasterSecretMaxLen),
	})
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected zero key to be skipped, got: %s", buf.String())
	}
}

func TestKeylogEncoder_Dedup(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	ev := &mockOpenSSLKeyEvent{
		version:      0x0303,
		clientRandom: makeCR(0xcc),
		masterKey:    makeMK(0xdd),
	}

	enc.Encode(ev)
	enc.Encode(ev)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line after dedup, got %d:\n%s", len(lines), buf.String())
	}
}

func TestKeylogEncoder_GoTLS(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&mockGoTLSKeyEvent{
		label:        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		clientRandom: makeCR(0x11),
		secret:       makeMK(0x22),
	})
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.HasPrefix(out, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") {
		t.Fatalf("expected GoTLS label line, got: %q", out)
	}
}

func TestKeylogEncoder_GoTLS_ZeroSecret(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&mockGoTLSKeyEvent{
		label:        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		clientRandom: makeCR(0x11),
		secret:       make([]byte, 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected zero secret to be skipped")
	}
}

func TestKeylogEncoder_TLS13(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&mockOpenSSLKeyEvent{
		version:                0x0304,
		clientRandom:           makeCR(0xee),
		clientAppTrafficSecret: makeMK(0x01),
		serverAppTrafficSecret: makeMK(0x02),
	})
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "CLIENT_TRAFFIC_SECRET_0") {
		t.Fatalf("expected CLIENT_TRAFFIC_SECRET_0, got: %q", out)
	}
	if !strings.Contains(out, "SERVER_TRAFFIC_SECRET_0") {
		t.Fatalf("expected SERVER_TRAFFIC_SECRET_0, got: %q", out)
	}
}

func TestKeylogEncoder_NonKeyEvent(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	err := enc.Encode(&nonKeyEvent{})
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected non-key event to be skipped")
	}
}

func TestKeylogEncoder_Close(t *testing.T) {
	var buf bytes.Buffer
	enc := NewKeylogEncoder(&buf)

	if err := enc.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

func TestKeylogEncoder_Name(t *testing.T) {
	enc := NewKeylogEncoder(nil)
	if enc.Name() != "keylog" {
		t.Fatalf("expected name 'keylog', got %q", enc.Name())
	}
}
