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

package handlers

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/pkg/util/hkdf"
)

// mockKeylogWriter wraps bytes.Buffer to implement OutputWriter for testing
type mockKeylogWriter struct {
	*bytes.Buffer
}

func newMockKeylogWriter() *mockKeylogWriter {
	return &mockKeylogWriter{Buffer: &bytes.Buffer{}}
}

func (m *mockKeylogWriter) Close() error {
	return nil
}

func (m *mockKeylogWriter) Name() string {
	return "mock-keylog-writer"
}

func (m *mockKeylogWriter) Flush() error {
	return nil
}

// mockMasterSecretEvent is a mock implementation of MasterSecretEvent for testing.
type mockMasterSecretEvent struct {
	version                int32
	clientRandom           []byte
	masterKey              []byte
	cipherId               uint32
	earlySecret            []byte
	handshakeSecret        []byte
	handshakeTrafficHash   []byte
	clientAppTrafficSecret []byte
	serverAppTrafficSecret []byte
	exporterMasterSecret   []byte
}

func (m *mockMasterSecretEvent) GetVersion() int32               { return m.version }
func (m *mockMasterSecretEvent) GetClientRandom() []byte         { return m.clientRandom }
func (m *mockMasterSecretEvent) GetMasterKey() []byte            { return m.masterKey }
func (m *mockMasterSecretEvent) GetCipherId() uint32             { return m.cipherId }
func (m *mockMasterSecretEvent) GetEarlySecret() []byte          { return m.earlySecret }
func (m *mockMasterSecretEvent) GetHandshakeSecret() []byte      { return m.handshakeSecret }
func (m *mockMasterSecretEvent) GetHandshakeTrafficHash() []byte { return m.handshakeTrafficHash }
func (m *mockMasterSecretEvent) GetClientAppTrafficSecret() []byte {
	return m.clientAppTrafficSecret
}
func (m *mockMasterSecretEvent) GetServerAppTrafficSecret() []byte {
	return m.serverAppTrafficSecret
}
func (m *mockMasterSecretEvent) GetExporterMasterSecret() []byte {
	return m.exporterMasterSecret
}

func (m *mockMasterSecretEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockMasterSecretEvent) Validate() error                   { return nil }
func (m *mockMasterSecretEvent) String() string                    { return "" }
func (m *mockMasterSecretEvent) StringHex() string                 { return "" }
func (m *mockMasterSecretEvent) Clone() domain.Event               { return &mockMasterSecretEvent{} }
func (m *mockMasterSecretEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockMasterSecretEvent) UUID() string                      { return "" }

func TestNewKeylogHandler(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)
	if handler == nil {
		t.Fatal("NewKeylogHandler returned nil")
		return
	}
	if handler.seenKeys == nil {
		t.Error("seenKeys map not initialized")
	}
}

func TestNewKeylogHandler_NilWriter(t *testing.T) {
	handler := NewKeylogHandler(nil)
	if handler == nil {
		t.Fatal("NewKeylogHandler returned nil with nil writer")
		return
	}
	if handler.writer == nil {
		t.Error("KeylogHandler writer should not be nil")
	}
}

func TestKeylogHandler_Handle_TLS12(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Create a TLS 1.2 event (version 0x0303)
	clientRandom := make([]byte, Ssl3RandomSize)
	masterKey := make([]byte, MasterSecretMaxLen)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	for i := range masterKey {
		masterKey[i] = byte(i + 100)
	}

	event := &mockMasterSecretEvent{
		version:      0x0303, // TLS 1.2
		clientRandom: clientRandom,
		masterKey:    masterKey,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	output := writer.String()
	if !strings.HasPrefix(output, "CLIENT_RANDOM ") {
		t.Errorf("Output should start with CLIENT_RANDOM, got: %s", output)
		return
	}
}

func TestKeylogHandler_Handle_TLS13(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Create a TLS 1.3 event (version 0x0304)
	clientRandom := make([]byte, Ssl3RandomSize)
	clientApp := make([]byte, EvpMaxMdSize)
	serverApp := make([]byte, EvpMaxMdSize)

	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	for i := range clientApp {
		clientApp[i] = byte(i + 50)
	}
	for i := range serverApp {
		serverApp[i] = byte(i + 100)
	}

	event := &mockMasterSecretEvent{
		version:                0x0304, // TLS 1.3
		clientRandom:           clientRandom,
		cipherId:               0x03001301, // hkdf.TlsAes128GcmSha256
		clientAppTrafficSecret: clientApp,
		serverAppTrafficSecret: serverApp,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	output := writer.String()
	if !strings.Contains(output, hkdf.KeyLogLabelClientTraffic) {
		t.Errorf("Output should contain %s, got: %s", hkdf.KeyLogLabelClientTraffic, output)
		return
	}
	if !strings.Contains(output, hkdf.KeyLogLabelServerTraffic) {
		t.Errorf("Output should contain %s, got: %s", hkdf.KeyLogLabelServerTraffic, output)
		return
	}
}

func TestKeylogHandler_Handle_Deduplication(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Create identical events
	clientRandom := make([]byte, Ssl3RandomSize)
	masterKey := make([]byte, MasterSecretMaxLen)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	for i := range masterKey {
		masterKey[i] = byte(i + 100)
	}

	event := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: clientRandom,
		masterKey:    masterKey,
	}

	// Handle the same event twice
	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("First Handle returned error: %v", err)
		return
	}

	firstOutput := writer.String()
	writer.Reset()

	err = handler.Handle(event)
	if err != nil {
		t.Fatalf("Second Handle returned error: %v", err)
		return
	}

	secondOutput := writer.String()
	if secondOutput != "" {
		t.Error("Duplicate event should not produce output")
	}
	if len(firstOutput) == 0 {
		t.Error("First event should produce output")
	}
}

func TestKeylogHandler_Handle_NilEvent(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	err := handler.Handle(nil)
	if err == nil {
		t.Error("Handle should return error for nil event")
	}
}

// mockNonMasterSecretEvent is a mock event that doesn't implement MasterSecretEvent
type mockNonMasterSecretEvent struct{}

func (m *mockNonMasterSecretEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockNonMasterSecretEvent) Validate() error                   { return nil }
func (m *mockNonMasterSecretEvent) String() string                    { return "" }
func (m *mockNonMasterSecretEvent) StringHex() string                 { return "" }
func (m *mockNonMasterSecretEvent) Clone() domain.Event               { return &mockNonMasterSecretEvent{} }
func (m *mockNonMasterSecretEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockNonMasterSecretEvent) UUID() string                      { return "" }

func TestKeylogHandler_Handle_InvalidEventType(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	var event domain.Event = &mockNonMasterSecretEvent{}
	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for non-master-secret event")
	}
}

func TestKeylogHandler_Handle_ShortClientRandom(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Client random too short
	event := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: make([]byte, 10), // Too short
		masterKey:    make([]byte, MasterSecretMaxLen),
	}

	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for short client random")
	}
}

func TestKeylogHandler_Handle_ShortMasterKey(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Master key too short
	event := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: make([]byte, Ssl3RandomSize),
		masterKey:    make([]byte, 10), // Too short
	}

	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for short master key")
	}
}

func TestKeylogHandler_Handle_TLS13_SkipZeroSecrets(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// TLS 1.3 event with zero secrets (should be skipped)
	clientRandom := make([]byte, Ssl3RandomSize)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	event := &mockMasterSecretEvent{
		version:                0x0304,
		clientRandom:           clientRandom,
		cipherId:               0x03001301,                 // hkdf.TlsAes128GcmSha256
		clientAppTrafficSecret: make([]byte, EvpMaxMdSize), // All zeros
		serverAppTrafficSecret: make([]byte, EvpMaxMdSize), // All zeros
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	output := writer.String()
	if output != "" {
		t.Error("Zero secrets should not produce output")
	}
}

func TestKeylogHandler_Close(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Add a key to seenKeys
	handler.seenKeys["test"] = true

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
		return
	}

	// Check that seenKeys was cleared
	if len(handler.seenKeys) != 0 {
		t.Error("seenKeys should be cleared after Close")
	}
}

// mockKeylogClosableWriter is a writer that implements io.Closer
type mockKeylogClosableWriter struct {
	*bytes.Buffer
	closed bool
}

func (m *mockKeylogClosableWriter) Close() error {
	m.closed = true
	return nil
}

func (m *mockKeylogClosableWriter) Name() string {
	return "mock-closable-writer"
}

func (m *mockKeylogClosableWriter) Flush() error {
	return nil
}

func TestKeylogHandler_Close_ClosableWriter(t *testing.T) {
	writer := &mockKeylogClosableWriter{Buffer: &bytes.Buffer{}}
	handler := NewKeylogHandler(writer)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
		return
	}
	if !writer.closed {
		t.Error("Writer should be closed")
	}
}

func Test_isZeroBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"All zeros", []byte{0, 0, 0, 0}, true},
		{"With non-zero", []byte{0, 1, 0, 0}, false},
		{"Empty slice", []byte{}, true},
		{"All non-zero", []byte{1, 2, 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isZeroBytes(tt.data)
			if got != tt.want {
				t.Errorf("isZeroBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeylogHandler_Concurrent(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			clientRandom := make([]byte, Ssl3RandomSize)
			masterKey := make([]byte, MasterSecretMaxLen)
			for j := range clientRandom {
				clientRandom[j] = byte(id + j)
			}
			for j := range masterKey {
				masterKey[j] = byte(id + j + 100)
			}

			event := &mockMasterSecretEvent{
				version:      0x0303,
				clientRandom: clientRandom,
				masterKey:    masterKey,
			}

			_ = handler.Handle(event)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	output := writer.String()
	if output == "" {
		t.Error("Concurrent writes should produce output")
	}
}

// TestKeylogHandler_TLS13_BoringSSLHashLen pins the length fix: BoringSSL
// master-secret events carry the TLS 1.3 hash length in the CipherId slot
// (mastersecret_bssl_t.hash_len decoded into CipherId), not a real cipher id. The
// handler must emit exactly that many bytes, not the full EvpMaxMdSize buffer.
// Before the fix, a hash_len of 32 fell through the cipher switch to the default
// and emitted 64 bytes (128 hex), which Wireshark rejects.
func TestKeylogHandler_TLS13_BoringSSLHashLen(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	clientRandom := make([]byte, Ssl3RandomSize)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	full := make([]byte, EvpMaxMdSize) // 64-byte buffer; only the first 32 are the secret
	for i := range full {
		full[i] = byte(i + 7)
	}
	event := &mockMasterSecretEvent{
		version:                0x0304, // TLS 1.3
		clientRandom:           clientRandom,
		cipherId:               32, // SHA-256 hash length aliased into CipherId
		clientAppTrafficSecret: full,
		serverAppTrafficSecret: full,
	}
	if err := handler.Handle(event); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	out := writer.String()
	re := regexp.MustCompile(`(CLIENT|SERVER)_TRAFFIC_SECRET_0 [0-9a-f]{64} ([0-9a-f]+)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		seen[m[1]] = true
		if len(m[2]) != 64 { // 32 bytes = 64 hex chars, not 128
			t.Errorf("%s_TRAFFIC_SECRET_0: want 64-hex (32-byte) secret, got %d hex chars", m[1], len(m[2]))
		}
	}
	if !seen["CLIENT"] || !seen["SERVER"] {
		t.Errorf("expected both CLIENT and SERVER traffic secret lines; got %v in %q", seen, out)
	}
}
