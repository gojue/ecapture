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
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
)

// mockMasterSecretEvent is a mock implementation of MasterSecretEvent for testing.
type mockMasterSecretEvent struct {
	version                  int32
	clientRandom             []byte
	masterKey                []byte
	cipherId                 uint32
	earlySecret              []byte
	handshakeSecret          []byte
	handshakeTrafficHash     []byte
	clientAppTrafficSecret   []byte
	serverAppTrafficSecret   []byte
	exporterMasterSecret     []byte
}

func (m *mockMasterSecretEvent) GetVersion() int32                     { return m.version }
func (m *mockMasterSecretEvent) GetClientRandom() []byte               { return m.clientRandom }
func (m *mockMasterSecretEvent) GetMasterKey() []byte                  { return m.masterKey }
func (m *mockMasterSecretEvent) GetCipherId() uint32                   { return m.cipherId }
func (m *mockMasterSecretEvent) GetEarlySecret() []byte                { return m.earlySecret }
func (m *mockMasterSecretEvent) GetHandshakeSecret() []byte            { return m.handshakeSecret }
func (m *mockMasterSecretEvent) GetHandshakeTrafficHash() []byte       { return m.handshakeTrafficHash }
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
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)
	if handler == nil {
		t.Fatal("NewKeylogHandler returned nil")
	}
	if handler.writer != buf {
		t.Error("KeylogHandler writer not set correctly")
	}
	if handler.seenKeys == nil {
		t.Error("seenKeys map not initialized")
	}
}

func TestNewKeylogHandler_NilWriter(t *testing.T) {
	handler := NewKeylogHandler(nil)
	if handler == nil {
		t.Fatal("NewKeylogHandler returned nil with nil writer")
	}
	if handler.writer == nil {
		t.Error("KeylogHandler writer should not be nil")
	}
}

func TestKeylogHandler_Handle_TLS12(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
	}

	output := buf.String()
	if !strings.HasPrefix(output, "CLIENT_RANDOM ") {
		t.Errorf("Output should start with CLIENT_RANDOM, got: %s", output)
	}
	if !strings.Contains(output, "\n") {
		t.Error("Output should end with newline")
	}
}

func TestKeylogHandler_Handle_TLS13(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
		clientAppTrafficSecret: clientApp,
		serverAppTrafficSecret: serverApp,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CLIENT_TRAFFIC_SECRET_0") {
		t.Errorf("Output should contain CLIENT_TRAFFIC_SECRET_0, got: %s", output)
	}
	if !strings.Contains(output, "SERVER_TRAFFIC_SECRET_0") {
		t.Errorf("Output should contain SERVER_TRAFFIC_SECRET_0, got: %s", output)
	}
}

func TestKeylogHandler_Handle_Deduplication(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
	}

	firstOutput := buf.String()
	buf.Reset()

	err = handler.Handle(event)
	if err != nil {
		t.Fatalf("Second Handle returned error: %v", err)
	}

	secondOutput := buf.String()
	if secondOutput != "" {
		t.Error("Duplicate event should not produce output")
	}
	if len(firstOutput) == 0 {
		t.Error("First event should produce output")
	}
}

func TestKeylogHandler_Handle_NilEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

	var event domain.Event = &mockNonMasterSecretEvent{}
	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for non-master-secret event")
	}
}

func TestKeylogHandler_Handle_ShortClientRandom(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

	// TLS 1.3 event with zero secrets (should be skipped)
	clientRandom := make([]byte, Ssl3RandomSize)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	event := &mockMasterSecretEvent{
		version:                0x0304,
		clientRandom:           clientRandom,
		clientAppTrafficSecret: make([]byte, EvpMaxMdSize), // All zeros
		serverAppTrafficSecret: make([]byte, EvpMaxMdSize), // All zeros
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := buf.String()
	if output != "" {
		t.Error("Zero secrets should not produce output")
	}
}

func TestKeylogHandler_Close(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

	// Add a key to seenKeys
	handler.seenKeys["test"] = true

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
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

func TestKeylogHandler_Close_ClosableWriter(t *testing.T) {
	writer := &mockKeylogClosableWriter{Buffer: &bytes.Buffer{}}
	handler := NewKeylogHandler(writer)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
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
	buf := &bytes.Buffer{}
	handler := NewKeylogHandler(buf)

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

			handler.Handle(event)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()
	if output == "" {
		t.Error("Concurrent writes should produce output")
	}
}
