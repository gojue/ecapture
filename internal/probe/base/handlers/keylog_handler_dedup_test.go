package handlers

import (
	"testing"

	"github.com/gojue/ecapture/internal/output/writers"
)

// Test that all-zero master secrets are filtered out
func TestKeylogHandler_FilterZeroMasterSecret(t *testing.T) {
	writer := &mockKeylogWriter{}
	handler := NewKeylogHandler(writer)

	// Create event with all-zero master key
	event := &mockMasterSecretEvent{
		version:      0x0303, // TLS 1.2
		clientRandom: make([]byte, 32),
		masterKey:    make([]byte, 48), // All zeros
	}

	// Fill client random with non-zero data
	for i := range event.clientRandom {
		event.clientRandom[i] = byte(i)
	}

	// Handle event - should be skipped
	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// Verify nothing was written
	if len(writer.written) > 0 {
		t.Errorf("Expected no writes for zero master secret, got %d writes: %s",
			len(writer.written), writer.written)
	}
}

// Test that valid master secrets are written
func TestKeylogHandler_WriteValidMasterSecret(t *testing.T) {
	writer := &mockKeylogWriter{}
	handler := NewKeylogHandler(writer)

	// Create event with valid master key
	event := &mockMasterSecretEvent{
		version:      0x0303, // TLS 1.2
		clientRandom: make([]byte, 32),
		masterKey:    make([]byte, 48),
	}

	// Fill with non-zero data
	for i := range event.clientRandom {
		event.clientRandom[i] = byte(i)
	}
	for i := range event.masterKey {
		event.masterKey[i] = byte(i + 100)
	}

	// Handle event - should be written
	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// Verify it was written
	if len(writer.written) != 1 {
		t.Fatalf("Expected 1 write, got %d", len(writer.written))
	}

	// Check format
	line := string(writer.written[0])
	if len(line) == 0 {
		t.Error("Written line is empty")
	}
	if line[0:14] != "CLIENT_RANDOM " {
		t.Errorf("Expected line to start with 'CLIENT_RANDOM ', got: %s", line[0:14])
	}
}

// Test deduplication based on client_random
func TestKeylogHandler_DeduplicateByClientRandom(t *testing.T) {
	writer := &mockKeylogWriter{}
	handler := NewKeylogHandler(writer)

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// First event with zero master key - should be skipped
	event1 := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: clientRandom,
		masterKey:    make([]byte, 48), // All zeros
	}

	err := handler.Handle(event1)
	if err != nil {
		t.Fatalf("Handle() event1 returned error: %v", err)
	}

	if len(writer.written) != 0 {
		t.Errorf("Expected 0 writes after zero master secret, got %d", len(writer.written))
	}

	// Second event with valid master key - should be written
	event2 := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: clientRandom, // Same client_random
		masterKey:    make([]byte, 48),
	}
	for i := range event2.masterKey {
		event2.masterKey[i] = byte(i + 100)
	}

	err = handler.Handle(event2)
	if err != nil {
		t.Fatalf("Handle() event2 returned error: %v", err)
	}

	if len(writer.written) != 1 {
		t.Fatalf("Expected 1 write after valid master secret, got %d", len(writer.written))
	}

	// Third event with different master key but same client_random - should be skipped (dedup)
	event3 := &mockMasterSecretEvent{
		version:      0x0303,
		clientRandom: clientRandom, // Same client_random
		masterKey:    make([]byte, 48),
	}
	for i := range event3.masterKey {
		event3.masterKey[i] = byte(i + 200) // Different master key
	}

	err = handler.Handle(event3)
	if err != nil {
		t.Fatalf("Handle() event3 returned error: %v", err)
	}

	// Should still be 1 write (deduped by client_random)
	if len(writer.written) != 1 {
		t.Errorf("Expected 1 write after dedup, got %d", len(writer.written))
	}
}

// Mock writer that records what was written
type mockKeylogWriter struct {
	written [][]byte
}

func (m *mockKeylogWriter) Write(p []byte) (n int, err error) {
	// Make a copy since the caller might reuse the buffer
	data := make([]byte, len(p))
	copy(data, p)
	m.written = append(m.written, data)
	return len(p), nil
}

func (m *mockKeylogWriter) Flush() error {
	return nil
}

func (m *mockKeylogWriter) Name() string {
	return "mock-keylog-writer"
}

func (m *mockKeylogWriter) WriteRaw(data []byte) error {
	_, err := m.Write(data)
	return err
}

func (m *mockKeylogWriter) IsReady() bool {
	return true
}

func (m *mockKeylogWriter) Close() error {
	return nil
}

func (m *mockKeylogWriter) String() string {
	return "mock-keylog-writer"
}

var _ writers.OutputWriter = (*mockKeylogWriter)(nil)
