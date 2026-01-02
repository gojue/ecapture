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
	"fmt"
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
)

// mockTLSDataEvent is a mock implementation of TLSDataEvent for testing.
type mockTLSDataEvent struct {
	pid       uint32
	comm      string
	data      []byte
	dataLen   uint32
	timestamp uint64
	isRead    bool
}

func (m *mockTLSDataEvent) GetPid() uint32 {
	return m.pid
}

func (m *mockTLSDataEvent) GetComm() string {
	return m.comm
}

func (m *mockTLSDataEvent) GetData() []byte {
	return m.data
}

func (m *mockTLSDataEvent) GetDataLen() uint32 {
	return m.dataLen
}

func (m *mockTLSDataEvent) GetTimestamp() uint64 {
	return m.timestamp
}

func (m *mockTLSDataEvent) IsRead() bool {
	return m.isRead
}

func (m *mockTLSDataEvent) DecodeFromBytes(data []byte) error {
	return nil
}

func (m *mockTLSDataEvent) Validate() error {
	return nil
}

func (m *mockTLSDataEvent) String() string {
	return string(m.data)
}

func (m *mockTLSDataEvent) StringHex() string {
	return fmt.Sprintf("%x", m.data)
}

func (m *mockTLSDataEvent) Clone() domain.Event {
	clone := *m
	clone.data = make([]byte, len(m.data))
	copy(clone.data, m.data)
	return &clone
}

func (m *mockTLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (m *mockTLSDataEvent) UUID() string {
	return "mock-uuid"
}

func TestNewTextHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)
	if handler == nil {
		t.Fatal("NewTextHandler returned nil")
	}
	if handler.writer != buf {
		t.Error("TextHandler writer not set correctly")
	}
}

func TestNewTextHandler_NilWriter(t *testing.T) {
	handler := NewTextHandler(nil)
	if handler == nil {
		t.Fatal("NewTextHandler returned nil with nil writer")
	}
	// Should use io.Discard
	if handler.writer == nil {
		t.Error("TextHandler writer should not be nil")
	}
}

func TestTextHandler_Handle_Write(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)

	event := &mockTLSDataEvent{
		pid:       1234,
		comm:      "test-app",
		data:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		dataLen:   42,
		timestamp: 1704168000000000000, // 2024-01-02 00:00:00 UTC
		isRead:    false,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "PID: 1234") {
		t.Errorf("Output should contain PID, got: %s", output)
	}
	if !strings.Contains(output, "test-app") {
		t.Errorf("Output should contain comm, got: %s", output)
	}
	if !strings.Contains(output, ">>>") {
		t.Errorf("Output should contain write direction (>>>), got: %s", output)
	}
	if !strings.Contains(output, "GET / HTTP/1.1") {
		t.Errorf("Output should contain data, got: %s", output)
	}
}

func TestTextHandler_Handle_Read(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)

	event := &mockTLSDataEvent{
		pid:       5678,
		comm:      "curl",
		data:      []byte("HTTP/1.1 200 OK\r\n\r\n"),
		dataLen:   20,
		timestamp: 1704168000000000000,
		isRead:    true,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "<<<") {
		t.Errorf("Output should contain read direction (<<<), got: %s", output)
	}
	if !strings.Contains(output, "HTTP/1.1 200 OK") {
		t.Errorf("Output should contain data, got: %s", output)
	}
}

func TestTextHandler_Handle_NilEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)

	err := handler.Handle(nil)
	if err == nil {
		t.Error("Handle should return error for nil event")
	}
}

// mockNonTLSEvent is a mock event that doesn't implement TLSDataEvent
type mockNonTLSEvent struct{}

func (m *mockNonTLSEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockNonTLSEvent) Validate() error                   { return nil }
func (m *mockNonTLSEvent) String() string                    { return "" }
func (m *mockNonTLSEvent) StringHex() string                 { return "" }
func (m *mockNonTLSEvent) Clone() domain.Event               { return &mockNonTLSEvent{} }
func (m *mockNonTLSEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockNonTLSEvent) UUID() string                      { return "" }

func TestTextHandler_Handle_InvalidEventType(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)

	var event domain.Event = &mockNonTLSEvent{}
	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for non-TLS event")
	}
}

func TestTextHandler_Close(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// mockClosableWriter is a writer that implements io.Closer
type mockClosableWriter struct {
	*bytes.Buffer
	closed bool
}

func (m *mockClosableWriter) Close() error {
	m.closed = true
	return nil
}

func TestTextHandler_Close_ClosableWriter(t *testing.T) {
	writer := &mockClosableWriter{Buffer: &bytes.Buffer{}}
	handler := NewTextHandler(writer)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	if !writer.closed {
		t.Error("Writer should be closed")
	}
}
