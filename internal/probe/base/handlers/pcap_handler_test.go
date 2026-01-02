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

// mockPacketEvent is a mock implementation of PacketEvent for testing.
type mockPacketEvent struct {
	timestamp      uint64
	packetData     []byte
	packetLen      uint32
	interfaceIndex uint32
	srcIP          string
	dstIP          string
	srcPort        uint16
	dstPort        uint16
}

func (m *mockPacketEvent) GetTimestamp() uint64              { return m.timestamp }
func (m *mockPacketEvent) GetPacketData() []byte             { return m.packetData }
func (m *mockPacketEvent) GetPacketLen() uint32              { return m.packetLen }
func (m *mockPacketEvent) GetInterfaceIndex() uint32         { return m.interfaceIndex }
func (m *mockPacketEvent) GetSrcIP() string                  { return m.srcIP }
func (m *mockPacketEvent) GetDstIP() string                  { return m.dstIP }
func (m *mockPacketEvent) GetSrcPort() uint16                { return m.srcPort }
func (m *mockPacketEvent) GetDstPort() uint16                { return m.dstPort }
func (m *mockPacketEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockPacketEvent) Validate() error                   { return nil }
func (m *mockPacketEvent) String() string                    { return "" }
func (m *mockPacketEvent) StringHex() string                 { return "" }
func (m *mockPacketEvent) Clone() domain.Event               { return &mockPacketEvent{} }
func (m *mockPacketEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockPacketEvent) UUID() string                      { return "" }

func TestNewPcapHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)
	if handler == nil {
		t.Fatal("NewPcapHandler returned nil")
	}
	if handler.writer != buf {
		t.Error("PcapHandler writer not set correctly")
	}
	if handler.interfaces == nil {
		t.Error("interfaces map not initialized")
	}
}

func TestNewPcapHandler_NilWriter(t *testing.T) {
	handler := NewPcapHandler(nil)
	if handler == nil {
		t.Fatal("NewPcapHandler returned nil with nil writer")
	}
	if handler.writer == nil {
		t.Error("PcapHandler writer should not be nil")
	}
}

func TestPcapHandler_Handle(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	event := &mockPacketEvent{
		timestamp:      1234567890,
		packetData:     []byte{0x45, 0x00, 0x00, 0x3c}, // IP header start
		packetLen:      60,
		interfaceIndex: 1,
		srcIP:          "192.168.1.100",
		dstIP:          "192.168.1.1",
		srcPort:        12345,
		dstPort:        443,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "192.168.1.100") {
		t.Errorf("Output should contain source IP, got: %s", output)
	}
	if !strings.Contains(output, "192.168.1.1") {
		t.Errorf("Output should contain destination IP, got: %s", output)
	}
	if !strings.Contains(output, "12345") {
		t.Errorf("Output should contain source port, got: %s", output)
	}
	if !strings.Contains(output, "443") {
		t.Errorf("Output should contain destination port, got: %s", output)
	}
}

func TestPcapHandler_Handle_NilEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	err := handler.Handle(nil)
	if err == nil {
		t.Error("Handle should return error for nil event")
	}
}

// mockNonPacketEvent is a mock event that doesn't implement PacketEvent
type mockNonPacketEvent struct{}

func (m *mockNonPacketEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockNonPacketEvent) Validate() error                   { return nil }
func (m *mockNonPacketEvent) String() string                    { return "" }
func (m *mockNonPacketEvent) StringHex() string                 { return "" }
func (m *mockNonPacketEvent) Clone() domain.Event               { return &mockNonPacketEvent{} }
func (m *mockNonPacketEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockNonPacketEvent) UUID() string                      { return "" }

func TestPcapHandler_Handle_InvalidEventType(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	var event domain.Event = &mockNonPacketEvent{}
	err := handler.Handle(event)
	if err == nil {
		t.Error("Handle should return error for non-packet event")
	}
}

func TestPcapHandler_AddInterface(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	err := handler.AddInterface(1, "eth0")
	if err != nil {
		t.Errorf("AddInterface returned error: %v", err)
	}

	// Check that interface was added
	if len(handler.interfaces) != 1 {
		t.Error("Interface not added to map")
	}
	if handler.interfaces[1] != "eth0" {
		t.Errorf("Interface name not set correctly, got: %s", handler.interfaces[1])
	}
}

func TestPcapHandler_AddInterface_Multiple(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	handler.AddInterface(1, "eth0")
	handler.AddInterface(2, "wlan0")
	handler.AddInterface(3, "lo")

	if len(handler.interfaces) != 3 {
		t.Errorf("Expected 3 interfaces, got %d", len(handler.interfaces))
	}
}

func TestPcapHandler_WriteFileHeader(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	err := handler.WriteFileHeader()
	if err != nil {
		t.Errorf("WriteFileHeader returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteFileHeader should write some output")
	}
}

func TestPcapHandler_Close(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	// Add some interfaces
	handler.AddInterface(1, "eth0")
	handler.AddInterface(2, "wlan0")

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Check that interfaces were cleared
	if len(handler.interfaces) != 0 {
		t.Error("Interfaces should be cleared after Close")
	}
}

// mockPcapClosableWriter is a writer that implements io.Closer
type mockPcapClosableWriter struct {
	*bytes.Buffer
	closed bool
}

func (m *mockPcapClosableWriter) Close() error {
	m.closed = true
	return nil
}

func TestPcapHandler_Close_ClosableWriter(t *testing.T) {
	writer := &mockPcapClosableWriter{Buffer: &bytes.Buffer{}}
	handler := NewPcapHandler(writer)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	if !writer.closed {
		t.Error("Writer should be closed")
	}
}

func TestPcapHandler_Concurrent(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewPcapHandler(buf)

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			event := &mockPacketEvent{
				timestamp:      uint64(id),
				packetData:     []byte{byte(id)},
				packetLen:      1,
				interfaceIndex: uint32(id),
				srcIP:          "192.168.1.100",
				dstIP:          "192.168.1.1",
				srcPort:        uint16(10000 + id),
				dstPort:        443,
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
