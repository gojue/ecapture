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
	"os"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/logger"
)

// mockPcapWriter wraps bytes.Buffer to implement OutputWriter for testing
type mockPcapWriter struct {
	*bytes.Buffer
}

func newMockPcapWriter() *mockPcapWriter {
	return &mockPcapWriter{Buffer: &bytes.Buffer{}}
}

func (m *mockPcapWriter) Close() error {
	return nil
}

func (m *mockPcapWriter) Name() string {
	return "mock-pcap-writer"
}

func (m *mockPcapWriter) Flush() error {
	return nil
}

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

func newTestLogger() *logger.Logger {
	return logger.New(os.Stdout, true)
}

func TestNewPcapHandler(t *testing.T) {
	writer := newMockPcapWriter()

	handler, err := NewPcapHandler(writer, "test-interface", "tcp port 80", newTestLogger())
	if err != nil {
		t.Fatalf("NewPcapHandler returned error: %v", err)
		return
	}
	if handler == nil {
		t.Fatal("NewPcapHandler returned nil")
		return
	}
	if handler.pcapWriter == nil {
		t.Error("PcapHandler pcapWriter not set correctly")
	}
}

func TestNewPcapHandler_NilWriter(t *testing.T) {
	handler, err := NewPcapHandler(nil, "test-interface", "tcp port 80", newTestLogger())
	if err != nil {
		t.Fatalf("NewPcapHandler returned error: %v", err)
		return
	}
	if handler == nil {
		t.Fatal("NewPcapHandler returned nil with nil writer")
		return
	}
	if handler.pcapWriter == nil {
		t.Error("PcapHandler pcapWriter should not be nil")
	}
}

func TestPcapHandler_Handle(t *testing.T) {
	writer := newMockPcapWriter()
	handler, err := NewPcapHandler(writer, "test-interface", "tcp port 80", newTestLogger())
	if err != nil {
		t.Fatalf("NewPcapHandler returned error: %v", err)
		return
	}

	event := &mockPacketEvent{
		timestamp:      1234567890000000000,            // nanoseconds
		packetData:     []byte{0x45, 0x00, 0x00, 0x3c}, // IP header start
		packetLen:      60,
		interfaceIndex: 0,
		srcIP:          "192.168.1.100",
		dstIP:          "192.168.1.1",
		srcPort:        12345,
		dstPort:        443,
	}

	err = handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	// PCAPNG data is binary, just verify something was written
	if writer.Len() == 0 {
		t.Error("Expected data to be written to pcap file")
	}
}

func TestPcapHandler_Handle_NilEvent(t *testing.T) {
	writer := newMockPcapWriter()
	handler, err := NewPcapHandler(writer, "test-interface", "tcp port 80", newTestLogger())
	if err != nil {
		t.Fatalf("NewPcapHandler returned error: %v", err)
		return
	}

	err = handler.Handle(nil)
	// Should return nil (skip silently) for nil events
	if err != nil {
		t.Errorf("Handle should skip nil events silently, got error: %v", err)
		return
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
	writer := newMockPcapWriter()
	handler, err := NewPcapHandler(writer, "test-interface", "tcp port 80", newTestLogger())
	if err != nil {
		t.Fatalf("NewPcapHandler returned error: %v", err)
		return
	}

	var event domain.Event = &mockNonPacketEvent{}
	err = handler.Handle(event)
	// Should return nil (skip silently) for non-packet events
	if err != nil {
		t.Errorf("Handle should skip non-packet events silently, got error: %v", err)
		return
	}
}
