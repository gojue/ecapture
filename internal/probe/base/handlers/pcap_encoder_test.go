package handlers

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/output/writers"
)

type mockPcapPacketEvent struct {
	timestamp  uint64
	packetData []byte
}

func (m *mockPcapPacketEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockPcapPacketEvent) Validate() error               { return nil }
func (m *mockPcapPacketEvent) String() string                { return "" }
func (m *mockPcapPacketEvent) StringHex() string             { return "" }
func (m *mockPcapPacketEvent) Clone() domain.Event           { return m }
func (m *mockPcapPacketEvent) Type() domain.EventType        { return domain.EventTypeOutput }
func (m *mockPcapPacketEvent) UUID() string                  { return "" }
func (m *mockPcapPacketEvent) GetTimestamp() uint64          { return m.timestamp }
func (m *mockPcapPacketEvent) GetPacketData() []byte         { return m.packetData }

type mockPcapNonPacketEvent struct{}

func (m *mockPcapNonPacketEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockPcapNonPacketEvent) Validate() error               { return nil }
func (m *mockPcapNonPacketEvent) String() string                { return "" }
func (m *mockPcapNonPacketEvent) StringHex() string             { return "" }
func (m *mockPcapNonPacketEvent) Clone() domain.Event           { return m }
func (m *mockPcapNonPacketEvent) Type() domain.EventType        { return domain.EventTypeOutput }
func (m *mockPcapNonPacketEvent) UUID() string                  { return "" }

func newPcapTestLogger() *logger.Logger {
	return logger.New(os.Stdout, true)
}

func TestPcapEncoder_Encode(t *testing.T) {
	var buf bytes.Buffer
	pcapWriter, err := writers.NewPcapWriter(&buf, 65535, "test-if", "", newPcapTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	enc := NewPcapEncoder(pcapWriter)
	defer enc.Close()

	err = enc.Encode(&mockPcapPacketEvent{
		timestamp:  uint64(time.Now().UnixNano()),
		packetData: []byte{0x45, 0x00, 0x00, 0x3c},
	})
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let Serve() goroutine flush

	if buf.Len() == 0 {
		t.Fatal("expected data written to pcap writer")
	}
}

func TestPcapEncoder_NonPacketEvent(t *testing.T) {
	var buf bytes.Buffer
	pcapWriter, _ := writers.NewPcapWriter(&buf, 65535, "test-if", "", newPcapTestLogger())
	enc := NewPcapEncoder(pcapWriter)
	defer enc.Close()

	err := enc.Encode(&mockPcapNonPacketEvent{})
	if err != nil {
		t.Fatalf("non-packet event should be silently skipped, got error: %v", err)
	}
}

func TestPcapEncoder_Name(t *testing.T) {
	enc := NewPcapEncoder(nil)
	if enc.Name() != "pcap" {
		t.Fatalf("expected name 'pcap', got %q", enc.Name())
	}
}

func TestPcapEncoder_Close(t *testing.T) {
	var buf bytes.Buffer
	pcapWriter, _ := writers.NewPcapWriter(&buf, 65535, "test-if", "", newPcapTestLogger())
	enc := NewPcapEncoder(pcapWriter)

	// Close may return "nothing captured" error on empty captures — that's normal.
	_ = enc.Close()
}
