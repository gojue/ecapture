package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
)

type mockTextEvent struct {
	data string
}

func (m *mockTextEvent) DecodeFromBytes([]byte) error { return nil }
func (m *mockTextEvent) Validate() error               { return nil }
func (m *mockTextEvent) String() string                { return m.data }
func (m *mockTextEvent) StringHex() string             { return m.data }
func (m *mockTextEvent) Clone() domain.Event           { return m }
func (m *mockTextEvent) Type() domain.EventType        { return domain.EventTypeOutput }
func (m *mockTextEvent) UUID() string                  { return "" }
func (m *mockTextEvent) IsCustomHandler() bool         { return false }

func TestTextEncoder_Encode(t *testing.T) {
	var buf bytes.Buffer
	enc := NewTextEncoder(&buf)

	err := enc.Encode(&mockTextEvent{data: "hello world"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "hello world") {
		t.Fatalf("expected 'hello world', got: %q", buf.String())
	}
}

func TestTextEncoder_NewlineAppended(t *testing.T) {
	var buf bytes.Buffer
	enc := NewTextEncoder(&buf)

	enc.Encode(&mockTextEvent{data: "no newline"})
	out := buf.String()
	if out[len(out)-1] != '\n' {
		t.Fatalf("expected trailing newline, got: %q", out)
	}
}

func TestTextEncoder_EmptyEvent(t *testing.T) {
	var buf bytes.Buffer
	enc := NewTextEncoder(&buf)

	err := enc.Encode(&mockTextEvent{data: ""})
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty output for empty event")
	}
}

func TestTextEncoder_Name(t *testing.T) {
	enc := NewTextEncoder(nil)
	if enc.Name() != "text" {
		t.Fatalf("expected name 'text', got %q", enc.Name())
	}
}

func TestTextEncoder_Close(t *testing.T) {
	var buf bytes.Buffer
	enc := NewTextEncoder(&buf)
	if err := enc.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}
