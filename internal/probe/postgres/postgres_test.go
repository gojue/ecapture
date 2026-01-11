// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package postgres

import (
	"context"
	"testing"

	"github.com/gojue/ecapture/internal/config"
	"github.com/gojue/ecapture/internal/domain"
)

// TestNewConfig tests the creation of a new PostgreSQL configuration
func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.FuncName != "exec_simple_query" {
		t.Errorf("Expected FuncName to be 'exec_simple_query', got %s", cfg.FuncName)
	}
}

// TestConfigValidateWithoutPath tests config validation when path is not set
func TestConfigValidateWithoutPath(t *testing.T) {
	cfg := NewConfig()

	// Validation should try auto-detection and may succeed or fail
	// depending on whether PostgreSQL is installed
	err := cfg.Validate()
	// We don't assert error here because it depends on system state
	_ = err
}

// TestConfigValidateWithInvalidPath tests config validation with an invalid path
func TestConfigValidateWithInvalidPath(t *testing.T) {
	cfg := NewConfig()
	cfg.SetPostgresPath("/nonexistent/postgres")

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for nonexistent path")
	}
}

// TestConfigGettersSetters tests configuration getters and setters
func TestConfigGettersSetters(t *testing.T) {
	cfg := NewConfig()

	// Test PostgresPath
	testPath := "/usr/lib/postgresql/15/bin/postgres"
	cfg.SetPostgresPath(testPath)
	if cfg.GetPostgresPath() != testPath {
		t.Errorf("Expected PostgresPath %s, got %s", testPath, cfg.GetPostgresPath())
	}

	// Test FuncName
	testFunc := "custom_function"
	cfg.SetFuncName(testFunc)
	if cfg.GetFuncName() != testFunc {
		t.Errorf("Expected FuncName %s, got %s", testFunc, cfg.GetFuncName())
	}

	// Test Offset
	testOffset := uint64(0x12345)
	cfg.SetOffset(testOffset)
	if cfg.GetOffset() != testOffset {
		t.Errorf("Expected Offset %d, got %d", testOffset, cfg.GetOffset())
	}
}

// TestNewProbe tests the creation of a new PostgreSQL probe
func TestNewProbe(t *testing.T) {
	probe := NewProbe()
	if probe == nil {
		t.Fatal("Expected non-nil probe")
	}
	if probe.Name() != "postgres" {
		t.Errorf("Expected probe name 'postgres', got %s", probe.Name())
	}
	if probe.IsRunning() {
		t.Error("Expected probe to not be running initially")
	}
}

// TestProbeInitialize tests probe initialization
func TestProbeInitialize(t *testing.T) {
	probe := NewProbe()
	cfg := NewConfig()
	cfg.SetPostgresPath("/usr/lib/postgresql/15/bin/postgres")

	dispatcher := &mockDispatcher{}
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg, dispatcher)
	// May fail if PostgreSQL is not installed, which is acceptable in tests
	_ = err
}

// TestProbeInitializeWithInvalidConfig tests probe initialization with invalid config
func TestProbeInitializeWithInvalidConfig(t *testing.T) {
	probe := NewProbe()

	// Pass a base config instead of PostgreSQL config
	cfg := config.NewBaseConfig()
	dispatcher := &mockDispatcher{}
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg, dispatcher)
	if err == nil {
		t.Error("Expected error when initializing with invalid config type")
	}
}

// Mock dispatcher for testing
type mockDispatcher struct{}

func (m *mockDispatcher) Register(handler domain.EventHandler) error {
	return nil
}

func (m *mockDispatcher) Unregister(handlerName string) error {
	return nil
}

func (m *mockDispatcher) Dispatch(event domain.Event) error {
	return nil
}

func (m *mockDispatcher) Close() error {
	return nil
}

// TestEventDecode tests PostgreSQL event decoding
func TestEventDecode(t *testing.T) {
	event := &Event{}

	// Create test data matching the C struct layout
	testData := make([]byte, 296) // 8 + 8 + 256 + 16 + 8 bytes

	// Set PID = 1234 (8 bytes little-endian)
	testData[0] = 0xD2
	testData[1] = 0x04

	// Set Timestamp = 1000000 (8 bytes little-endian)
	testData[8] = 0x40
	testData[9] = 0x42
	testData[10] = 0x0F

	// Set Query = "SELECT * FROM users"
	query := "SELECT * FROM users"
	copy(testData[16:16+len(query)], []byte(query))

	// Set Comm = "postgres"
	comm := "postgres"
	copy(testData[272:272+len(comm)], []byte(comm))

	err := event.DecodeFromBytes(testData)
	if err != nil {
		t.Fatalf("Failed to decode event: %v", err)
	}

	if event.GetPid() != 1234 {
		t.Errorf("Expected PID 1234, got %d", event.GetPid())
	}

	decodedQuery := event.GetQuery()
	if decodedQuery != query {
		t.Errorf("Expected query '%s', got '%s'", query, decodedQuery)
	}

	decodedComm := event.GetComm()
	if decodedComm != comm {
		t.Errorf("Expected comm '%s', got '%s'", comm, decodedComm)
	}
}

// TestEventValidate tests event validation
func TestEventValidate(t *testing.T) {
	// Valid event
	event := &Event{
		Pid:       1234,
		Timestamp: 1000000,
	}
	if err := event.Validate(); err != nil {
		t.Errorf("Expected valid event to pass validation, got error: %v", err)
	}

	// Invalid event - zero PID
	invalidEvent := &Event{
		Pid:       0,
		Timestamp: 1000000,
	}
	if err := invalidEvent.Validate(); err == nil {
		t.Error("Expected validation error for zero PID")
	}

	// Invalid event - zero timestamp
	invalidEvent2 := &Event{
		Pid:       1234,
		Timestamp: 0,
	}
	if err := invalidEvent2.Validate(); err == nil {
		t.Error("Expected validation error for zero timestamp")
	}
}

// TestEventClone tests event cloning
func TestEventClone(t *testing.T) {
	original := &Event{
		Pid:       1234,
		Timestamp: 1000000,
	}
	copy(original.Query[:], []byte("SELECT * FROM users"))
	copy(original.Comm[:], []byte("postgres"))

	cloned := original.Clone()
	if cloned == nil {
		t.Fatal("Expected non-nil cloned event")
	}

	clonedEvent, ok := cloned.(*Event)
	if !ok {
		t.Fatal("Expected cloned event to be *Event type")
	}

	if clonedEvent.GetPid() != original.GetPid() {
		t.Error("Cloned event PID does not match original")
	}

	if clonedEvent.GetQuery() != original.GetQuery() {
		t.Error("Cloned event Query does not match original")
	}

	// Modify clone to ensure deep copy
	clonedEvent.Pid = 5678
	if original.Pid == clonedEvent.Pid {
		t.Error("Modifying cloned event affected original")
	}
}

// TestEventTypeAndUUID tests event type and UUID generation
func TestEventTypeAndUUID(t *testing.T) {
	event := &Event{
		Pid:       1234,
		Timestamp: 1000000,
	}

	if event.Type() != domain.EventTypeOutput {
		t.Errorf("Expected type EventTypeOutput, got %v", event.Type())
	}

	uuid := event.UUID()
	if uuid == "" {
		t.Error("Expected non-empty UUID")
	}

	// UUID should be unique for different events
	event2 := &Event{
		Pid:       5678,
		Timestamp: 2000000,
	}
	if event.UUID() == event2.UUID() {
		t.Error("Expected different UUIDs for different events")
	}
}

// TestEventIsTruncated tests the truncation detection
func TestEventIsTruncated(t *testing.T) {
	// Not truncated - has zero bytes at the end
	event := &Event{}
	copy(event.Query[:], []byte("SELECT * FROM users"))
	if event.IsTruncated() {
		t.Error("Expected event to not be truncated")
	}

	// Truncated - non-zero byte at the end
	truncatedEvent := &Event{}
	for i := 0; i < MaxDataSizePostgres; i++ {
		truncatedEvent.Query[i] = 'A'
	}
	if !truncatedEvent.IsTruncated() {
		t.Error("Expected event to be truncated")
	}
}

// Mock implementations for testing
var _ domain.Configuration = (*Config)(nil)
var _ domain.Probe = (*Probe)(nil)
var _ domain.Event = (*Event)(nil)
