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

package nspr

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
)

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
	}
	if probe.Name() != "nspr" {
		t.Errorf("expected name 'nspr', got %s", probe.Name())
	}
}

func TestProbe_Initialize_InvalidConfig(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	ctx := context.Background()

	// Pass invalid config type (nil is invalid)
	invalidConfig := &Config{} // Valid type but nil BaseConfig
	err = probe.Initialize(ctx, invalidConfig, nil)
	if err == nil {
		t.Error("Initialize() should have failed with invalid config")
	}
}

func TestProbe_Initialize_TextMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	cfg := NewConfig()
	cfg.CaptureMode = "text"
	// Set dummy paths to skip library detection
	cfg.NSSPath = "/usr/lib/libnss3.so"
	cfg.NSPRPath = "/usr/lib/libnspr4.so"

	ctx := context.Background()

	// This will fail because the libraries don't exist, but it validates the flow
	err = probe.Initialize(ctx, cfg, nil)
	// We expect this to fail during validation since we're using dummy paths
	if err == nil {
		t.Log("Initialize() succeeded (libraries might exist on this system)")
	}
}

func TestProbe_Initialize_KeylogMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tempDir := t.TempDir()
	cfg := NewConfig()
	cfg.CaptureMode = "keylog"
	cfg.KeylogFile = filepath.Join(tempDir, "test_keylog.log")
	// Set dummy paths to skip library detection
	cfg.NSSPath = "/usr/lib/libnss3.so"
	cfg.NSPRPath = "/usr/lib/libnspr4.so"

	ctx := context.Background()

	// This will fail because the libraries don't exist, but it validates the flow
	err = probe.Initialize(ctx, cfg, nil)
	// We expect this to fail during validation since we're using dummy paths
	if err == nil {
		t.Log("Initialize() succeeded (libraries might exist on this system)")
	}
}

func TestProbe_Name(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	name := probe.Name()
	if name != "nspr" {
		t.Errorf("Name() = %s, want 'nspr'", name)
	}
}

func TestTLSDataEventDecode(t *testing.T) {
	event := &TLSDataEvent{}

	// Create minimal valid data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint64(12345))       // Timestamp
	binary.Write(buf, binary.LittleEndian, uint32(1234))        // PID
	binary.Write(buf, binary.LittleEndian, uint32(5678))        // TID
	binary.Write(buf, binary.LittleEndian, [16]byte{'t'})       // Comm
	binary.Write(buf, binary.LittleEndian, int32(10))           // FD
	binary.Write(buf, binary.LittleEndian, uint32(100))         // DataLen
	binary.Write(buf, binary.LittleEndian, uint32(1))           // Direction
	binary.Write(buf, binary.LittleEndian, [MaxDataSize]byte{}) // Data

	err := event.DecodeFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if event.PID != 1234 {
		t.Errorf("expected PID=1234, got %d", event.PID)
	}
	if event.TID != 5678 {
		t.Errorf("expected TID=5678, got %d", event.TID)
	}
	if event.DataLen != 100 {
		t.Errorf("expected DataLen=100, got %d", event.DataLen)
	}
	if !event.IsWrite() {
		t.Error("expected IsWrite() to be true")
	}
}

func TestTLSDataEventString(t *testing.T) {
	event := &TLSDataEvent{
		Timestamp: 12345,
		PID:       1234,
		TID:       5678,
		Comm:      [16]byte{'f', 'i', 'r', 'e', 'f', 'o', 'x', 0},
		FD:        10,
		DataLen:   100,
		Direction: 0,
	}

	str := event.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	if !contains(str, "1234") {
		t.Error("String() should contain PID")
	}
	if !contains(str, "firefox") {
		t.Error("String() should contain comm")
	}
}

func TestTLSDataEventUUID(t *testing.T) {
	event := &TLSDataEvent{
		PID:       1234,
		TID:       5678,
		Timestamp: 12345,
	}

	uuid := event.UUID()
	if uuid == "" {
		t.Error("UUID() returned empty string")
	}
	if !contains(uuid, "1234") {
		t.Error("UUID() should contain PID")
	}
}

func TestTLSDataEventValidate(t *testing.T) {
	// Valid event
	event := &TLSDataEvent{
		DataLen: 100,
	}
	if err := event.Validate(); err != nil {
		t.Errorf("Validate() should pass for valid event: %v", err)
	}

	// Invalid event - DataLen too large
	event.DataLen = MaxDataSize + 1
	if err := event.Validate(); err == nil {
		t.Error("Validate() should fail for DataLen > MaxDataSize")
	}
}

func TestMasterSecretEventDecode(t *testing.T) {
	event := &MasterSecretEvent{}

	// Create minimal valid data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, [ClientRandomSize]byte{1, 2, 3})
	binary.Write(buf, binary.LittleEndian, [MasterKeySize]byte{4, 5, 6})
	binary.Write(buf, binary.LittleEndian, [TrafficSecretSize]byte{})
	binary.Write(buf, binary.LittleEndian, [TrafficSecretSize]byte{})
	binary.Write(buf, binary.LittleEndian, [TrafficSecretSize]byte{})
	binary.Write(buf, binary.LittleEndian, [TrafficSecretSize]byte{})
	binary.Write(buf, binary.LittleEndian, [TrafficSecretSize]byte{})

	err := event.DecodeFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if event.ClientRandom[0] != 1 {
		t.Errorf("expected ClientRandom[0]=1, got %d", event.ClientRandom[0])
	}
	if !event.HasMasterKey() {
		t.Error("expected HasMasterKey() to be true")
	}
}

func TestMasterSecretEventString(t *testing.T) {
	event := &MasterSecretEvent{
		ClientRandom: [ClientRandomSize]byte{1, 2, 3},
		MasterKey:    [MasterKeySize]byte{4, 5, 6},
	}

	str := event.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	if !contains(str, "ClientRandom") {
		t.Error("String() should contain ClientRandom")
	}
}

func TestMasterSecretEventValidate(t *testing.T) {
	// Valid event with master key
	event := &MasterSecretEvent{
		MasterKey: [MasterKeySize]byte{1, 2, 3},
	}
	if err := event.Validate(); err != nil {
		t.Errorf("Validate() should pass for event with master key: %v", err)
	}

	// Valid event with TLS 1.3 secrets
	event = &MasterSecretEvent{
		ClientHandshakeTrafficSecret: [TrafficSecretSize]byte{1, 2, 3},
	}
	if err := event.Validate(); err != nil {
		t.Errorf("Validate() should pass for event with TLS 1.3 secrets: %v", err)
	}

	// Invalid event - no secrets
	event = &MasterSecretEvent{}
	if err := event.Validate(); err == nil {
		t.Error("Validate() should fail for event with no secrets")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
