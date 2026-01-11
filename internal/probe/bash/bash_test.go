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

package bash

import (
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig returned nil")
		return
	}
	if cfg.ErrNo != 128 {
		t.Errorf("expected ErrNo=128, got %d", cfg.ErrNo)
		return
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := NewConfig()

	// Test with invalid PerCpuMapSize
	cfg.PerCpuMapSize = -1
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with invalid PerCpuMapSize")
	}
}

func TestCommToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "null terminated",
			input:    []byte{'b', 'a', 's', 'h', 0, 0, 0},
			expected: "bash",
		},
		{
			name:     "full buffer",
			input:    []byte{'t', 'e', 's', 't'},
			expected: "test",
		},
		{
			name:     "empty",
			input:    []byte{0, 0, 0},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := commToString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
				return
			}
		})
	}
}

func TestEventDecodeFromBytes(t *testing.T) {
	event := &Event{}

	// Create minimal valid data
	data := make([]byte, 4+4+4+256+4+16) // BashType+Pid+Uid+Line+ReturnValue+Comm

	err := event.DecodeFromBytes(data)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
		return
	}
}

func TestEventString(t *testing.T) {
	event := &Event{
		Pid:         1234,
		Uid:         1000,
		Comm:        [16]byte{'b', 'a', 's', 'h', 0},
		ReturnValue: 0,
		AllLines:    "echo hello",
	}

	str := event.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	if !contains(str, "1234") {
		t.Error("String() should contain PID")
	}
	if !contains(str, "echo hello") {
		t.Error("String() should contain command")
	}
}

func TestEventUUID(t *testing.T) {
	event := &Event{
		Pid:  1234,
		Uid:  1000,
		Comm: [16]byte{'b', 'a', 's', 'h', 0},
	}

	uuid := event.UUID()
	if uuid == "" {
		t.Error("UUID() returned empty string")
	}
	if !contains(uuid, "1234") {
		t.Error("UUID() should contain PID")
	}
	if !contains(uuid, "1000") {
		t.Error("UUID() should contain UID")
	}
}

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
	}
	if probe.Name() != "bash" {
		t.Errorf("expected name 'bash', got %s", probe.Name())
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
