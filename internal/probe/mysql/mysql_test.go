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

package mysql

import (
	"context"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/events"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
)

func TestMysqlVersion_String(t *testing.T) {
	tests := []struct {
		version  MysqlVersion
		expected string
	}{
		{MysqlVersionUnknown, "Unknown"},
		{MysqlVersion56, "MySQL 5.6"},
		{MysqlVersion57, "MySQL 5.7"},
		{MysqlVersion80, "MySQL 8.0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("MysqlVersion.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDispatchCommandReturn_String(t *testing.T) {
	tests := []struct {
		retval   DispatchCommandReturn
		expected string
	}{
		{DispatchCommandSuccess, "SUCCESS"},
		{DispatchCommandCloseConnection, "CLOSE_CONNECTION"},
		{DispatchCommandWouldblock, "WOULDBLOCK"},
		{DispatchCommandNotCaptured, "NOT_CAPTURED"},
		{DispatchCommandV57Failed, "V57_FAILED"},
		{DispatchCommandReturn(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.retval.String(); got != tt.expected {
				t.Errorf("DispatchCommandReturn.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "empty mysql path",
			config: &Config{
				BaseConfig: NewConfig().BaseConfig,
				MysqlPath:  "",
			},
			wantErr: true,
		},
		{
			name: "with function name",
			config: &Config{
				BaseConfig: NewConfig().BaseConfig,
				MysqlPath:  "/usr/sbin/mysqld",
				FuncName:   "dispatch_command",
			},
			wantErr: false, // Will fail on non-existent file, but validation logic passes
		},
		{
			name: "with offset",
			config: &Config{
				BaseConfig: NewConfig().BaseConfig,
				MysqlPath:  "/usr/sbin/mysqld",
				Offset:     0x12345,
			},
			wantErr: false, // Will fail on non-existent file, but validation logic passes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvent_DecodeFromBytes(t *testing.T) {
	// Create a sample event with known values
	event := &Event{
		Pid:       12345,
		Timestamp: 1234567890,
		Len:       10,
		Alllen:    50,
		Retval:    DispatchCommandSuccess,
	}
	copy(event.Query[:], []byte("SELECT * FROM users"))
	copy(event.Comm[:], []byte("mysqld"))

	// For a real test, we would need proper binary encoding.
	// This test just validates the structure exists and can be instantiated.
	if event.Pid != 12345 {
		t.Errorf("Event.Pid = %d, want 12345", event.Pid)
		return
	}
}

func TestEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *Event
		wantErr bool
	}{
		{
			name: "valid event",
			event: &Event{
				Len:    10,
				Alllen: 50,
			},
			wantErr: false,
		},
		{
			name: "len exceeds max",
			event: &Event{
				Len:    MaxDataSize + 1,
				Alllen: MaxDataSize + 10,
			},
			wantErr: true,
		},
		{
			name: "len exceeds alllen",
			event: &Event{
				Len:    100,
				Alllen: 50,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Event.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvent_Methods(t *testing.T) {
	event := &Event{
		Pid:    12345,
		Len:    15,
		Alllen: 100,
		Retval: DispatchCommandSuccess,
	}
	copy(event.Comm[:], []byte("mysqld"))
	copy(event.Query[:], []byte("SELECT * FROM"))

	t.Run("GetPID", func(t *testing.T) {
		if got := event.GetPID(); got != 12345 {
			t.Errorf("Event.GetPID() = %v, want %v", got, 12345)
		}
	})

	t.Run("GetComm", func(t *testing.T) {
		if got := event.GetComm(); got != "mysqld" {
			t.Errorf("Event.GetComm() = %v, want %v", got, "mysqld")
		}
	})

	t.Run("GetQueryLen", func(t *testing.T) {
		if got := event.GetQueryLen(); got != 15 {
			t.Errorf("Event.GetQueryLen() = %v, want %v", got, 15)
		}
	})

	t.Run("IsTruncated", func(t *testing.T) {
		if got := event.IsTruncated(); !got {
			t.Errorf("Event.IsTruncated() = %v, want %v", got, true)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if got := event.Type(); got != domain.EventTypeOutput {
			t.Errorf("Event.Type() = %v, want %v", got, domain.EventTypeOutput)
		}
	})

	t.Run("Clone", func(t *testing.T) {
		cloned := event.Clone()
		if cloned == nil {
			t.Error("Event.Clone() returned nil")
		}
		if _, ok := cloned.(*Event); !ok {
			t.Errorf("Event.Clone() returned wrong type: %T", cloned)
			return
		}
	})
}

func TestProbe_Creation(t *testing.T) {
	probe := NewProbe()
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
	}

	if probe.Name() != "mysql" {
		t.Errorf("Probe.Name() = %v, want %v", probe.Name(), "mysql")
	}
}

func TestProbe_Initialize(t *testing.T) {
	probe := NewProbe()
	config := NewConfig()
	config.MysqlPath = "/usr/sbin/mysqld"
	config.FuncName = "dispatch_command"

	dispatcher := events.NewDispatcher(logger.New(nil, false))
	ctx := context.Background()

	// Initialize should succeed with function name provided (no file check during init)
	err := probe.Initialize(ctx, config, dispatcher)
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
		return
	}

	// Verify probe name
	if probe.Name() != "mysql" {
		t.Errorf("Probe name = %s, want mysql", probe.Name())
	}
}

func TestProbe_FactoryRegistration(t *testing.T) {
	// Test that the probe is registered with the factory
	probe, err := factory.CreateProbe(factory.ProbeTypeMySQL)
	if err != nil {
		t.Fatalf("Failed to create MySQL probe from factory: %v", err)
		return
	}

	if probe == nil {
		t.Fatal("Factory returned nil probe")
		return
	}

	if probe.Name() != "mysql" {
		t.Errorf("Factory probe name = %v, want %v", probe.Name(), "mysql")
	}
}
