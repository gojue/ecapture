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

package zsh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.BaseConfig)
	assert.Equal(t, 128, cfg.ErrNo)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr bool
	}{
		{
			name: "valid config with zsh path",
			setup: func(c *Config) {
				c.Zshpath = "/bin/zsh"
			},
			wantErr: false,
		},
		{
			name: "valid config auto-detect",
			setup: func(c *Config) {
				// Auto-detection will find /bin/zsh or $SHELL
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			if tt.setup != nil {
				tt.setup(cfg)
			}

			err := cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// May fail if zsh is not installed
				if err != nil {
					t.Skipf("Skipping test: %v", err)
				}
			}
		})
	}
}

func TestEvent_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "insufficient data",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{}
			err := event.DecodeFromBytes(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
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
				Pid: 1234,
				Uid: 1000,
			},
			wantErr: false,
		},
		{
			name: "event with PID 0 is valid (root process)",
			event: &Event{
				Pid: 0,
				Uid: 1000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEvent_String(t *testing.T) {
	event := &Event{
		Pid: 1234,
		Uid: 1000,
	}
	copy(event.Comm[:], []byte("zsh"))
	copy(event.Line[:], []byte("ls -la"))

	str := event.String()
	assert.Contains(t, str, "PID:1234")
	assert.Contains(t, str, "UID:1000")
	assert.Contains(t, str, "zsh")
	assert.Contains(t, str, "ls -la")
}

func TestEvent_Clone(t *testing.T) {
	original := &Event{
		ZshType: 0,
		Pid:     1234,
		Uid:     1000,
	}
	copy(original.Comm[:], []byte("zsh"))
	copy(original.Line[:], []byte("test command"))

	clone := original.Clone()
	require.NotNil(t, clone)

	// Clone returns a new empty event
	cloneEvent, ok := clone.(*Event)
	require.True(t, ok)
	assert.NotNil(t, cloneEvent)
}

func TestNewProbe(t *testing.T) {
	probe := NewProbe()
	assert.NotNil(t, probe)
	assert.NotNil(t, probe.BaseProbe)
	assert.Equal(t, "Zsh", probe.Name())
}
