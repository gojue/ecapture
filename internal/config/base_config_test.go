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

package config

import (
	"testing"
)

func TestNewBaseConfig(t *testing.T) {
	cfg := NewBaseConfig()
	if cfg == nil {
		t.Fatal("NewBaseConfig returned nil")
	}
	if cfg.PerCpuMapSize != DefaultMapSizePerCpu {
		t.Errorf("expected PerCpuMapSize=%d, got %d", DefaultMapSizePerCpu, cfg.PerCpuMapSize)
	}
}

func TestBaseConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *BaseConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  NewBaseConfig(),
			wantErr: false,
		},
		{
			name: "invalid per cpu map size",
			config: &BaseConfig{
				PerCpuMapSize: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid btf mode",
			config: &BaseConfig{
				PerCpuMapSize: DefaultMapSizePerCpu,
				BtfMode:       99,
			},
			wantErr: true,
		},
		{
			name: "invalid bytecode file mode",
			config: &BaseConfig{
				PerCpuMapSize:    DefaultMapSizePerCpu,
				ByteCodeFileMode: 99,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBaseConfigGettersSetters(t *testing.T) {
	cfg := NewBaseConfig()

	// Test Pid
	cfg.SetPid(1234)
	if cfg.GetPid() != 1234 {
		t.Errorf("expected Pid=1234, got %d", cfg.GetPid())
	}

	// Test Uid
	cfg.SetUid(5678)
	if cfg.GetUid() != 5678 {
		t.Errorf("expected Uid=5678, got %d", cfg.GetUid())
	}

	// Test Debug
	cfg.SetDebug(true)
	if !cfg.GetDebug() {
		t.Error("expected Debug=true")
	}

	// Test Hex
	cfg.SetHex(true)
	if !cfg.GetHex() {
		t.Error("expected Hex=true")
	}

	// Test BTF
	cfg.SetBTF(BTFModeCore)
	if cfg.GetBTF() != BTFModeCore {
		t.Errorf("expected BTF=%d, got %d", BTFModeCore, cfg.GetBTF())
	}

	// Test TruncateSize
	cfg.SetTruncateSize(1024)
	if cfg.GetTruncateSize() != 1024 {
		t.Errorf("expected TruncateSize=1024, got %d", cfg.GetTruncateSize())
	}
}

func TestBaseConfigBytes(t *testing.T) {
	cfg := NewBaseConfig()
	cfg.SetPid(1234)
	cfg.SetDebug(true)

	bytes := cfg.Bytes()
	if len(bytes) == 0 {
		t.Error("Bytes() returned empty byte slice")
	}
}
