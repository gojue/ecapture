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

package builder

import (
	"testing"

	"github.com/gojue/ecapture/internal/config"
)

func TestNewConfigBuilder(t *testing.T) {
	builder := NewConfigBuilder()
	if builder == nil {
		t.Fatal("NewConfigBuilder returned nil")
		return
	}
	if builder.config == nil {
		t.Fatal("ConfigBuilder.config is nil")
		return
	}
}

func TestConfigBuilderFluentAPI(t *testing.T) {
	cfg, err := NewConfigBuilder().
		WithPid(1234).
		WithUid(5678).
		WithDebug(true).
		WithHex(false).
		WithBTF(config.BTFModeCore).
		WithTruncateSize(1024).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if cfg.GetPid() != 1234 {
		t.Errorf("expected Pid=1234, got %d", cfg.GetPid())
		return
	}
	if cfg.GetUid() != 5678 {
		t.Errorf("expected Uid=5678, got %d", cfg.GetUid())
		return
	}
	if !cfg.GetDebug() {
		t.Error("expected Debug=true")
	}
	if cfg.GetHex() {
		t.Error("expected Hex=false")
	}
	if cfg.GetBTF() != config.BTFModeCore {
		t.Errorf("expected BTF=%d, got %d", config.BTFModeCore, cfg.GetBTF())
	}
	if cfg.GetTruncateSize() != 1024 {
		t.Errorf("expected TruncateSize=1024, got %d", cfg.GetTruncateSize())
	}
}

func TestConfigBuilderInvalidConfig(t *testing.T) {
	// Create an invalid configuration
	builder := NewConfigBuilder()
	builder.config.PerCpuMapSize = -1 // Invalid value

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should return error for invalid config")
	}
}

func TestConfigBuilderMustBuild(t *testing.T) {
	// Test successful build
	cfg := NewConfigBuilder().
		WithPid(1234).
		MustBuild()

	if cfg.GetPid() != 1234 {
		t.Errorf("expected Pid=1234, got %d", cfg.GetPid())
		return
	}
}

func TestConfigBuilderMustBuildPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustBuild() should panic for invalid config")
		}
	}()

	builder := NewConfigBuilder()
	builder.config.PerCpuMapSize = -1 // Invalid value
	builder.MustBuild()               // Should panic
}
