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

package base

import (
	"context"
	"testing"
	"time"

	"github.com/gojue/ecapture/internal/config"
)

func TestNewBaseProbe(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	if probe == nil {
		t.Fatal("NewBaseProbe returned nil")
		return
	}
	if probe.Name() != "test-probe" {
		t.Errorf("expected name 'test-probe', got '%s'", probe.Name())
	}
	if probe.IsRunning() {
		t.Error("newly created probe should not be running")
	}
}

func TestBaseProbeInitialize(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := config.NewBaseConfig()
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if probe.Config() != cfg {
		t.Error("config not set correctly")
	}
	if probe.Dispatcher() == nil {
		t.Error("dispatcher not initialized")
	}
	if probe.Context() != ctx {
		t.Error("context not set correctly")
	}
}

func TestBaseProbeInitializeInvalidConfig(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := &config.BaseConfig{
		PerCpuMapSize: -1, // Invalid
	}
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() should return error for invalid config")
	}
}

func TestBaseProbeInitializeNilConfig(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	ctx := context.Background()

	err := probe.Initialize(ctx, nil)
	if err == nil {
		t.Error("Initialize() should return error for nil config")
	}
}

func TestBaseProbeInitializeNilDispatcher(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := config.NewBaseConfig()
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() should return error for nil dispatcher")
	}
}

func TestBaseProbeLifecycle(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := config.NewBaseConfig()
	ctx := context.Background()

	// Initialize
	err := probe.Initialize(ctx, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Start
	err = probe.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !probe.IsRunning() {
		t.Error("probe should be running after Start()")
	}

	// Start again (should error)
	err = probe.Start(ctx)
	if err == nil {
		t.Error("Start() should return error when already running")
	}

	// Stop
	err = probe.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if probe.IsRunning() {
		t.Error("probe should not be running after Stop()")
	}

	// Close
	err = probe.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if probe.IsRunning() {
		t.Error("probe should not be running after Close()")
	}
}

func TestBaseProbeCloseWithReaders(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := config.NewBaseConfig()
	ctx := context.Background()

	err := probe.Initialize(ctx, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Add a mock reader
	mockReader := &mockCloser{closed: false}
	probe.readers = append(probe.readers, mockReader)

	err = probe.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if !mockReader.closed {
		t.Error("reader was not closed")
	}
	if len(probe.readers) != 0 {
		t.Errorf("expected 0 readers after close, got %d", len(probe.readers))
	}
}

func TestBaseProbeStopAndClose(t *testing.T) {
	probe := NewBaseProbe("test-probe")
	cfg := config.NewBaseConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := probe.Initialize(ctx, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	err = probe.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop multiple times should not error
	_ = probe.Stop(ctx)
	err = probe.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() should not error when called multiple times")
	}

	err = probe.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// mockCloser implements the closer interface for testing
type mockCloser struct {
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}
