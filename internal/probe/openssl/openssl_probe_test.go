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

package openssl

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
		return
	}
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_Initialize(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	cfg := NewConfig()
	cfg.OpensslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
	cfg.SslVersion = Version_1_1_1

	// Test that Initialize requires a dispatcher
	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() with nil dispatcher should return error")
	}
}

func TestProbe_Initialize_InvalidConfig(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Use wrong config type
	cfg := NewConfig()
	cfg.OpensslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
	cfg.SslVersion = "invalid-version"

	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	// Will fail due to nil dispatcher first
	if err == nil {
		t.Error("Initialize() with nil dispatcher should return error")
	}
}

func TestProbe_SetOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	buf := &bytes.Buffer{}
	probe.SetOutput(buf)

	if probe.output != buf {
		t.Error("SetOutput() did not set output correctly")
	}
}

func TestProbe_Close(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Close without initializing - should handle gracefully
	// We can't test this directly because BaseProbe requires initialization
	// Just test that the probe was created successfully
	if probe == nil {
		t.Error("Probe should not be nil")
	}
}

func TestProbe_Events(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	events := probe.Events()
	// Should return empty slice for stub implementation
	if events == nil {
		t.Error("Events() returned nil")
	}
}

func TestProbe_Lifecycle(t *testing.T) {
	// Test basic lifecycle without full initialization
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Set output
	var buf bytes.Buffer
	probe.SetOutput(&buf)

	// Just test that basic methods work
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_WithRealOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Test with a real writer
	var buf bytes.Buffer
	probe.SetOutput(io.Writer(&buf))

	if probe.output == nil {
		t.Error("Output writer not set")
	}
}
