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
	"context"
	"path/filepath"
	"testing"
)

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	if probe == nil {
		t.Fatal("NewProbe() returned nil probe")
	}
}

func TestProbe_Initialize_InvalidConfig(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	ctx := context.Background()

	// Pass invalid config type
	err = probe.Initialize(ctx, "invalid", nil)
	if err == nil {
		t.Error("Initialize() should have failed with invalid config type")
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
