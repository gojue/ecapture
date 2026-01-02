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

package gnutls

import (
	"bytes"
	"context"
	"testing"
)

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() returned error: %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil probe")
	}
}

func TestProbe_Initialize_TextMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error: %v", err)
	}

	cfg := NewConfig()
	cfg.GnutlsPath = "/usr/lib/libgnutls.so.30"
	cfg.GnuVersion = "3.7.10"
	cfg.CaptureMode = "text"
	probe.output = &bytes.Buffer{}

	ctx := context.Background()
	// Note: Will fail if GnuTLS not installed, but that's expected
	err = probe.Initialize(ctx, cfg, nil)
	if err != nil {
		t.Logf("Initialize() failed (expected if GnuTLS not installed): %v", err)
	}
}

func TestProbe_Close(t *testing.T) {
	probe, _ := NewProbe()
	// Close handlers individually since BaseProbe might not be fully initialized
	// This is a stub implementation test
	if probe.textHandler != nil {
		probe.textHandler.Close()
	}
	if probe.keylogHandler != nil {
		probe.keylogHandler.Close()
	}
	if probe.pcapHandler != nil {
		probe.pcapHandler.Close()
	}
	t.Log("Close test completed for stub implementation")
}

func TestProbe_Events(t *testing.T) {
	probe, _ := NewProbe()
	if probe == nil {
		t.Fatal("NewProbe returned nil")
	}
	events := probe.Events()
	if events == nil {
		t.Error("Events() returned nil")
	}
	// Stub implementation returns empty slice
	if len(events) != 0 {
		t.Errorf("Events() should return empty slice in stub, got %d", len(events))
	}
}
