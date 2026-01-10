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

package gotls

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// mockDispatcher implements domain.EventDispatcher for testing
type mockDispatcher struct{}

func (m *mockDispatcher) Register(handler domain.EventHandler) error { return nil }
func (m *mockDispatcher) Unregister(handlerName string) error        { return nil }
func (m *mockDispatcher) Dispatch(event domain.Event) error          { return nil }
func (m *mockDispatcher) Close() error                               { return nil }

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	if probe == nil {
		t.Fatal("NewProbe() returned nil")
	}
}

func TestProbe_Initialize_TextMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	cfg := NewConfig()
	cfg.CaptureMode = "text"

	ctx := context.Background()
	dispatcher := &mockDispatcher{}
	if err := probe.Initialize(ctx, cfg, dispatcher); err != nil {
		t.Errorf("Initialize() failed for text mode: %v", err)
	}

	if probe.config == nil {
		t.Error("expected config to be set")
	}

	if probe.config.CaptureMode != "text" {
		t.Errorf("expected capture mode 'text', got %q", probe.config.CaptureMode)
	}

	// Clean up
	_ = probe.Close()
}

func TestProbe_Initialize_KeylogMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tmpDir := t.TempDir()
	keylogFile := filepath.Join(tmpDir, "keylog.txt")

	cfg := NewConfig()
	cfg.CaptureMode = handlers.ModeKeylog
	cfg.KeylogFile = keylogFile

	ctx := context.Background()
	dispatcher := &mockDispatcher{}
	if err := probe.Initialize(ctx, cfg, dispatcher); err != nil {
		t.Errorf("Initialize() failed for keylog mode: %v", err)
	}

	if probe.keylogFile == nil {
		t.Error("expected keylogFile to be opened")
	}

	// Clean up
	_ = probe.Close()

	// Check if file was created
	if _, err := os.Stat(keylogFile); os.IsNotExist(err) {
		t.Error("keylog file was not created")
	}
}

func TestProbe_Initialize_PcapMode(t *testing.T) {
	// This test only runs if we can find a valid network interface
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(ifaces) == 0 {
		t.Skip("Cannot find network interfaces, skipping test")
	}

	ifname := ifaces[0].Name()
	if ifname == "lo" && len(ifaces) > 1 {
		ifname = ifaces[1].Name() // Skip loopback if possible
	}

	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tmpDir := t.TempDir()
	pcapFile := filepath.Join(tmpDir, "capture.pcapng")

	cfg := NewConfig()
	cfg.CaptureMode = handlers.ModePcap
	cfg.PcapFile = pcapFile
	cfg.Ifname = ifname

	ctx := context.Background()
	dispatcher := &mockDispatcher{}
	if err := probe.Initialize(ctx, cfg, dispatcher); err != nil {
		t.Errorf("Initialize() failed for pcap mode: %v", err)
	}

	if probe.pcapFile == nil {
		t.Error("expected pcapFile to be opened")
	}

	// Clean up
	_ = probe.Close()

	// Check if file was created
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Error("pcap file was not created")
	}
}

func TestProbe_Close(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tmpDir := t.TempDir()
	keylogFile := filepath.Join(tmpDir, "keylog.txt")

	cfg := NewConfig()
	cfg.CaptureMode = handlers.ModeKeylog
	cfg.KeylogFile = keylogFile

	ctx := context.Background()
	dispatcher := &mockDispatcher{}
	if err := probe.Initialize(ctx, cfg, dispatcher); err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	// Close should not fail
	if err := probe.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// File handles should be cleared
	if probe.keylogFile != nil {
		t.Error("keylogFile should be nil after Close()")
	}

	// Close again should not fail
	if err := probe.Close(); err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}
