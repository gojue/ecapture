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
)

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
	if err := probe.Initialize(ctx, cfg, nil); err != nil {
		t.Errorf("Initialize() failed for text mode: %v", err)
	}

	if probe.textHandler == nil {
		t.Error("expected textHandler to be initialized")
	}

	// Clean up
	probe.Close()
}

func TestProbe_Initialize_KeylogMode(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tmpDir := t.TempDir()
	keylogFile := filepath.Join(tmpDir, "keylog.txt")

	cfg := NewConfig()
	cfg.CaptureMode = "keylog"
	cfg.KeylogFile = keylogFile

	ctx := context.Background()
	if err := probe.Initialize(ctx, cfg, nil); err != nil {
		t.Errorf("Initialize() failed for keylog mode: %v", err)
	}

	if probe.keylogHandler == nil {
		t.Error("expected keylogHandler to be initialized")
	}

	if probe.keylogFile == nil {
		t.Error("expected keylogFile to be opened")
	}

	// Clean up
	probe.Close()

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

	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	tmpDir := t.TempDir()
	pcapFile := filepath.Join(tmpDir, "capture.pcapng")

	cfg := NewConfig()
	cfg.CaptureMode = "pcap"
	cfg.PcapFile = pcapFile
	cfg.Ifname = ifname

	ctx := context.Background()
	if err := probe.Initialize(ctx, cfg, nil); err != nil {
		t.Errorf("Initialize() failed for pcap mode: %v", err)
	}

	if probe.pcapHandler == nil {
		t.Error("expected pcapHandler to be initialized")
	}

	if probe.pcapFile == nil {
		t.Error("expected pcapFile to be opened")
	}

	// Clean up
	probe.Close()

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
	cfg.CaptureMode = "keylog"
	cfg.KeylogFile = keylogFile

	ctx := context.Background()
	if err := probe.Initialize(ctx, cfg, nil); err != nil {
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
