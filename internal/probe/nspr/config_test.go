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
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig() returned nil")
	}

	if cfg.CaptureMode != "text" {
		t.Errorf("Expected default CaptureMode 'text', got '%s'", cfg.CaptureMode)
	}

	if cfg.PID != 0 {
		t.Errorf("Expected default PID 0, got %d", cfg.PID)
	}
}

func TestConfig_isSupportedVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{"NSS 3.90", "3.90", true},
		{"NSS 3.88.1", "3.88.1", true},
		{"NSS 3.6", "3.6", true},
		{"NSS 2.0", "2.0", false},
		{"NSS 4.0", "4.0", false},
	}

	cfg := NewConfig()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.isSupportedVersion(tt.version)
			if result != tt.expected {
				t.Errorf("isSupportedVersion(%s) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestConfig_selectBPFFileName(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"NSS 3.90", "3.90", "nspr_kern.o"},
		{"NSS 3.88", "3.88", "nspr_kern.o"},
		{"NSS 3.6", "3.6", "nspr_kern.o"},
	}

	cfg := NewConfig()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.selectBPFFileName(tt.version)
			if result != tt.expected {
				t.Errorf("selectBPFFileName(%s) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}

func TestConfig_validateCaptureMode_Text(t *testing.T) {
	cfg := NewConfig()
	cfg.CaptureMode = "text"

	if err := cfg.validateCaptureMode(); err != nil {
		t.Errorf("validateCaptureMode() failed for text mode: %v", err)
	}
}

func TestConfig_validateCaptureMode_Keylog(t *testing.T) {
	// Create a temp directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		keylogFile  string
		shouldError bool
	}{
		{
			name:        "Valid keylog file",
			keylogFile:  filepath.Join(tempDir, "test_keylog.log"),
			shouldError: false,
		},
		{
			name:        "Missing keylog file",
			keylogFile:  "",
			shouldError: true,
		},
		{
			name:        "Non-existent directory",
			keylogFile:  "/nonexistent/path/keylog.log",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.CaptureMode = "keylog"
			cfg.KeylogFile = tt.keylogFile

			err := cfg.validateCaptureMode()
			if tt.shouldError && err == nil {
				t.Error("validateCaptureMode() should have failed but didn't")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("validateCaptureMode() failed unexpectedly: %v", err)
			}
		})
	}
}

func TestConfig_validateCaptureMode_Pcap(t *testing.T) {
	// Create a temp directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		pcapFile    string
		ifname      string
		shouldError bool
	}{
		{
			name:        "Missing pcap file",
			pcapFile:    "",
			ifname:      "eth0",
			shouldError: true,
		},
		{
			name:        "Missing interface name",
			pcapFile:    filepath.Join(tempDir, "test.pcapng"),
			ifname:      "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.CaptureMode = "pcap"
			cfg.PcapFile = tt.pcapFile
			cfg.Ifname = tt.ifname

			err := cfg.validateCaptureMode()
			if tt.shouldError && err == nil {
				t.Error("validateCaptureMode() should have failed but didn't")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("validateCaptureMode() failed unexpectedly: %v", err)
			}
		})
	}
}

func TestConfig_validateCaptureMode_Invalid(t *testing.T) {
	cfg := NewConfig()
	cfg.CaptureMode = "invalid"

	err := cfg.validateCaptureMode()
	if err == nil {
		t.Error("validateCaptureMode() should have failed for invalid mode")
	}
}

func TestConfig_validateNetworkInterface(t *testing.T) {
	tests := []struct {
		name        string
		ifname      string
		shouldError bool
	}{
		{
			name:        "Loopback interface",
			ifname:      "lo",
			shouldError: false,
		},
		{
			name:        "Non-existent interface",
			ifname:      "nonexistent999",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Ifname = tt.ifname

			err := cfg.validateNetworkInterface()
			if tt.shouldError && err == nil {
				t.Error("validateNetworkInterface() should have failed but didn't")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("validateNetworkInterface() failed unexpectedly: %v", err)
			}
		})
	}
}

func TestConfig_checkTCSupport(t *testing.T) {
	cfg := NewConfig()
	cfg.Ifname = "lo"

	// Check if /proc/sys/net/core exists (basic networking support)
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		t.Skip("Skipping test: /proc/sys/net/core not available on this system")
	}

	err := cfg.checkTCSupport()
	if err != nil {
		t.Errorf("checkTCSupport() failed: %v", err)
	}
}
