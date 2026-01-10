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
	"os"
	"testing"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig returned nil")
	}
	if cfg.BaseConfig == nil {
		t.Error("BaseConfig not initialized")
	}
}

func TestConfig_IsSupportedVersion(t *testing.T) {
	tests := []struct {
		name       string
		sslVersion string
		want       bool
	}{
		{"OpenSSL 1.1.1", Version_1_1_1, true},
		{"OpenSSL 3.0", Version_3_0, true},
		{"OpenSSL 3.1", Version_3_1, true},
		{"Unsupported version", "1.0.2", false},
		{"Empty version", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.SslVersion = tt.sslVersion
			if got := cfg.IsSupportedVersion(); got != tt.want {
				t.Errorf("IsSupportedVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetBPFFileName(t *testing.T) {
	tests := []struct {
		name        string
		sslVersion  string
		isBoringSSL bool
		want        string
	}{
		{"OpenSSL 1.1.1", Version_1_1_1, false, "openssl_1_1_1_kern.o"},
		{"OpenSSL 3.0", Version_3_0, false, "openssl_3_0_0_kern.o"},
		{"OpenSSL 3.1", Version_3_1, false, "openssl_3_0_0_kern.o"},
		{"BoringSSL", Version_1_1_1, true, "openssl_kern_boringssl.o"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.SslVersion = tt.sslVersion
			cfg.IsBoringSSL = tt.isBoringSSL
			if got := cfg.GetBPFFileName(); got != tt.want {
				t.Errorf("GetBPFFileName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Bytes(t *testing.T) {
	cfg := NewConfig()
	cfg.OpensslPath = "/usr/lib/libssl.so.1.1"
	cfg.SslVersion = Version_1_1_1

	bytes := cfg.Bytes()
	if len(bytes) == 0 {
		t.Error("Bytes() returned empty")
	}
}

func TestConfig_DetectOpenSSL(t *testing.T) {
	cfg := NewConfig()

	// Test with explicit path (should work if the file exists)
	cfg.OpensslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
	if _, err := os.Stat(cfg.OpensslPath); err == nil {
		err := cfg.detectOpenSSL()
		if err != nil {
			t.Errorf("detectOpenSSL() with valid path failed: %v", err)
		}
	}

	// Test auto-detection (may or may not find a library depending on system)
	cfg2 := NewConfig()
	err := cfg2.detectOpenSSL()
	// We don't fail the test if detection fails, as it depends on the system
	if err == nil {
		t.Logf("Auto-detected OpenSSL at: %s", cfg2.OpensslPath)
	} else {
		t.Logf("OpenSSL auto-detection failed (expected on systems without OpenSSL): %v", err)
	}
}

func TestConfig_DetectVersion(t *testing.T) {
	cfg := NewConfig()

	// Test with a path that suggests version
	cfg.OpensslPath = "/usr/lib/libssl.so.1.1"
	err := cfg.detectVersion()
	if err != nil {
		t.Logf("detectVersion() failed (expected if file doesn't exist): %v", err)
	}

	// Test with version 3.0 path
	cfg2 := NewConfig()
	cfg2.OpensslPath = "/usr/lib/libssl.so.3"
	err = cfg2.detectVersion()
	if err != nil {
		t.Logf("detectVersion() for 3.x failed (expected if file doesn't exist): %v", err)
	}

	// Test BoringSSL detection
	cfg3 := NewConfig()
	cfg3.OpensslPath = "/usr/lib/libboringssl.so"
	err = cfg3.detectVersion()
	if err == nil && !cfg3.IsBoringSSL {
		t.Error("BoringSSL not detected correctly")
	}
}

func TestConfig_Validate(t *testing.T) {
	// This test will pass or fail depending on whether OpenSSL is installed
	cfg := NewConfig()
	err := cfg.Validate()

	if err != nil {
		t.Logf("Validate() failed (expected on systems without OpenSSL): %v", err)
		// Don't fail the test - just log it
	} else {
		t.Logf("Validate() succeeded - detected OpenSSL at: %s, version: %s",
			cfg.OpensslPath, cfg.SslVersion)

		// If validation succeeded, check that version was detected
		if cfg.SslVersion == "" {
			t.Error("Version not detected after successful validation")
		}
		if cfg.OpensslPath == "" {
			t.Error("OpenSSL path not set after successful validation")
		}
	}
}

func TestConfig_ValidateNetworkInterface(t *testing.T) {
	cfg := NewConfig()

	// Test with loopback interface (should exist on most systems)
	cfg.Ifname = "lo"
	err := cfg.validateNetworkInterface()
	if err != nil {
		t.Logf("validateNetworkInterface('lo') failed: %v (may not exist on this system)", err)
	} else {
		t.Log("validateNetworkInterface('lo') succeeded")
	}

	// Test with non-existent interface
	cfg.Ifname = "nonexistent-interface-12345"
	err = cfg.validateNetworkInterface()
	if err == nil {
		t.Error("validateNetworkInterface() should fail for non-existent interface")
	}

	// Test with empty interface name
	cfg.Ifname = ""
	err = cfg.validateNetworkInterface()
	if err != nil {
		t.Errorf("validateNetworkInterface() should not fail for empty interface: %v", err)
	}
}

func TestConfig_CheckTCSupport(t *testing.T) {
	cfg := NewConfig()

	// Test with loopback interface
	cfg.Ifname = "lo"
	err := cfg.checkTCSupport()
	if err != nil {
		t.Logf("checkTCSupport('lo') failed: %v (expected on non-Linux or restricted systems)", err)
	} else {
		t.Log("checkTCSupport('lo') succeeded")
	}

	// Test with non-existent interface
	cfg.Ifname = "nonexistent-interface-12345"
	err = cfg.checkTCSupport()
	if err == nil {
		t.Error("checkTCSupport() should fail for non-existent interface")
	}
}

func TestConfig_ValidateCaptureMode_Pcap(t *testing.T) {
	cfg := NewConfig()
	cfg.OpensslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	cfg.SslVersion = Version_3_0

	// Test pcap mode validation with valid settings
	cfg.CaptureMode = handlers.ModePcap
	cfg.PcapFile = "/tmp/test.pcapng"
	cfg.Ifname = "lo"

	// Note: Full validation will depend on system state
	// We're mainly testing the validation logic exists
	err := cfg.validateCaptureMode()
	if err != nil {
		t.Logf("Pcap mode validation failed (expected on some systems): %v", err)
	}

	// Test pcap mode without interface
	cfg.Ifname = ""
	err = cfg.validateCaptureMode()
	if err == nil {
		t.Error("validateCaptureMode() should fail for pcap mode without interface")
	}

	// Test pcap mode without file
	cfg.Ifname = "lo"
	cfg.PcapFile = ""
	err = cfg.validateCaptureMode()
	if err == nil {
		t.Error("validateCaptureMode() should fail for pcap mode without pcap file")
	}
}
