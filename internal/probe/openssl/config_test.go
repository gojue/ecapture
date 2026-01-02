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
