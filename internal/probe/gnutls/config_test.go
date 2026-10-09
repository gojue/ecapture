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
	"testing"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func TestConfigImplementsCaptureModeConfiguration(t *testing.T) {
	var cfg domain.CaptureModeConfiguration = &Config{CaptureMode: handlers.ModeKeylog}
	if got := cfg.GetCaptureMode(); got != handlers.ModeKeylog {
		t.Fatalf("GetCaptureMode() = %q, want %q", got, handlers.ModeKeylog)
	}
}

func TestConfig_IsSupportedVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{
			name:    "GnuTLS 3.6",
			version: "3.6.16",
			want:    true,
		},
		{
			name:    "GnuTLS 3.7",
			version: "3.7.10",
			want:    true,
		},
		{
			name:    "GnuTLS 3.8",
			version: "3.8.0",
			want:    true,
		},
		{
			name:    "Unsupported version",
			version: "3.5.0",
			want:    false,
		},
		{
			name:    "Unsupported newer patch",
			version: "3.8.10",
			want:    false,
		},
		{
			name:    "Empty version",
			version: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.GnuVersion = tt.version
			if got := cfg.IsSupportedVersion(); got != tt.want {
				t.Errorf("IsSupportedVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetBPFFileName(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "GnuTLS 3.6.12",
			version: "3.6.12",
			want:    "gnutls_3_6_12_kern.o",
		},
		{
			name:    "GnuTLS 3.6.16",
			version: "3.6.16",
			want:    "gnutls_3_6_13_kern.o",
		},
		{
			name:    "GnuTLS 3.7.10",
			version: "3.7.10",
			want:    "gnutls_3_7_7_kern.o",
		},
		{
			name:    "GnuTLS 3.8.0",
			version: "3.8.0",
			want:    "gnutls_3_7_7_kern.o",
		},
		{
			name:    "GnuTLS 3.8.4",
			version: "3.8.4",
			want:    "gnutls_3_8_4_kern.o",
		},
		{
			name:    "GnuTLS 3.8.9",
			version: "3.8.9",
			want:    "gnutls_3_8_7_kern.o",
		},
		{
			name:    "Unknown version",
			version: "3.5.0",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.GnuVersion = tt.version
			if got := cfg.GetBPFFileName(); got != tt.want {
				t.Errorf("GetBPFFileName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Bytes(t *testing.T) {
	cfg := NewConfig()
	cfg.GnutlsPath = "/usr/lib/libgnutls.so.30"
	cfg.GnuVersion = "3.7.10"

	bytes := cfg.Bytes()
	if len(bytes) == 0 {
		t.Error("Bytes() returned empty result")
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

func TestConfig_ValidateCaptureMode_Text(t *testing.T) {
	cfg := NewConfig()
	cfg.GnutlsPath = "/usr/lib/libgnutls.so.30"
	cfg.GnuVersion = "3.7.10"
	cfg.CaptureMode = handlers.ModeText

	err := cfg.validateCaptureMode()
	if err != nil {
		t.Errorf("Text mode validation failed: %v", err)
		return
	}
}

func TestConfig_ValidateCaptureMode_Keylog(t *testing.T) {
	cfg := NewConfig()
	cfg.GnutlsPath = "/usr/lib/libgnutls.so.30"
	cfg.GnuVersion = "3.7.10"
	cfg.CaptureMode = handlers.ModeKeylog
	cfg.KeylogFile = "/tmp/test_keylog.log"

	err := cfg.validateCaptureMode()
	if err != nil {
		t.Errorf("Keylog mode validation failed: %v", err)
		return
	}

	// Repeated validation retains the normalized primary destination.
	cfg.KeylogFile = ""
	if err = cfg.validateCaptureMode(); err != nil {
		t.Errorf("repeated validation should retain normalized destination: %v", err)
	}

	missingDestination := NewConfig()
	missingDestination.CaptureMode = handlers.ModeKeylog
	if err = missingDestination.validateCaptureMode(); err == nil {
		t.Error("keylog mode without eventaddr or keylogfile should fail")
	}
}

func TestConfig_ValidateCaptureMode_Pcap(t *testing.T) {
	cfg := NewConfig()
	cfg.GnutlsPath = "/usr/lib/libgnutls.so.30"
	cfg.GnuVersion = "3.7.10"
	cfg.CaptureMode = handlers.ModePcap
	cfg.PcapFile = "/tmp/test.pcapng"
	cfg.Ifname = "lo"

	err := cfg.validateCaptureMode()
	if err != nil {
		t.Logf("Pcap mode validation failed (expected on some systems): %v", err)
	}

	// Test without interface
	cfg.Ifname = ""
	err = cfg.validateCaptureMode()
	if err == nil {
		t.Error("validateCaptureMode() should fail for pcap mode without interface")
	}

	// Repeated validation retains the normalized primary destination.
	cfg.Ifname = "lo"
	cfg.PcapFile = ""
	if err = cfg.validateCaptureMode(); err != nil {
		t.Errorf("repeated validation should retain normalized destination: %v", err)
	}

	missingPcapDestination := NewConfig()
	missingPcapDestination.CaptureMode = handlers.ModePcap
	missingPcapDestination.Ifname = "lo"
	if err = missingPcapDestination.validateCaptureMode(); err == nil {
		t.Error("pcap mode without eventaddr or pcapfile should fail")
	}
}
