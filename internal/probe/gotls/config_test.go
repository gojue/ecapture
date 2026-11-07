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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	if cfg.CaptureMode != handlers.ModeText {
		t.Errorf("expected default CaptureMode='text', got '%s'", cfg.CaptureMode)
		return
	}

	if cfg.Pid != 0 {
		t.Errorf("expected default Pid=0, got %d", cfg.Pid)
		return
	}
}

func TestConfig_Validate_GoVersion(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS config validation")
}

func TestConfigTextRaw(t *testing.T) {
	for _, test := range []struct {
		name, mode, source string
		raw, wantErr       bool
	}{
		{"default parsed hook", "text", "hook", false, false},
		{"parsed pcapng", "text", "pcapng", false, false},
		{"raw pcapng", "text", "pcapng", true, false},
		{"normalized raw pcapng", "TEXT", " PCAPNG ", true, false},
		{"default text mode", "", "pcapng", true, false},
		{"reject hook", "text", "hook", true, true},
		{"reject default hook", "text", "", true, true},
		{"reject keylog", "keylog", "hook", true, true},
		{"reject pcapng", "pcapng", "hook", true, true},
		{"reject nontext source", "keylog", "pcapng", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.CaptureMode, cfg.TextSource, cfg.TextRaw = test.mode, test.source, test.raw
			cfg.Ifname = "lo"
			for attempt := 0; attempt < 2; attempt++ {
				err := cfg.validateCaptureMode()
				if (err != nil) != test.wantErr {
					t.Fatalf("validation %d error = %v, wantErr %v", attempt, err, test.wantErr)
				}
				if cfg.TextRaw != test.raw {
					t.Fatal("validation changed text_raw")
				}
			}
		})
	}
}

func TestConfig_Validate_TextMode(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS config validation")
}

func TestConfig_Validate_KeylogMode(t *testing.T) {
	t.Skip("requires ElfPath to be set for GoTLS config validation")
}

func TestConfig_Validate_KeylogMode_MissingFile(t *testing.T) {
	cfg := NewConfig()
	cfg.CaptureMode = handlers.ModeKeylog
	cfg.KeylogFile = ""

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when KeylogFile is empty")
	}
}

func TestConfig_Validate_InvalidCaptureMode(t *testing.T) {
	cfg := NewConfig()
	cfg.CaptureMode = "invalid"

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for invalid capture mode")
	}
}

func TestConfig_GetBPFFileName(t *testing.T) {
	tests := []struct {
		name       string
		goVersion  string
		wantPrefix string
	}{
		{
			name:       "current version",
			goVersion:  runtime.Version(),
			wantPrefix: "gotls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.GoVersion = tt.goVersion

			fileName := cfg.GetBPFFileName()
			if fileName == "" {
				t.Error("GetBPFFileName() returned empty string")
			}

			if fileName != "gotls_kern.o" {
				t.Errorf("expected 'gotls_kern.o', got '%s'", fileName)
				return
			}
		})
	}
}

func TestDetectGoVersion(t *testing.T) {
	version := detectGoVersion()
	if version == "" {
		t.Error("detectGoVersion() returned empty string")
	}

	expectedVersion := runtime.Version()
	if version != expectedVersion {
		t.Errorf("expected version='%s', got '%s'", expectedVersion, version)
		return
	}
}

func TestIsGoVersionSupported(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		supported bool
	}{
		{"Go 1.16", "go1.16.0", false},
		{"Go 1.17", "go1.17.0", true},
		{"Go 1.18", "go1.18.0", true},
		{"Go 1.19", "go1.19.0", true},
		{"Go 1.20", "go1.20.0", true},
		{"Go 1.21", "go1.21.0", true},
		{"Go 2.0", "go2.0.0", true},
		{"Invalid", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supported := isGoVersionSupported(tt.version)
			if supported != tt.supported {
				t.Errorf("isGoVersionSupported(%s) = %v, want %v", tt.version, supported, tt.supported)
			}
		})
	}
}

func TestConfig_ValidateNetworkInterface(t *testing.T) {
	// This test only runs if we can find a valid network interface
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Skip("Cannot read /sys/class/net, skipping test")
	}

	if len(ifaces) == 0 {
		t.Skip("No network interfaces found, skipping test")
	}

	var ifname string
	for _, entry := range ifaces {
		iface, lookupErr := net.InterfaceByName(entry.Name())
		if lookupErr != nil || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr == nil && len(addrs) > 0 {
			ifname = entry.Name()
			break
		}
	}
	if ifname == "" {
		t.Skip("No active network interface with an address found")
	}

	cfg := NewConfig()
	cfg.CaptureMode = handlers.ModePcap
	cfg.PcapFile = filepath.Join(t.TempDir(), "capture.pcapng")
	cfg.Ifname = ifname

	if err := cfg.validateNetworkInterface(); err != nil {
		t.Errorf("validateNetworkInterface() failed for interface %s: %v", ifname, err)
	}
}

func TestConfig_CheckTCSupport(t *testing.T) {
	// This test only runs on Linux with networking support
	if _, err := os.Stat("/proc/sys/net/core"); os.IsNotExist(err) {
		t.Skip("/proc/sys/net/core not found, skipping test")
	}

	// Get a valid interface
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(ifaces) == 0 {
		t.Skip("Cannot find network interfaces, skipping test")
	}

	ifname := ifaces[0].Name()

	cfg := NewConfig()
	cfg.Ifname = ifname

	if err := cfg.checkTCSupport(); err != nil {
		t.Errorf("checkTCSupport() failed: %v", err)
	}
}

func TestConfigDecryptOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		options config.DecryptConfig
		wantErr bool
	}{
		{"DNS", config.DecryptConfig{TextProtocol: "dot"}, false},
		{"HTTP events with gzip", config.DecryptConfig{TextHTTPEvents: true, TextMaxDecodedBody: 1024}, false},
		{"STARTTLS raw", config.DecryptConfig{TextTLSUpgrade: "smtp", TextRaw: true}, false},
		{"DTLS", config.DecryptConfig{TextUDPProtocol: "dtls"}, false},
		{"unknown parser", config.DecryptConfig{TextProtocol: "unknown"}, true},
		{"raw HTTP events conflict", config.DecryptConfig{TextRaw: true, TextHTTPEvents: true}, true},
		{"raw parser conflict", config.DecryptConfig{TextRaw: true, TextProtocol: "redis"}, true},
		{"gzip requires events", config.DecryptConfig{TextMaxDecodedBody: 1024}, true},
		{"negative gzip limit", config.DecryptConfig{TextHTTPEvents: true, TextMaxDecodedBody: -1}, true},
		{"DTLS parser conflict", config.DecryptConfig{TextUDPProtocol: "dtls", TextProtocol: "doq"}, true},
		{"QUIC upgrade conflict", config.DecryptConfig{TextProtocol: "doq", TextTLSUpgrade: "smtp"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.CaptureMode, cfg.TextSource, cfg.Ifname = "text", "pcapng", "lo"
			cfg.DecryptConfig = test.options
			for attempt := 0; attempt < 2; attempt++ {
				err := cfg.validateCaptureMode()
				if (err != nil) != test.wantErr {
					t.Fatalf("validation %d error = %v, wantErr %v", attempt, err, test.wantErr)
				}
				if cfg.DecryptConfig != test.options {
					t.Fatal("validation changed decryption options")
				}
			}
			cfg.TextSource = "hook"
			if err := cfg.validateCaptureMode(); err == nil {
				t.Fatal("decryption options accepted without pcapng text source")
			}
		})
	}
}
