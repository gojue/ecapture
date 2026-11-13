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

	"github.com/gojue/ecapture/v2/internal/config"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
)

func TestConfigImplementsCaptureModeConfiguration(t *testing.T) {
	var cfg domain.CaptureModeConfiguration = &Config{CaptureMode: handlers.ModeKeylog}
	if got := cfg.GetCaptureMode(); got != handlers.ModeKeylog {
		t.Fatalf("GetCaptureMode() = %q, want %q", got, handlers.ModeKeylog)
	}
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
		{"raw default pcapng", "text", "", true, false},
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
		{name: "GnuTLS 3.8.9", version: "3.8.9", want: true},
		{name: "GnuTLS 3.8.10", version: "3.8.10", want: true},
		{name: "GnuTLS 3.8.11", version: "3.8.11", want: true},
		{name: "GnuTLS 3.8.12", version: "3.8.12", want: true},
		{name: "GnuTLS 3.8.13", version: "3.8.13", want: true},
		{
			name:    "Unsupported version",
			version: "3.5.0",
			want:    false,
		},
		{
			name:    "Unsupported newer patch",
			version: "3.8.14",
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
		{name: "GnuTLS 3.8.10", version: "3.8.10", want: "gnutls_3_8_10_kern.o"},
		{name: "GnuTLS 3.8.11", version: "3.8.11", want: "gnutls_3_8_11_kern.o"},
		{name: "GnuTLS 3.8.12", version: "3.8.12", want: "gnutls_3_8_11_kern.o"},
		{name: "GnuTLS 3.8.13", version: "3.8.13", want: "gnutls_3_8_11_kern.o"},
		{name: "Unsupported future version", version: "3.8.14", want: ""},
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
	cfg.Ifname = "lo"

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

	// Explicit invalid interfaces must not be silently replaced.
	cfg.Ifname = "nonexistent-interface-12345"
	err = cfg.validateCaptureMode()
	if err == nil {
		t.Error("validateCaptureMode() should fail for an explicit nonexistent interface")
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

func TestConfigDefaultTextSource(t *testing.T) {
	for _, test := range []struct {
		name, mode, source, ifname, want string
		wantErr                          bool
	}{
		{"default text", "text", "", "lo", "pcapng", false},
		{"empty mode", "", "", "lo", "pcapng", false},
		{"normalized default", "TEXT", "  ", "lo", "pcapng", false},
		{"explicit missing interface", "text", "", "nonexistent-interface-12345", "pcapng", true},
		{"explicit hook without interface", "text", "hook", "", "hook", false},
		{"normalized hook", "text", " HOOK ", "", "hook", false},
		{"keylog default", "keylog", "", "", "hook", false},
		{"key alias default", "key", "", "", "hook", false},
		{"pcapng default", "pcapng", "", "lo", "hook", false},
		{"pcap alias default", "pcap", "", "lo", "hook", false},
		{"explicit pcapng requires text", "keylog", "pcapng", "", "pcapng", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.CaptureMode, cfg.TextSource, cfg.Ifname = test.mode, test.source, test.ifname
			cfg.EventCollectorAddr = "stdout"
			for attempt := 0; attempt < 2; attempt++ {
				err := cfg.validateCaptureMode()
				if (err != nil) != test.wantErr {
					t.Fatalf("validation %d error = %v, wantErr %v", attempt, err, test.wantErr)
				}
				if cfg.TextSource != test.want {
					t.Fatalf("text source = %q, want %q", cfg.TextSource, test.want)
				}
			}
		})
	}
}
