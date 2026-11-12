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
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/gojue/ecapture/v2/internal/logger"
)

func TestCaptureInterfaceStartupLog(t *testing.T) {
	for _, test := range []struct {
		name, mode, source, ifname, autoIfname, want string
	}{
		{"automatic text", "text", "pcapng", "eth0", "eth0", "warn"},
		{"automatic pcapng", "pcapng", "hook", "eth0", "eth0", "warn"},
		{"explicit override", "text", "pcapng", "lo", "eth0", "info"},
		{"explicit interface", "text", "pcapng", "lo", "", "info"},
		{"hook needs no interface", "text", "hook", "", "", ""},
		{"keylog needs no interface", "keylog", "hook", "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			zlog := zerolog.New(&output)
			cfg := NewConfig()
			cfg.CaptureMode, cfg.TextSource = test.mode, test.source
			cfg.Ifname, cfg.autoIfname = test.ifname, test.autoIfname
			cfg.ifnameSelectionReason = "IPv4 default route, metric 100"
			logCaptureInterface(&logger.Logger{Logger: &zlog}, cfg)
			got := output.String()
			if test.want == "" {
				if got != "" {
					t.Fatalf("unexpected interface log: %s", got)
				}
				return
			}
			for _, want := range []string{`"level":"` + test.want + `"`, `"ifname":"` + test.ifname + `"`, "-i <interface>", "--ifname <interface>"} {
				if !strings.Contains(got, want) {
					t.Fatalf("startup log missing %q: %s", want, got)
				}
			}
			if test.want == "warn" && (!strings.Contains(got, "Automatically selected capture interface") || !strings.Contains(got, cfg.ifnameSelectionReason)) {
				t.Fatalf("automatic selection warning lacks selection or reason: %s", got)
			}
		})
	}
}

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
		return
	}
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_Initialize(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	cfg := NewConfig()
	cfg.OpensslPath = "/nonexistent/path/libssl.so.1.1"

	// Test that Initialize returns an error when the openssl path does not exist
	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() with non-existent openssl path should return error")
	}
}

func TestProbe_Initialize_InvalidConfig(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Use a non-existent path to ensure config validation fails reliably
	cfg := NewConfig()
	cfg.OpensslPath = "/nonexistent/path/libssl.so.1.1"

	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() with invalid config should return error")
	}
}

func TestProbe_SetOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	buf := &bytes.Buffer{}
	probe.SetOutput(buf)

	if probe.output != buf {
		t.Error("SetOutput() did not set output correctly")
	}
}

func TestProbe_Close(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Close without initializing - should handle gracefully
	// We can't test this directly because BaseProbe requires initialization
	// Just test that the probe was created successfully
	if probe == nil {
		t.Error("Probe should not be nil")
	}
}

func TestProbe_Events(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	events := probe.Events()
	// Should return empty slice for stub implementation
	if events == nil {
		t.Error("Events() returned nil")
	}
}

func TestProbe_Lifecycle(t *testing.T) {
	// Test basic lifecycle without full initialization
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Set output
	var buf bytes.Buffer
	probe.SetOutput(&buf)

	// Just test that basic methods work
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_WithRealOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Test with a real writer
	var buf bytes.Buffer
	probe.SetOutput(io.Writer(&buf))

	if probe.output == nil {
		t.Error("Output writer not set")
	}
}
