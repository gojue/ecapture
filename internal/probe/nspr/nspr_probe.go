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
	"context"
	"fmt"
	"os"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe represents the NSPR/NSS probe
type Probe struct {
	config *Config

	// Handlers for different output modes
	textHandler   *handlers.TextHandler
	keylogHandler *handlers.KeylogHandler
	pcapHandler   *handlers.PcapHandler

	// Files for different modes
	keylogFile *os.File
	pcapFile   *os.File
}

// NewProbe creates a new NSPR probe
func NewProbe() (*Probe, error) {
	return &Probe{}, nil
}

// Initialize initializes the probe with the given configuration
func (p *Probe) Initialize(ctx context.Context, config interface{}, dispatcher interface{}) error {
	cfg, ok := config.(*Config)
	if !ok {
		return fmt.Errorf("invalid config type: expected *nspr.Config")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	p.config = cfg

	// Initialize handler based on capture mode
	switch cfg.CaptureMode {
	case "text":
		// For text mode, use stdout
		p.textHandler = handlers.NewTextHandler(os.Stdout)

	case "keylog":
		// For keylog mode, open keylog file
		file, err := os.OpenFile(cfg.KeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open keylog file: %w", err)
		}
		p.keylogFile = file
		p.keylogHandler = handlers.NewKeylogHandler(file)

	case "pcap":
		// For pcap mode, open pcap file
		file, err := os.OpenFile(cfg.PcapFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open pcap file: %w", err)
		}
		p.pcapFile = file
		p.pcapHandler = handlers.NewPcapHandler(file)

	default:
		return fmt.Errorf("invalid capture mode: %s", cfg.CaptureMode)
	}

	// TODO: Load eBPF program and attach hooks
	// - Load nspr_kern.o bytecode
	// - Attach to PR_Send/PR_Recv functions
	// - Set up event maps and perf buffers
	// - For keylog mode, also attach to master secret capture functions
	// - For pcap mode, also attach TC classifier for packet capture

	return nil
}

// Start starts the probe
func (p *Probe) Start(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("probe not initialized")
	}

	// TODO: Start eBPF event processing
	// - Start reading from perf buffers
	// - Process TLS data events and forward to appropriate handler
	// - Process master secret events (keylog mode)
	// - Process packet events (pcap mode)

	return nil
}

// Stop stops the probe
func (p *Probe) Stop() error {
	// TODO: Stop eBPF event processing
	// - Stop reading from perf buffers
	// - Detach eBPF programs
	// - Clean up event maps

	return nil
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	// Close keylog file if open
	if p.keylogFile != nil {
		if err := p.keylogFile.Close(); err != nil {
			return fmt.Errorf("failed to close keylog file: %w", err)
		}
		p.keylogFile = nil
	}

	// Close pcap file if open
	if p.pcapFile != nil {
		if err := p.pcapFile.Close(); err != nil {
			return fmt.Errorf("failed to close pcap file: %w", err)
		}
		p.pcapFile = nil
	}

	// TODO: Unload eBPF program and clean up resources

	return nil
}

// Name returns the probe name
func (p *Probe) Name() string {
	return "nspr"
}
