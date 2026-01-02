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
	"fmt"
	"os"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe represents the GoTLS probe
type Probe struct {
	config *Config

	// Handlers for different output modes
	textHandler   *handlers.TextHandler
	keylogHandler *handlers.KeylogHandler
	pcapHandler   *handlers.PcapHandler

	// File handles
	keylogFile *os.File
	pcapFile   *os.File
}

// NewProbe creates a new GoTLS probe
func NewProbe() (*Probe, error) {
	return &Probe{}, nil
}

// Initialize initializes the probe with the given configuration
func (p *Probe) Initialize(ctx context.Context, config interface{}, dispatcher interface{}) error {
	cfg, ok := config.(*Config)
	if !ok {
		return fmt.Errorf("invalid config type: expected *gotls.Config")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	p.config = cfg

	// Initialize handler based on capture mode
	switch cfg.CaptureMode {
	case "text":
		// Text mode: output to stdout
		p.textHandler = handlers.NewTextHandler(os.Stdout)

	case "keylog":
		// Keylog mode: open keylog file
		file, err := os.OpenFile(cfg.KeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open keylog file: %w", err)
		}
		p.keylogFile = file
		p.keylogHandler = handlers.NewKeylogHandler(file)

	case "pcap":
		// Pcap mode: open pcap file
		file, err := os.OpenFile(cfg.PcapFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open pcap file: %w", err)
		}
		p.pcapFile = file
		p.pcapHandler = handlers.NewPcapHandler(file)

		// TODO: Write pcap file header once PcapHandler.WriteHeader() is implemented
	}

	// TODO: Load eBPF program
	// TODO: Attach crypto/tls hooks
	// TODO: Set up perf event arrays

	return nil
}

// Start starts the probe
func (p *Probe) Start(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("probe not initialized")
	}

	// TODO: Start event polling loop
	// TODO: Read events from perf event array
	// TODO: Dispatch events to appropriate handlers

	return nil
}

// Stop stops the probe
func (p *Probe) Stop(ctx context.Context) error {
	// TODO: Stop event polling
	// TODO: Detach eBPF programs

	return nil
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	// Close file handles
	if p.keylogFile != nil {
		if err := p.keylogFile.Close(); err != nil {
			return fmt.Errorf("failed to close keylog file: %w", err)
		}
		p.keylogFile = nil
	}

	if p.pcapFile != nil {
		if err := p.pcapFile.Close(); err != nil {
			return fmt.Errorf("failed to close pcap file: %w", err)
		}
		p.pcapFile = nil
	}

	// TODO: Clean up eBPF resources

	return nil
}

// handleTLSDataEvent handles a TLS data event
func (p *Probe) handleTLSDataEvent(event *TLSDataEvent) error {
	if p.textHandler != nil {
		// Text mode: format and write to stdout
		// TODO: Use textHandler.Handle() once the interface is implemented
		direction := ">>>"
		if event.IsRead() {
			direction = "<<<"
		}

		_, err := fmt.Fprintf(os.Stdout, "[%s] [PID:%d] %s %s\n",
			event.GetTimestamp().Format("2006-01-02 15:04:05.000"),
			event.GetPid(),
			direction,
			string(event.GetData()))

		return err
	}

	// TODO: Handle keylog and pcap modes when we have actual TLS connection info

	return nil
}

// handleMasterSecretEvent handles a master secret event
func (p *Probe) handleMasterSecretEvent(event *MasterSecretEvent) error {
	if p.keylogHandler != nil {
		// Keylog mode: write to keylog file
		// TODO: Call p.keylogHandler.Handle(event) once MasterSecretEvent implements domain.Event
		_ = event // Suppress unused variable warning
	}

	return nil
}
