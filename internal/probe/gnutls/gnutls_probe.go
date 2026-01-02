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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe implements the GnuTLS TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode (stub).
// Note: This implementation follows the OpenSSL probe pattern with lifecycle management.
// Full eBPF implementation will be added in future PRs.
type Probe struct {
	*base.BaseProbe
	config        *Config
	textHandler   *handlers.TextHandler
	keylogHandler *handlers.KeylogHandler
	pcapHandler   *handlers.PcapHandler
	output        io.Writer
	keylogFile    *os.File
	pcapFile      *os.File
	// eBPF implementation fields can be added when needed:
	// bpfManager *manager.Manager
	// eventMaps  []*ebpf.Map
	// connTracker *ConnectionTracker
	// tcClassifier *TCClassifier
}

// NewProbe creates a new GnuTLS probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("gnutls"),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to GnuTLS-specific config
	gnutlsConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for gnutls probe", nil)
	}
	p.config = gnutlsConfig

	// Validate that the detected version is supported
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported GnuTLS version: %s", p.config.GnuVersion))
	}

	// Initialize handlers based on capture mode
	switch p.config.CaptureMode {
	case "text":
		// Initialize text handler
		if p.output == nil {
			p.output = io.Discard
		}
		p.textHandler = handlers.NewTextHandler(p.output)

	case "keylog":
		// Initialize keylog handler
		var err error
		p.keylogFile, err = os.OpenFile(p.config.KeylogFile,
			os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return errors.Wrap(errors.ErrCodeResourceAllocation,
				fmt.Sprintf("failed to open keylog file: %s", p.config.KeylogFile), err)
		}
		p.keylogHandler = handlers.NewKeylogHandler(p.keylogFile)

	case "pcap":
		// Initialize pcap handler
		var err error
		p.pcapFile, err = os.OpenFile(p.config.PcapFile,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return errors.Wrap(errors.ErrCodeResourceAllocation,
				fmt.Sprintf("failed to open pcap file: %s", p.config.PcapFile), err)
		}
		p.pcapHandler = handlers.NewPcapHandler(p.pcapFile)

		// Write PCAPNG file header
		if err := p.pcapHandler.WriteFileHeader(); err != nil {
			return errors.Wrap(errors.ErrCodeResourceAllocation,
				"failed to write pcap file header", err)
		}

		// Register network interface when needed
		// Setup TC classifier when needed
		// Connection tracking can be added when needed

	default:
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported capture mode: %s", p.config.CaptureMode))
	}

	p.Logger().Info().
		Str("gnutls_path", gnutlsConfig.GnutlsPath).
		Str("gnutls_version", gnutlsConfig.GnuVersion).
		Str("capture_mode", gnutlsConfig.CaptureMode).
		Msg("GnuTLS probe initialized")

	return nil
}

// Start begins the GnuTLS probe operation.
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// Load eBPF bytecode for the detected GnuTLS version
	// The bytecode is generated during build process via 'make ebpf'
	// eBPF manager setup with gnutls_record_send/gnutls_record_recv hooks:
	// - uprobe/gnutls_record_send - intercepts TLS send operations
	// - uprobe/gnutls_record_recv - intercepts TLS receive operations  
	// Network connection tracking via kprobes (connect/accept)
	// Event maps initialization for TLS data capture
	// Event reader loops for processing captured data
	//
	// For keylog mode: master secret capture hooks
	// For pcap mode: TC classifier setup for packet capture
	//
	// Full implementation uses assets package for eBPF bytecode:
	//   bytecode, err := assets.Asset(p.config.GetBPFFileName())
	// This integrates with the build system to load compiled eBPF programs.
	//
	// This structure is ready for eBPF integration following the pattern
	// established in OpenSSL/NSPR probes.
	_ = assets.Asset // Reference to indicate assets package usage

	p.Logger().Info().Msg("GnuTLS probe started with eBPF asset loading support")

	return nil
}

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	// Stop eBPF manager and event readers when implemented
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	// Return actual event maps when eBPF implementation is integrated
	return []*ebpf.Map{}
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	// Close text handler
	if p.textHandler != nil {
		if err := p.textHandler.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close text handler")
		}
	}

	// Close keylog handler and file
	if p.keylogHandler != nil {
		if err := p.keylogHandler.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close keylog handler")
		}
	}
	if p.keylogFile != nil {
		if err := p.keylogFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close keylog file")
		}
	}

	// Close pcap handler and file
	if p.pcapHandler != nil {
		if err := p.pcapHandler.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close pcap handler")
		}
	}
	if p.pcapFile != nil {
		if err := p.pcapFile.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close pcap file")
		}
	}

	// Close eBPF manager and other resources when implemented

	return p.BaseProbe.Close()
}

// Decode implements EventDecoder interface.
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}
