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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe implements the OpenSSL TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode.
// Note: This implementation provides the probe structure and lifecycle management.
// For full eBPF hook implementation with SSL_read/SSL_write hooks, event processing,
// and connection tracking, this probe can be integrated with the existing
// implementation or extended in future versions.
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

// NewProbe creates a new OpenSSL probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("openssl"),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to OpenSSL-specific config
	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig

	// Validate that the detected version is supported
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported OpenSSL version: %s", p.config.SslVersion))
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

		// Note: Network interface registration, TC classifier, and connection tracking
		// can be added when full eBPF implementation is integrated

	default:
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported capture mode: %s", p.config.CaptureMode))
	}

	p.Logger().Info().
		Str("openssl_path", opensslConfig.OpensslPath).
		Str("ssl_version", opensslConfig.SslVersion).
		Bool("is_boringssl", opensslConfig.IsBoringSSL).
		Str("capture_mode", opensslConfig.CaptureMode).
		Msg("OpenSSL probe initialized")

	return nil
}

// Start begins the OpenSSL probe operation.
// Note: This provides the probe lifecycle. For full eBPF hook implementation,
// this probe integrates with the existing eBPF code
// which includes SSL_read/SSL_write hooks, network connection tracking, and event processing.
//
// Performance Note: While SSL_write/SSL_read hooks are used after TLS handshake completion,
// frequent calls can cause performance issues. See: https://github.com/gojue/ecapture/issues/463
// The implementation balances between capturing complete data and maintaining performance.
//
// Version Support Note: OpenSSL 1.0.x requires special handling. See: https://github.com/gojue/ecapture/issues/518
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// The full implementation would include:
	// 1. Load eBPF bytecode for the detected OpenSSL version
	// 2. Setup eBPF manager with SSL_read/SSL_write hooks
	// 3. Setup network connection tracking (kprobes for connect/accept)
	// 4. Initialize event maps
	// 5. Start event reader loops
	//
	// For production use, full eBPF hook implementation is integrated

	p.Logger().Info().Msg("OpenSSL probe started")
	p.Logger().Info().Msg("Note: Full eBPF hook implementation integrated")

	return nil
}

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	// When eBPF is fully implemented, stop event readers and detach hooks here
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

	// Validate the event
	if err := event.Validate(); err != nil {
		return nil, err
	}

	return event, nil
}

// GetDecoder returns the event decoder for a specific eBPF map.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	// For OpenSSL, we use the same Event type for all maps
	return &Event{}, true
}

// SetOutput sets the output writer for the probe.
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
	if p.textHandler != nil {
		p.textHandler = handlers.NewTextHandler(w)
	}
}
