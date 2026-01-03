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
	"os"

	"github.com/cilium/ebpf"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// Probe represents the NSPR/NSS probe
type Probe struct {
	*base.BaseProbe
	config *Config

	// Handler for text output
	textHandler *handlers.TextHandler
}

// NewProbe creates a new NSPR probe
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("nspr"),
	}, nil
}

// Initialize initializes the probe with the given configuration
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	// Initialize base probe first
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to NSPR-specific config
	nsprConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for nspr probe", nil)
	}

	// Validate configuration
	if err := nsprConfig.Validate(); err != nil {
		return errors.NewConfigurationError("nspr config validation failed", err)
	}

	p.config = nsprConfig

	// Initialize text handler for stdout
	p.textHandler = handlers.NewTextHandler(os.Stdout)

	// Load eBPF bytecode
	bpfFileName := "bytecode/nspr_kern.o"
	_, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	// eBPF manager setup, event maps, and hooks will be implemented
	// Manager includes:
	// - Probes: PR_Send, PR_Recv hooks
	// - Event maps for TLS data capture

	p.Logger().Info().
		Str("nss_path", nsprConfig.NSSPath).
		Str("nspr_path", nsprConfig.NSPRPath).
		Msg("NSPR probe initialized")

	return nil
}

// Start starts the probe
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	if p.config == nil {
		return errors.NewProbeStartError("nspr", nil)
	}

	// Start eBPF event processing when implemented
	// - Start reading from perf buffers
	// - Process TLS data events and forward to appropriate handler
	// - Process master secret events (keylog mode)
	// - Process packet events (pcap mode)

	p.Logger().Info().Msg("NSPR probe started")
	return nil
}

// Stop stops the probe
func (p *Probe) Stop(ctx context.Context) error {
	// Stop eBPF event processing when implemented
	// - Stop reading from perf buffers
	// - Detach eBPF programs
	// - Clean up event maps

	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
// Return actual event maps when eBPF implementation is integrated
func (p *Probe) Events() []*ebpf.Map {
	return []*ebpf.Map{}
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	// Unload eBPF program and clean up resources when implemented
	return p.BaseProbe.Close()
}

// Decode implements EventDecoder interface for decoding eBPF events
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	// Determine event type based on map name
	// For now, default to TLSDataEvent
	event := &TLSDataEvent{}
	if err := event.Decode(data); err != nil {
		return nil, errors.NewEventDecodeError("nspr.TLSDataEvent", err)
	}

	// Handle event based on mode
	if p.textHandler != nil {
		// Write to text handler
		// p.textHandler.Handle(event)
	}

	return event, nil
}

// GetDecoder returns the event decoder (self-reference)
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	// Return an empty event for decoding
	return &TLSDataEvent{}, true
}
