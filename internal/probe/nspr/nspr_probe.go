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

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
)

// Probe represents the NSPR/NSS probe
type Probe struct {
	*base.BaseProbe
	config           *Config
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
}

// NewProbe creates a new NSPR probe
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeNSPR)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
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

	// Retrieve eBPF maps and associate with decoders (configured in setupManager)
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	// Start eBPF event processing when implemented
	// - Start reading from perf buffers
	// - Process TLS data events and forward to appropriate handler
	// - Process master secret events (keylog mode)
	// - Process packet events (pcap mode)

	p.Logger().Info().Msg("NSPR probe started")
	return nil
}

// retrieveEventMaps retrieves eBPF maps from the manager and creates eventFuncMaps.
// The decoder mapping by name (mapNameToDecoder) is already configured in setupManager().
// This will be populated when eBPF implementation is complete.
func (p *Probe) retrieveEventMaps() error {
	// TODO: When eBPF is implemented, retrieve actual maps
	// for mapName, decoder := range p.mapNameToDecoder {
	//     em, found, err := p.bpfManager.GetMap(mapName)
	//     if found {
	//         p.eventMaps = append(p.eventMaps, em)
	//         p.eventFuncMaps[em] = decoder
	//     }
	// }

	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Msg("Event maps retrieved and decoders mapped")

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
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	// Unload eBPF program and clean up resources when implemented
	return p.BaseProbe.Close()
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// nsprEventDecoder implements domain.EventDecoder for NSPR TLS data events
type nsprEventDecoder struct {
	probe *Probe
}

func (d *nsprEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &TLSDataEvent{}
	if err := event.Decode(data); err != nil {
		return nil, errors.NewEventDecodeError("nspr.TLSDataEvent", err)
	}

	// Event will be handled by dispatcher
	return event, nil
}

func (d *nsprEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &TLSDataEvent{}, true
}
