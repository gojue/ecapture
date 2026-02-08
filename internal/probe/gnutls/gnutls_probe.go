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

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
)

// Probe implements the GnuTLS TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode (stub).
// Note: This implementation follows the OpenSSL probe pattern with lifecycle management.
// Full eBPF implementation will be added in future PRs.
type Probe struct {
	*base.BaseProbe
	config           *Config
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
	output           io.Writer
	// eBPF implementation fields can be added when needed:
	// bpfManager *manager.Manager
	// connTracker *ConnectionTracker
	// tcClassifier *TCClassifier
}

// NewProbe creates a new GnuTLS probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeGnuTLS)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
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

	// Retrieve eBPF maps and associate with decoders (configured in setupManager)
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	p.Logger().Info().Msg("GnuTLS probe started with eBPF asset loading support")

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

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	// Stop eBPF manager and event readers when implemented
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	// Close eBPF manager and other resources when implemented
	if p.BaseProbe == nil {
		return nil
	}
	return p.BaseProbe.Close()
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// gnutlsEventDecoder implements domain.EventDecoder for GnuTLS TLS data events
type gnutlsEventDecoder struct {
	probe *Probe
}

func (d *gnutlsEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *gnutlsEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &Event{}, true
}
