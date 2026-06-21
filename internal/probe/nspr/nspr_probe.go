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
	"bytes"
	"context"
	"fmt"
	"io"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

// Probe represents the NSPR/NSS probe
type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
	output           io.Writer
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
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	// Initialize base probe first
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
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

	// Load eBPF bytecode with correct filename (core vs noncore)
	bpfFileName := p.BaseProbe.GetBPFName("bytecode/nspr_kern.o")
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading eBPF bytecode")

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	// Setup eBPF manager with probes and maps
	if err := p.setupManager(); err != nil {
		return err
	}

	// Initialize eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("nspr manager init", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("nspr manager start", err)
	}

	// Retrieve eBPF maps and associate with decoders
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	// Start event readers for all configured maps
	for em, decoder := range p.eventFuncMaps {
		if err := p.StartPerfEventReader(em, decoder); err != nil {
			return err
		}
	}

	p.Logger().Info().Msg("NSPR probe started successfully")
	return nil
}

// retrieveEventMaps retrieves eBPF maps from the manager and creates eventFuncMaps.
// The decoder mapping by name (mapNameToDecoder) is already configured in setupManager().
func (p *Probe) retrieveEventMaps() error {
	for mapName, decoder := range p.mapNameToDecoder {
		em, found, err := p.bpfManager.GetMap(mapName)
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess, fmt.Sprintf("failed to get %s map", mapName), err)
		}
		if !found {
			p.Logger().Warn().Str("map", mapName).Msg("Map not found but was configured")
			continue
		}

		p.eventMaps = append(p.eventMaps, em)
		p.eventFuncMaps[em] = decoder
	}

	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Msg("Event maps retrieved and decoders mapped")

	return nil
}

// Stop stops the probe
func (p *Probe) Stop(ctx context.Context) error {
	// Stop event readers are handled by BaseProbe
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// Close closes the probe and releases resources
func (p *Probe) Close() error {
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
		}
	}
	return p.BaseProbe.Close()
}

// SetOutput sets the output writer for the probe (for testing purposes).
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// setupManager configures the eBPF manager with uprobes/uretprobes for PR_Write/PR_Read.
func (p *Probe) setupManager() error {
	nsprPath := p.config.NSPRPath
	if nsprPath == "" {
		return errors.NewConfigurationError("nspr_path is required for NSPR probe", nil)
	}

	p.Logger().Info().
		Str("nspr_path", nsprPath).
		Str("nss_path", p.config.NSSPath).
		Msg("Setting up eBPF probes for NSPR")

	// Configure probes: uprobe/uretprobe pairs for PR_Write and PR_Read
	probes := []*manager.Probe{
		{
			Section:          "uprobe/PR_Write",
			EbpfFuncName:     "probe_entry_SSL_write",
			AttachToFuncName: "PR_Write",
			BinaryPath:       nsprPath,
		},
		{
			Section:          "uretprobe/PR_Write",
			EbpfFuncName:     "probe_ret_SSL_write",
			AttachToFuncName: "PR_Write",
			BinaryPath:       nsprPath,
		},
		{
			Section:          "uprobe/PR_Read",
			EbpfFuncName:     "probe_entry_SSL_read",
			AttachToFuncName: "PR_Read",
			BinaryPath:       nsprPath,
		},
		{
			Section:          "uretprobe/PR_Read",
			EbpfFuncName:     "probe_ret_SSL_read",
			AttachToFuncName: "PR_Read",
			BinaryPath:       nsprPath,
		},
	}

	// Configure maps matching those defined in kern/nspr_kern.c
	maps := []*manager.Map{
		{Name: "nspr_events"},
		{Name: "active_ssl_read_args_map"},
		{Name: "active_ssl_write_args_map"},
		{Name: "data_buffer_heap"},
	}

	// Configure decoder for nspr_events map
	p.mapNameToDecoder["nspr_events"] = &nsprEventDecoder{probe: p}

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}

	return nil
}

// getManagerOptions returns eBPF manager options with constant editors for filtering.
func (p *Probe) getManagerOptions() manager.Options {
	opts := manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSizeStart: 2097152,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	// Add constant editors if kernel supports global variables
	if p.config.EnableGlobalVar() {
		kv, _ := kernel.HostVersion()
		kernelLess52 := uint64(0)
		if kv < kernel.VersionCode(5, 2, 0) {
			kernelLess52 = 1
		}

		opts.ConstantEditors = []manager.ConstantEditor{
			{Name: "target_pid", Value: p.config.GetPid()},
			{Name: "target_uid", Value: p.config.GetUid()},
			{Name: "less52", Value: kernelLess52},
			{Name: "target_cgroup_id", Value: uint64(0)},
		}
	} else {
		if p.config.GetPid() != 0 {
			p.Logger().Warn().Uint64("pid", p.config.GetPid()).
				Msg("PID filter is not supported on kernel < 5.2, --pid filter will be ignored")
		}
		if p.config.GetUid() != 0 {
			p.Logger().Warn().Uint64("uid", p.config.GetUid()).
				Msg("UID filter is not supported on kernel < 5.2, --uid filter will be ignored")
		}
	}

	return opts
}

// nsprEventDecoder implements domain.EventDecoder for NSPR TLS data events
type nsprEventDecoder struct {
	probe *Probe
}

func (d *nsprEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &TLSDataEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *nsprEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &TLSDataEvent{}, true
}
