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

package postgres

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/internal/factory"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

// Probe implements PostgreSQL query monitoring using uprobe
type Probe struct {
	*base.BaseProbe
	config     *Config
	bpfManager *manager.Manager
}

// NewProbe creates a new PostgreSQL probe instance
func NewProbe() *Probe {
	return &Probe{
		BaseProbe: base.NewBaseProbe(string(factory.ProbeTypePostgres)),
	}
}

// Initialize initializes the PostgreSQL probe with the provided configuration
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	// Type assert configuration
	config, ok := cfg.(*Config)
	if !ok {
		return errors.New(errors.ErrCodeProbeInit, "invalid configuration type for postgres probe")
	}
	p.config = config

	// Initialize base probe
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return errors.Wrap(errors.ErrCodeProbeInit, "failed to initialize base probe", err)
	}

	return nil
}

// Start starts the PostgreSQL probe
func (p *Probe) Start(ctx context.Context) error {
	// Start base probe
	if err := p.BaseProbe.Start(ctx); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to start base probe", err)
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to setup eBPF manager", err)
	}

	// Load eBPF bytecode
	bytecode, err := p.loadBytecode()
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to load bytecode", err)
	}

	// Initialize eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(bytecode), p.getManagerOptions()); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to initialize eBPF manager", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to start eBPF manager", err)
	}

	// Get events map
	eventsMap, found, err := p.bpfManager.GetMap("events")
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to get events map", err)
	}
	if !found {
		return errors.New(errors.ErrCodeProbeStart, "events map not found in eBPF program")
	}

	// Start event reader
	decoder := &postgresEventDecoder{eventsMap: eventsMap}
	if err := p.StartPerfEventReader(eventsMap, decoder); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "failed to start perf event reader", err)
	}

	return nil
}

// Stop stops the PostgreSQL probe
func (p *Probe) Stop(ctx context.Context) error {
	// Stop base probe first
	if err := p.BaseProbe.Stop(ctx); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStop, "failed to stop base probe", err)
	}

	return nil
}

// Close closes the PostgreSQL probe and releases resources
func (p *Probe) Close() error {
	// Stop eBPF manager if running
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			return errors.Wrap(errors.ErrCodeProbeClose, "failed to stop eBPF manager", err)
		}
	}

	// Close base probe
	if err := p.BaseProbe.Close(); err != nil {
		return errors.Wrap(errors.ErrCodeProbeClose, "failed to close base probe", err)
	}

	return nil
}

// setupManager sets up the eBPF manager with PostgreSQL-specific configuration
func (p *Probe) setupManager() error {
	// Create uprobe for exec_simple_query
	probes := []*manager.Probe{
		{
			Section:          "uprobe/exec_simple_query",
			EbpfFuncName:     "postgres_query",
			AttachToFuncName: p.config.GetFuncName(),
			BinaryPath:       p.config.GetPostgresPath(),
		},
	}

	// Create eBPF manager
	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	p.Logger().Info().
		Str("binary", p.config.GetPostgresPath()).
		Str("function", p.config.GetFuncName()).
		Msg("PostgreSQL probe manager configured")

	return nil
}

// loadBytecode loads the eBPF bytecode for the PostgreSQL probe
func (p *Probe) loadBytecode() ([]byte, error) {
	// Determine which bytecode file to use based on BTF support
	var bytecodeFile string
	if p.config.GetBTF() == 1 { // BTFModeCore
		bytecodeFile = "bytecode/postgres_kern_core.o"
	} else {
		bytecodeFile = "bytecode/postgres_kern.o"
	}

	// Load bytecode from assets
	bytecode, err := assets.Asset(bytecodeFile)
	if err != nil {
		p.Logger().Error().Err(err).Str("file", bytecodeFile).Msg("Failed to load PostgreSQL eBPF bytecode")
		return nil, fmt.Errorf("failed to load bytecode file %s: %w", bytecodeFile, err)
	}

	p.Logger().Info().Str("file", bytecodeFile).Msg("Loaded PostgreSQL eBPF bytecode")
	return bytecode, nil
}

// getManagerOptions returns the eBPF manager options
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
		}
	}

	return opts
}

// postgresEventDecoder implements EventDecoder for PostgreSQL events
type postgresEventDecoder struct {
	eventsMap *ebpf.Map
}

// Decode decodes a raw event from eBPF into a domain.Event
func (d *postgresEventDecoder) Decode(em *ebpf.Map, rawData []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(rawData); err != nil {
		return nil, errors.Wrap(errors.ErrCodeEventDecode, "failed to decode PostgreSQL event", err)
	}
	return event, nil
}

// GetDecoder returns the event decoder for a specific eBPF map
func (d *postgresEventDecoder) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	if em == d.eventsMap {
		return &Event{}, true
	}
	return nil, false
}
