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

package zsh

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

// Probe implements the Zsh probe using the new architecture.
type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
}

// NewProbe creates a new Zsh probe instance.
func NewProbe() *Probe {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeZsh)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
		eventMaps:        make([]*ebpf.Map, 0, 1),
	}
}

// Initialize initializes the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	config, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for zsh probe", nil)
	}

	if err := config.Validate(); err != nil {
		return err
	}

	p.config = config

	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
		return err
	}

	p.Logger().Info().
		Str("zsh_path", config.Zshpath).
		Str("func", config.ReadlineFuncName).
		Msg("Zsh probe initialized")

	return nil
}

// Start starts the probe and begins capturing events.
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// Load eBPF bytecode
	bytecode, err := p.loadBytecode()
	if err != nil {
		return errors.NewProbeStartError("zsh", err)
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return errors.NewProbeStartError("zsh", err)
	}

	// Initialize manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(bytecode), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("zsh manager init", err)
	}

	// Start manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("zsh manager start", err)
	}

	// Retrieve eBPF maps and associate with decoders (configured in setupManager)
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	// Start event readers for all configured maps
	for em, decoder := range p.eventFuncMaps {
		if err := p.StartPerfEventReader(em, decoder); err != nil {
			return err
		}
	}

	p.Logger().Info().Msg("Zsh probe started successfully")
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

// Close stops the probe and releases resources.
func (p *Probe) Close() error {
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop bpf manager")
		}
	}
	return p.BaseProbe.Close()
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// loadBytecode loads the eBPF bytecode for the probe.
func (p *Probe) loadBytecode() ([]byte, error) {
	bpfFileName := p.getBPFName("bytecode/zsh_kern.o")
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading BPF bytecode")

	bytecode, err := assets.Asset(bpfFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load bytecode %s: %w", bpfFileName, err)
	}

	return bytecode, nil
}

// getBPFName returns the appropriate eBPF bytecode filename based on BTF mode.
func (p *Probe) getBPFName(baseName string) string {
	// Determine if we should use core or non-core bytecode
	useCoreMode := p.config.GetBTF() == 1 // BTFModeCore

	// Replace .o extension
	if useCoreMode {
		return baseName[:len(baseName)-2] + "_core.o"
	}
	return baseName[:len(baseName)-2] + "_noncore.o"
}

// setupManager configures the eBPF manager with probes and maps.
func (p *Probe) setupManager() error {
	binaryPath := p.config.Zshpath
	if binaryPath == "" {
		binaryPath = "/bin/zsh"
	}

	readlineFuncName := p.config.ReadlineFuncName

	p.Logger().Info().
		Str("binary", binaryPath).
		Str("function", readlineFuncName).
		Msg("Setting up zsh probe")

	p.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/zsh_zleentry",
				EbpfFuncName:     "uretprobe_zsh_zleentry",
				AttachToFuncName: readlineFuncName,
				BinaryPath:       binaryPath,
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	// Configure decoder for events map
	p.mapNameToDecoder["events"] = &zshEventDecoder{}

	return nil
}

// getManagerOptions returns the manager options for the probe.
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

	// Add constant editors if global variables are enabled
	if p.config.EnableGlobalVar() {
		kv, _ := kernel.HostVersion()
		kernelLess52 := uint64(0)
		if kv < kernel.VersionCode(5, 2, 0) {
			kernelLess52 = 1
		}

		opts.ConstantEditors = []manager.ConstantEditor{
			{
				Name:  "target_pid",
				Value: p.config.Pid,
			},
			{
				Name:  "target_uid",
				Value: p.config.Uid,
			},
			{
				Name:  "target_errno",
				Value: uint64(p.config.ErrNo),
			},
			{
				Name:  "less52",
				Value: kernelLess52,
			},
		}

		if p.config.Pid > 0 {
			p.Logger().Info().Uint64("pid", p.config.Pid).Msg("Targeting specific PID")
		} else {
			p.Logger().Info().Msg("Targeting all processes")
		}

		if p.config.Uid > 0 {
			p.Logger().Info().Uint64("uid", p.config.Uid).Msg("Targeting specific UID")
		} else {
			p.Logger().Info().Msg("Targeting all users")
		}
	}

	return opts
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// zshEventDecoder implements domain.EventDecoder for zsh command events
type zshEventDecoder struct{}

func (d *zshEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *zshEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &Event{}, true
}
