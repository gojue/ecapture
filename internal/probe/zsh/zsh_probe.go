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

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
)

// Probe implements the Zsh probe using the new architecture.
type Probe struct {
	*base.BaseProbe
	config      *Config
	bpfManager  *manager.Manager
	eventMaps   []*ebpf.Map
}

// NewProbe creates a new Zsh probe instance.
func NewProbe() *Probe {
	return &Probe{
		BaseProbe: base.NewBaseProbe("zsh"),
		eventMaps: make([]*ebpf.Map, 0, 1),
	}
}

// Initialize initializes the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	config, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for zsh probe", nil)
	}
	
	if err := config.Validate(); err != nil {
		return err
	}
	
	p.config = config
	
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
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

	// Get events map
	eventsMap, found, err := p.bpfManager.GetMap("events")
	if err != nil {
		return errors.Wrap(errors.ErrCodeEBPFMapAccess, "failed to get events map", err)
	}
	if !found {
		return errors.NewResourceNotFoundError("eBPF map: events")
	}
	p.eventMaps = []*ebpf.Map{eventsMap}

	// Start event reader
	if err := p.StartPerfEventReader(eventsMap, p); err != nil {
		return err
	}

	p.Logger().Info().Msg("Zsh probe started successfully")
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

// Decode implements EventDecoder interface.
func (p *Probe) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}

// GetDecoder implements EventDecoder interface.
func (p *Probe) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	for _, m := range p.eventMaps {
		if m == em {
			return &Event{}, true
		}
	}
	return nil, false
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
