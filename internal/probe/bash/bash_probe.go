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

package bash

import (
	"bytes"
	"context"
	"io"
	"math"
	"sync"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

// Probe implements the bash command tracing probe.
type Probe struct {
	*base.BaseProbe
	config     *Config
	bpfManager *manager.Manager
	eventMaps  []*ebpf.Map
	lineMap    map[string]string
	lineMutex  sync.RWMutex
	output     io.Writer
}

// NewProbe creates a new Bash probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe: base.NewBaseProbe("bash"),
		lineMap:   make(map[string]string),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	// Type assert to Bash-specific config
	bashConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for bash probe", nil)
	}
	p.config = bashConfig

	p.Logger().Info().
		Str("bash_path", bashConfig.Bashpath).
		Str("readline", bashConfig.Readline).
		Str("readline_func", bashConfig.ReadlineFuncName).
		Msg("Bash probe initialized")

	return nil
}

// Start begins the bash probe operation.
func (p *Probe) Start(ctx context.Context) error {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// Load eBPF bytecode
	bpfFileName := p.BaseProbe.GetBPFName("bytecode/bash_kern.o")
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading eBPF bytecode")

	// Load from assets
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return err
	}

	// Initialize eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("bash manager init", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("bash manager start", err)
	}

	// Get event maps
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

	p.Logger().Info().Msg("Bash probe started successfully")
	return nil
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	return p.eventMaps
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
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

	// Handle multi-line commands
	p.handleEvent(event)

	// Only return completed commands
	if event.AllLines == "" {
		return nil, nil // Not ready yet
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

// handleEvent processes bash events and manages multi-line commands.
func (p *Probe) handleEvent(event *Event) {
	uuid := event.UUID()

	p.lineMutex.Lock()
	defer p.lineMutex.Unlock()

	switch event.BashType {
	case BashEventTypeReadline:
		// Accumulate line
		newLine := unix.ByteSliceToString(event.Line[:])
		existingLine := p.lineMap[uuid]
		if existingLine != "" {
			p.lineMap[uuid] = existingLine + "\n" + newLine
		} else {
			p.lineMap[uuid] = newLine
		}

	case BashEventTypeRetval:
		// Command completed
		line := p.lineMap[uuid]
		delete(p.lineMap, uuid)

		// Skip empty lines or default error returns
		if line == "" || event.ReturnValue == uint32(p.config.ErrNo) {
			return
		}
		event.AllLines = line

	case BashEventTypeExitOrExec:
		// Exit or exec event
		line := p.lineMap[uuid]
		delete(p.lineMap, uuid)

		if line == "" {
			return
		}
		event.AllLines = line
	}
}

// setupManager configures the eBPF manager with probes.
func (p *Probe) setupManager() error {
	var bashPath string
	var readlinePath string

	switch p.config.ElfType {
	case ElfTypeBin:
		bashPath = p.config.Bashpath
		readlinePath = p.config.Bashpath
	case ElfTypeSo:
		bashPath = p.config.Bashpath
		readlinePath = p.config.Readline
	default:
		bashPath = "/bin/bash"
		readlinePath = "/bin/bash"
	}

	p.Logger().Info().
		Str("bash_path", bashPath).
		Str("readline_path", readlinePath).
		Str("readline_func", p.config.ReadlineFuncName).
		Msg("Setting up eBPF probes")

	p.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uretprobe/bash_readline",
				EbpfFuncName:     "uretprobe_bash_readline",
				AttachToFuncName: p.config.ReadlineFuncName,
				BinaryPath:       readlinePath,
			},
			{
				Section:          "uretprobe/bash_retval",
				EbpfFuncName:     "uretprobe_bash_retval",
				AttachToFuncName: "execute_command",
				BinaryPath:       bashPath,
			},
			{
				Section:          "uprobe/exec_builtin",
				EbpfFuncName:     "uprobe_exec_builtin",
				AttachToFuncName: "exec_builtin",
				BinaryPath:       bashPath,
			},
			{
				Section:          "uprobe/exit_builtin",
				EbpfFuncName:     "uprobe_exit_builtin",
				AttachToFuncName: "exit_builtin",
				BinaryPath:       bashPath,
			},
		},
		Maps: []*manager.Map{
			{Name: "events"},
		},
	}

	return nil
}

// getManagerOptions returns eBPF manager options.
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
			{Name: "target_errno", Value: uint64(p.config.ErrNo)},
			{Name: "less52", Value: kernelLess52},
		}
	}

	return opts
}
