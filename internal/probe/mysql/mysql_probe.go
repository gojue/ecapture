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

package mysql

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

// Probe represents the MySQL probe that captures SQL queries
type Probe struct {
	*base.BaseProbe

	config     *Config
	bpfManager *manager.Manager
	eventsMap  *ebpf.Map
}

// NewProbe creates a new MySQL probe instance
func NewProbe() *Probe {
	return &Probe{
		BaseProbe: base.NewBaseProbe("mysql"),
	}
}

// Initialize initializes the MySQL probe with the provided configuration
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration, dispatcher domain.EventDispatcher) error {
	// Type assert the configuration
	mysqlConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError(
			"invalid configuration type for MySQL probe",
			fmt.Errorf("expected *mysql.Config, got %T", cfg),
		)
	}

	// Validate configuration
	if err := mysqlConfig.Validate(); err != nil {
		return errors.NewProbeInitError("mysql", err)
	}

	p.config = mysqlConfig

	// Initialize base probe
	if err := p.BaseProbe.Initialize(ctx, cfg, dispatcher); err != nil {
		return err
	}

	p.Logger().Info().
		Str("probe", p.Name()).
		Str("mysql_path", p.config.GetBinaryPath()).
		Str("func_name", p.config.GetFuncName()).
		Str("version", p.config.GetVersion().String()).
		Str("version_info", p.config.GetVersionInfo()).
		Uint64("offset", p.config.GetOffset()).
		Msg("MySQL probe initialized")

	return nil
}

// Start starts the MySQL probe
func (p *Probe) Start(ctx context.Context) error {
	// Start base probe
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}

	// Load eBPF bytecode
	bytecode, err := p.loadBytecode()
	if err != nil {
		return err
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return err
	}

	// Initialize the eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(bytecode), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("mysql", err)
	}

	// Start the eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("mysql", err)
	}

	// Get the events map
	eventsMap, found, err := p.bpfManager.GetMap("events")
	if err != nil {
		return errors.NewEBPFLoadError("mysql events map", err)
	}
	if !found {
		return errors.NewResourceNotFoundError("events map")
	}
	p.eventsMap = eventsMap

	// Start event reader with decoder
	decoder := &mysqlEventDecoder{eventsMap: eventsMap}
	if err := p.StartPerfEventReader(p.eventsMap, decoder); err != nil {
		return err
	}

	p.Logger().Info().
		Str("probe", p.Name()).
		Msg("MySQL probe started successfully")

	return nil
}

// Stop stops the MySQL probe
func (p *Probe) Stop(ctx context.Context) error {
	p.Logger().Info().
		Str("probe", p.Name()).
		Msg("Stopping MySQL probe")

	return p.BaseProbe.Stop(ctx)
}

// Close closes the MySQL probe and releases resources
func (p *Probe) Close() error {
	p.Logger().Info().
		Str("probe", p.Name()).
		Msg("Closing MySQL probe")

	// Stop the eBPF manager
	if p.bpfManager != nil {
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Error().
				Err(err).
				Str("probe", p.Name()).
				Msg("Failed to stop eBPF manager")
		}
	}

	// Close base probe
	return p.BaseProbe.Close()
}

// loadBytecode loads the eBPF bytecode for the MySQL probe
func (p *Probe) loadBytecode() ([]byte, error) {
	// Determine bytecode filename based on BTF availability
	var bpfFileName string
	btfEnabled := (p.config.GetBTF() != 0)
	if btfEnabled {
		bpfFileName = "bytecode/mysqld_kern.o"
	} else {
		bpfFileName = "bytecode/mysqld_kern.o" // Same file for non-BTF
	}

	p.Logger().Info().
		Str("probe", p.Name()).
		Str("bytecode", bpfFileName).
		Bool("btf", btfEnabled).
		Msg("Loading eBPF bytecode")

	// Load bytecode from assets
	bytecode, err := assets.Asset(bpfFileName)
	if err != nil {
		return nil, errors.NewEBPFLoadError(bpfFileName, err)
	}

	return bytecode, nil
}

// setupManager sets up the eBPF manager with probes
func (p *Probe) setupManager() error {
	binaryPath := p.config.GetBinaryPath()
	funcName := p.config.GetFuncName()
	offset := p.config.GetOffset()
	version := p.config.GetVersion()

	// Create probes based on MySQL version
	var probes []*manager.Probe

	switch version {
	case MysqlVersion57, MysqlVersion80:
		// MySQL 5.7 and 8.0 use the same hook points
		probes = []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command_57",
				EbpfFuncName:     "mysql57_query",
				AttachToFuncName: funcName,
				UAddress:         offset,
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command_57",
				EbpfFuncName:     "mysql57_query_return",
				AttachToFuncName: funcName,
				UAddress:         offset,
				BinaryPath:       binaryPath,
			},
		}
	default:
		// MySQL 5.6 and MariaDB
		probes = []*manager.Probe{
			{
				Section:          "uprobe/dispatch_command",
				EbpfFuncName:     "mysql56_query",
				AttachToFuncName: funcName,
				UAddress:         offset,
				BinaryPath:       binaryPath,
			},
			{
				Section:          "uretprobe/dispatch_command",
				EbpfFuncName:     "mysql56_query_return",
				AttachToFuncName: funcName,
				UAddress:         offset,
				BinaryPath:       binaryPath,
			},
		}
	}

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	p.Logger().Info().
		Str("probe", p.Name()).
		Str("binary", binaryPath).
		Str("function", funcName).
		Str("version", version.String()).
		Uint64("offset", offset).
		Int("num_probes", len(probes)).
		Msg("eBPF manager configured")

	return nil
}

// getManagerOptions returns the eBPF manager options
func (p *Probe) getManagerOptions() manager.Options {
	return manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel: ebpf.LogLevelBranch,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

// mysqlEventDecoder implements the EventDecoder interface for MySQL events
type mysqlEventDecoder struct {
	eventsMap *ebpf.Map
}

// Decode deserializes raw bytes from an eBPF map into an Event
func (d *mysqlEventDecoder) Decode(em *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return event, nil
}

// GetDecoder returns the event decoder for a specific eBPF map
func (d *mysqlEventDecoder) GetDecoder(em *ebpf.Map) (domain.Event, bool) {
	if em == d.eventsMap {
		return &Event{}, true
	}
	return nil, false
}
