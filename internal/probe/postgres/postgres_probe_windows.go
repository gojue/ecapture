//go:build windows
// +build windows

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
	"context"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/pkg/util/hook"
)

// Probe implements PostgreSQL query monitoring on Windows using DLL hooking.
type Probe struct {
	name      string
	logger    *logger.Logger
	config    *Config
	isRunning atomic.Bool

	hookManager *hook.HookManager
	dispatcher  domain.EventDispatcher
}

// NewProbe creates a new PostgreSQL probe instance for Windows.
func NewProbe() *Probe {
	return &Probe{name: string(factory.ProbeTypePostgres)}
}

// Initialize initializes the PostgreSQL probe with the provided configuration.
func (p *Probe) Initialize(_ context.Context, cfg domain.Configuration) error {
	if cfg == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	postgresConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for postgres probe", nil)
	}
	p.config = postgresConfig
	p.logger = base.NewLogger(p.name, p.config.GetDebug())

	p.logger.Info().
		Uint64("pid", p.config.GetPid()).
		Str("postgres_path", p.config.GetPostgresPath()).
		Str("func_name", p.config.GetFuncName()).
		Msg("PostgreSQL probe initialized")

	dispatcher, err := base.InitDispatcher(p.name, cfg)
	if err != nil {
		return err
	}
	p.dispatcher = dispatcher
	return nil
}

// Start begins the PostgreSQL probe.
func (p *Probe) Start(_ context.Context) error {
	if p.isRunning.Load() {
		return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeProbeStart, "probe already running"))
	}
	p.isRunning.Store(true)

	p.hookManager = hook.NewHookManager()
	if err := p.installHooks(); err != nil {
		p.isRunning.Store(false)
		return err
	}

	p.logger.Info().Str("func_name", p.config.GetFuncName()).Msg("PostgreSQL probe started")
	return nil
}

func (p *Probe) installHooks() error {
	funcName := p.config.GetFuncName()
	if funcName == "" {
		funcName = "PQexec"
	}

	modulePath := p.config.GetPostgresPath()
	return p.hookManager.AddHook(funcName, hook.HookConfig{
		Module:   modulePath,
		FuncName: funcName,
		Callback: func(_ uintptr, pid uint32, args []uintptr) {
			if p.config.GetPid() != 0 && uint64(pid) != p.config.GetPid() {
				return
			}
			query := extractPostgresQuery(args, funcName)
			if query == "" {
				return
			}
			ev := NewWindowsEvent(pid, "", query, funcName)
			if err := p.dispatcher.Dispatch(ev); err != nil {
				p.logger.Warn().Err(err).Msg("Failed to dispatch PostgreSQL event")
			}
		},
	})
}

// extractPostgresQuery extracts the SQL query from PQexec arguments.
// Signature: PGresult *PQexec(PGconn *conn, const char *command);
func extractPostgresQuery(args []uintptr, funcName string) string {
	if len(args) < 2 {
		return ""
	}
	ptr := unsafe.Pointer(args[1])
	if ptr == nil {
		return ""
	}
	data := (*[MaxDataSizePostgres]byte)(ptr)
	length := 0
	for length < MaxDataSizePostgres && data[length] != 0 {
		length++
	}
	return string(data[:length:length])
}

// Stop stops the PostgreSQL probe.
func (p *Probe) Stop(_ context.Context) error {
	if !p.isRunning.Load() {
		return nil
	}
	p.isRunning.Store(false)
	if p.hookManager != nil {
		_ = p.hookManager.Close()
		p.hookManager = nil
	}
	p.logger.Info().Msg("PostgreSQL probe stopped")
	return nil
}

// Close releases resources.
func (p *Probe) Close() error {
	_ = p.Stop(context.Background())
	p.isRunning.Store(false)
	base.CloseDispatcher(p.dispatcher, p.logger)
	p.logger.Info().Msg("PostgreSQL probe closed")
	return nil
}

// Name returns the probe's identifier.
func (p *Probe) Name() string { return p.name }

// IsRunning returns whether the probe is active.
func (p *Probe) IsRunning() bool { return p.isRunning.Load() }

// Events returns the eBPF maps used for event collection.
func (p *Probe) Events() []*ebpf.Map { return nil }
